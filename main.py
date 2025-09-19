import os
import glob
import json
import time
import sqlite3
import subprocess
import re
from openai import OpenAI
import ipaddress
import logging
from collections import defaultdict, deque
import fnmatch

# --- Configuration Constants ---
LOG_DIR_GLOB = "/var/log/nginx/saren/wtako.net/*.log"
CONFIG_FILE = "log_monitor_config.json"
DB_FILE = "blacklist.db"
NGINX_DENY_LIST = "/etc/nginx/conf.d/blacklist.conf"
UNBAN_FILE = "/tmp/nginx-unban-ips.txt"


# IMPORTANT: Set your API key as an environment variable for security.
API_KEY = os.getenv("OPENROUTER_API_KEY", "")
API_BASE_URL = "https://openrouter.ai/api/v1"
LLM_MODEL = "@preset/wtako-nginx-llm"

# Batching parameters
MAX_QUEUE_SIZE = 100
MAX_WAIT_SECONDS = 60
POLLING_INTERVAL_SECONDS = 5

# --- Dependencies ---
# This script requires the inotify_simple library.
# Install it using: pip install inotify-simple
try:
    from inotify_simple import INotify, flags
except ImportError:
    logging.critical("inotify_simple is not installed. Please run: pip install inotify-simple")
    exit(1)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class LogMonitor:
    # --- IP Filtering ---
    # Private IP ranges to be excluded from logs sent to LLM
    PRIVATE_IP_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('100.64.0.0/10'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]
    FLOOD_THRESHOLD_BYTES = 10 * 1024  # 10 KB

    def __init__(self, log_dir_glob, config_file, db_file, nginx_deny_list, unban_file):
        """Initializes the log monitor, sets up configuration, database, and watches."""
        # --- Configuration ---
        self.LOG_DIR_GLOB = log_dir_glob
        self.CONFIG_FILE = config_file
        self.DB_FILE = db_file
        self.NGINX_DENY_LIST = nginx_deny_list
        self.UNBAN_FILE = unban_file
        self.LOG_DIR = os.path.dirname(self.LOG_DIR_GLOB)
        self.UNBAN_FILENAME = os.path.basename(self.UNBAN_FILE)
        self.UNBAN_DIR = os.path.dirname(self.UNBAN_FILE)

        # Initialize instance state
        self.current_public_ip = None
        self.config = {}
        self.db_conn = None
        self.inotify = None
        self.log_queue = deque()
        self.pending_cursor_updates = {}
        self.last_llm_check_time = time.time()
        self.last_hourly_export_time = time.time()
        self.ip_regex = re.compile(r'^(\S+)')
        self.active_blacklist = set()  # New set to store active blacklisted IPs

        # Run setup methods
        self._setup_monitoring()

    @staticmethod
    def _get_external_ip_from_ifconfig():
        """Tries to get the external IP address by parsing ifconfig output."""
        try:
            result = subprocess.run(['ifconfig', 'ext1'], capture_output=True, text=True, check=True)
            match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
            if match:
                logging.info(f"Detected external IP from ifconfig ext1: {match.group(1)}")
                return match.group(1)
        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            logging.warning(f"Could not get external IP from ifconfig: {e}")
        return None

    def _update_current_public_ip(self):
        """Updates the instance's public IP variable."""
        new_ip = self._get_external_ip_from_ifconfig()
        if new_ip and new_ip != self.current_public_ip:
            logging.info(f"Public IP updated from {self.current_public_ip} to {new_ip}")
            self.current_public_ip = new_ip

    def _is_private_ip(self, ip_str: str) -> bool:
        """Checks if an IP address is private or matches the instance's public IP."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
                return True
            if self.current_public_ip and ip == ipaddress.ip_address(self.current_public_ip):
                return True
            for net in self.PRIVATE_IP_NETWORKS:
                if ip in net:
                    return True
        except ValueError:
            return True
        return False

    def _initialize_config(self):
        """Creates or loads the monitor configuration file."""
        if os.path.exists(self.CONFIG_FILE):
            logging.info(f"Loading existing configuration from {self.CONFIG_FILE}")
            with open(self.CONFIG_FILE, 'r') as f:
                self.config = json.load(f)
            return

        logging.info(f"Creating new configuration file at {self.CONFIG_FILE}")
        self.config = {"files": {}}
        log_files = glob.glob(self.LOG_DIR_GLOB)
        if not log_files:
            logging.warning(f"No log files found matching pattern: {self.LOG_DIR_GLOB}")

        for log_file in log_files:
            if ".error" in os.path.basename(log_file):
                logging.info(f"Ignoring error log file: {log_file}")
                continue

            server_name = os.path.basename(log_file).replace('.log', '')
            try:
                file_size = os.path.getsize(log_file)
                self.config["files"][log_file] = {
                    "server_name": server_name,
                    "cursor": file_size,
                    "system_prompt_context": f"This server '{server_name}' hosts a public service. Please add specific context here."
                }
                logging.info(f"Initializing {log_file} with cursor at {file_size} bytes.")
            except OSError as e:
                logging.error(f"Could not access {log_file}: {e}")

        with open(self.CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def _initialize_db(self):
        """Initializes the SQLite database and sets the instance connection."""
        self.db_conn = sqlite3.connect(self.DB_FILE)
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY,
                reason_tldr TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                logs TEXT,
                sections TEXT,
                ban_hours INTEGER,
                verdict TEXT
            )
        ''')
        # Add new columns if they don't exist
        for col, col_type in {'logs': 'TEXT', 'sections': 'TEXT', 'ban_hours': 'INTEGER', 'verdict': 'TEXT'}.items():
            try:
                cursor.execute(f"ALTER TABLE blacklist ADD COLUMN {col} {col_type}")
                logging.info(f"Added '{col}' column to blacklist table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e):
                    logging.warning(f"Could not add '{col}' column: {e}")

        self.db_conn.commit()
        logging.info(f"Database initialized at {self.DB_FILE}")

    def _initialize_unban_file(self):
        """Creates the unban IP file if it doesn't exist."""
        if not os.path.exists(self.UNBAN_FILE):
            try:
                with open(self.UNBAN_FILE, 'w') as f:
                    pass
                logging.info(f"Created unban file at {self.UNBAN_FILE}")
            except OSError as e:
                logging.error(f"Could not create unban file at {self.UNBAN_FILE}: {e}")

    def _add_new_file_to_config(self, filepath: str):
        """Adds a newly discovered log file to the running config."""
        if filepath in self.config.get("files", {}) or ".error" in os.path.basename(filepath):
            return

        logging.info(f"Discovered new log file: {filepath}")
        server_name = os.path.basename(filepath).replace('.log', '')
        try:
            self.config["files"][filepath] = {
                "server_name": server_name,
                "cursor": 0,
                "system_prompt_context": f"This server '{server_name}' hosts a public service. Please add specific context here."
            }
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to add {filepath} to config: {e}")

    def _read_new_log_lines(self, filepath: str, last_cursor: int) -> tuple[list[str], int]:
        """
        Reads new lines from a log file since the last cursor position.
        If the file has grown by more than a threshold, skips to the end to avoid getting overwhelmed.
        Handles race conditions by backtracking if a partial line write is detected.
        """
        try:
            current_size = os.path.getsize(filepath)
            if current_size < last_cursor:
                logging.warning(f"Log file {filepath} was truncated. Resetting cursor.")
                return [], 0

            if current_size == last_cursor:
                return [], last_cursor

            # --- FLOOD DETECTION LOGIC ---
            if (current_size - last_cursor) > self.FLOOD_THRESHOLD_BYTES:
                logging.warning(
                    f"Flood detected in {filepath}. Log growth ({current_size - last_cursor} bytes) "
                    f"exceeds threshold ({self.FLOOD_THRESHOLD_BYTES} bytes). Skipping to near end of file."
                )
                with open(filepath, 'rb') as f:
                    # Seek to a position near the end to find the last full line, avoiding partial reads.
                    # We'll look in the last 2KB. This is a reasonable chunk size.
                    seek_pos = max(0, current_size - 2048)
                    f.seek(seek_pos)
                    chunk = f.read()  # Read from seek_pos to the end.

                    # Find the last newline character in this chunk.
                    last_newline_pos_in_chunk = chunk.rfind(b'\n')

                    if last_newline_pos_in_chunk != -1:
                        # Calculate the absolute position of the new cursor in the file.
                        new_cursor = seek_pos + last_newline_pos_in_chunk + 1
                        logging.info(f"Jumping cursor for {filepath} to {new_cursor} to align with last full line.")
                        return [], new_cursor
                    else:
                        # If no newline is found (unlikely for large files), just jump to the end.
                        logging.warning(f"Could not find a recent newline in {filepath}. Jumping cursor to absolute end: {current_size}")
                        return [], current_size
            # --- END OF FLOOD DETECTION LOGIC ---

            with open(filepath, 'rb') as f:
                read_from_cursor = last_cursor

                # If not at the start, check if the previous byte is a newline to avoid
                # reading a partially written line.
                if last_cursor > 0:
                    f.seek(last_cursor - 1)
                    if f.read(1) != b'\n':
                        logging.warning(
                            f"Partial line write detected in {filepath} at offset {last_cursor}. "
                            "Backtracking up to 100 bytes to find previous newline."
                        )
                        # Define how far back to search for a newline.
                        backtrack_amount = min(last_cursor, 100)
                        f.seek(last_cursor - backtrack_amount)
                        chunk = f.read(backtrack_amount)

                        # Find the last newline in the chunk we read.
                        last_newline_pos = chunk.rfind(b'\n')

                        if last_newline_pos != -1:
                            # Adjust cursor to start reading *after* the found newline.
                            read_from_cursor = (last_cursor - backtrack_amount) + last_newline_pos + 1
                        elif last_cursor <= 100:
                            # We searched to the beginning of the file and found no newline.
                            # The file likely starts with one very long line, so read from the start.
                            read_from_cursor = 0
                        # If no newline was found in a larger backtrack window, we implicitly
                        # fall through and use the original `last_cursor`, accepting one
                        # potentially incomplete line. This is a safe fallback.

                f.seek(read_from_cursor)
                new_content_bytes = f.read()
                new_content = new_content_bytes.decode('utf-8', errors='ignore')

                return [line for line in new_content.strip().split('\n') if line], current_size

        except FileNotFoundError:
            logging.warning(f"Log file not found: {filepath}. It might have been rotated.")
            return [], 0
        except Exception as e:
            logging.error(f"Error reading {filepath}: {e}")
        return [], last_cursor

    def _format_logs_for_llm(self, log_batch: list[tuple[str, str]]) -> str:
        """Formats a batch of logs for the LLM prompt."""
        logs_by_server = defaultdict(list)
        for file_path, log_line in log_batch:
            server_name = self.config["files"].get(file_path, {}).get("server_name", "unknown_server")
            logs_by_server[server_name].append(log_line)

        prompt_parts = []
        for server_name, lines in logs_by_server.items():
            context = "No context provided."
            for conf in self.config["files"].values():
                if conf['server_name'] == server_name:
                    context = conf['system_prompt_context']
                    break
            prompt_parts.append(f"[{server_name}]")
            prompt_parts.append(context)
            prompt_parts.extend(lines)
        return "\n".join(prompt_parts)

    def _query_llm(self, log_content: str) -> list | None:
        """Sends log content to the LLM and gets a structured JSON response."""
        if not API_KEY or "<" in API_KEY:
            logging.error("OpenRouter API key is not set. Please set the OPENROUTER_API_KEY environment variable.")
            return None

        client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
        system_prompt = (
            "You are a server network security expert. You will be provided snippet of nginx HTTP log for a public server that accessible by internet, including bots.\n"
            "Give the list of IPs that should be blacklisted for a very long time for blatant vulnerability scanning/triggering in attempt to hack.\n"
            "We have zero tolerance for such activities. However, well-known crawlers are not enemies, try no be nice to them, except when they demostrate explicit malicious behaviours (Bots that are scanning for PHP vulns are no way legit).\n\n"
            "Output the JSON array in format of:\n"
            "[{\n"
            "  \"ip\": string, \n"
            "  \"reason_tldr\": string, \n"
            "  \"confidence\": 0-1\n"
            "}, ...]\n\n"
            "If no suspicious IPs, return empty array [], and no need extra reasoning."
        )

        try:
            logging.info("Querying LLM with new log batch of %d characters.", len(log_content))
            completion = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": log_content}],
                temperature=0.6
            )
            response_content = completion.choices[0].message.content
            response_content = response_content.strip().strip('```').strip('json').strip()
            data = json.loads(response_content)
            if isinstance(data, list):
                logging.info(f"LLM identified {len(data)} IPs to blacklist.")
                return data
            else:
                logging.warning(f"LLM response was valid JSON but not a list: {type(data)}")
                return []
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON from LLM: {e}\nResponse: {response_content}")
            return None
        except Exception as e:
            if "429" in str(e):
                logging.warning(f"LLM rate limit (429) hit. Sleeping for 60 seconds.")
                time.sleep(60)
            else:
                logging.error(f"An unexpected error occurred while querying LLM: {e}")
            return None

    def _update_database(self, items_to_blacklist: list, logs_by_ip: dict) -> bool:
        """Updates the blacklist database. Returns True if any change was made."""
        if not items_to_blacklist:
            return False

        cursor = self.db_conn.cursor()
        changes_made = False
        timestamp = int(time.time())

        for item in items_to_blacklist:
            if not isinstance(item, dict) or not all(k in item for k in ["ip", "reason_tldr", "confidence"]):
                logging.warning(f"Skipping malformed item from LLM: {item}")
                continue

            ip = item.get("ip")
            if not ip or not isinstance(ip, str) or self._is_private_ip(ip):
                logging.info(f"Skipping invalid or private IP from LLM: {ip}")
                continue

            ip_evidence = logs_by_ip.get(ip)
            related_logs = "\n".join(ip_evidence['logs']) if ip_evidence else None
            related_sections = ",".join(sorted(list(ip_evidence['sections']))) if ip_evidence else None
            try:
                cursor.execute(
                    "INSERT OR REPLACE INTO blacklist (ip, reason_tldr, confidence, timestamp, logs, sections) VALUES (?, ?, ?, ?, ?, ?)",
                    (ip, str(item["reason_tldr"]), float(item["confidence"]), timestamp, related_logs, related_sections)
                )
                if cursor.rowcount > 0:
                    changes_made = True
                    self.active_blacklist.add(ip)  # Add to active blacklist set
                    logging.info(f"ADD/UPDATE IP: {ip} | Reason: {item['reason_tldr']} | Confidence: {item['confidence']:.2f}")
            except (sqlite3.Error, ValueError) as e:
                logging.error(f"DB/Type error for IP {ip}: {e}")

        if changes_made:
            self.db_conn.commit()
        return changes_made

    def _process_unban_requests(self):
        """Reads IPs from the unban file, removes them from the DB, and reloads Nginx."""
        try:
            with open(self.UNBAN_FILE, 'r') as f:
                ips_to_unban = [line.strip() for line in f if line.strip()]
            if not ips_to_unban:
                return

            logging.info(f"Processing unban request for IPs: {', '.join(ips_to_unban)}")
            cursor = self.db_conn.cursor()
            changes_made = 0
            for ip in ips_to_unban:
                try:
                    ipaddress.ip_address(ip)
                    cursor.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
                    if cursor.rowcount > 0:
                        changes_made += 1
                        self.active_blacklist.discard(ip) # Remove from active blacklist set
                        logging.info(f"Removed IP {ip} from the blacklist.")
                    else:
                        logging.warning(f"IP {ip} from unban file was not found.")
                except (ValueError, sqlite3.Error) as e:
                    logging.warning(f"Skipping invalid or DB error for IP in unban file: {ip}, {e}")

            if changes_made > 0:
                self.db_conn.commit()
                logging.info(f"Successfully unbanned {changes_made} IP(s).")
                self._check_and_update_deny_list()
            else:
                logging.info("No IPs from unban file found in DB. No changes made.")

            with open(self.UNBAN_FILE, 'w') as f:
                pass
            logging.info(f"Cleared unban file: {self.UNBAN_FILE}")
        except FileNotFoundError:
            logging.warning(f"Unban file {self.UNBAN_FILE} not found.")
        except Exception as e:
            logging.error(f"An error occurred processing unban requests: {e}")

    def _unban_class_e_ips(self):
        """Removes all Class E (240.0.0.0-255.255.255.255) IPs from the database."""
        logging.info("Checking for and unbanning Class E IPs (240.0.0.0/4).")
        class_e_network = ipaddress.ip_network('240.0.0.0/4')
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT ip FROM blacklist")
        all_banned_ips = cursor.fetchall()
        ips_to_unban = []
        for (ip_str,) in all_banned_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip in class_e_network:
                    ips_to_unban.append(ip_str)
            except ValueError:
                logging.warning(f"Invalid IP address found in DB: {ip_str}")

        if ips_to_unban:
            logging.info(f"Found {len(ips_to_unban)} Class E IPs to unban.")
            placeholders = ','.join('?' for _ in ips_to_unban)
            cursor.execute(f"DELETE FROM blacklist WHERE ip IN ({placeholders})", ips_to_unban)
            changes_made = cursor.rowcount
            self.db_conn.commit()
            if changes_made > 0:
                for ip in ips_to_unban:
                    self.active_blacklist.discard(ip) # Remove from active blacklist set
                logging.info(f"Successfully unbanned {changes_made} Class E IP(s) from the database.")
                self._check_and_update_deny_list()
            else:
                logging.info("No Class E IPs were found in the database to unban.")
        else:
            logging.info("No Class E IPs found in the database.")


    def _export_nginx_deny_list(self):
        """Exports active blacklisted IPs to an Nginx 'deny' file."""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT ip, reason_tldr, timestamp, ban_hours FROM blacklist WHERE confidence >= 0.5 ORDER BY timestamp DESC")
            all_potential_bans = cursor.fetchall()
            active_bans = []
            current_time = int(time.time())

            self.active_blacklist.clear() # Clear and rebuild active blacklist
            for ip, reason, ts, ban_hours in all_potential_bans:
                if ban_hours is None or ban_hours < 0:
                    active_bans.append((ip, reason, ts, ban_hours))
                    self.active_blacklist.add(ip)
                    continue
                if isinstance(ban_hours, (int, float)) and ban_hours > 0 and current_time < (ts + ban_hours * 3600):
                    active_bans.append((ip, reason, ts, ban_hours))
                    self.active_blacklist.add(ip)

            with open(self.NGINX_DENY_LIST, 'w') as f:
                f.write(f"# Auto-generated on {time.ctime()}\n# Active Bans: {len(active_bans)}\n\n")
                f.write("geo $is_denied {\n")
                f.write("    default 0;\n")
                for ip, reason, ts, ban_hours in active_bans:
                    ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                    ban_str = f", for {ban_hours} hours" if ban_hours is not None and ban_hours > 0 else ", permanent"
                    f.write(f"    {ip} 1;  # Added {ts_str}{ban_str}, Reason: {reason}\n")
                f.write("}\n")
            logging.info(f"Exported {len(active_bans)} active IPs to {self.NGINX_DENY_LIST}.")
        except Exception as e:
            logging.error(f"Failed to export Nginx deny list: {e}")

    @staticmethod
    def _reload_nginx():
        """Executes 'sudo nginx -s reload'."""
        command = ["sudo", "nginx", "-s", "reload"]
        logging.info(f"Running command: {' '.join(command)}")
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            logging.info("Nginx reloaded successfully.")
            if result.stderr:
                logging.info(f"Nginx output (stderr): {result.stderr.strip()}")
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logging.error(f"Failed to reload Nginx: {e}")
            if isinstance(e, subprocess.CalledProcessError):
                logging.error(f"Stderr: {e.stderr.strip()}")
            logging.error("Ensure passwordless sudo rights for 'nginx -s reload'.")

    def _check_and_update_deny_list(self):
        """Generates, compares, and reloads Nginx if deny list changes."""
        old_content_without_first_line = ""
        try:
            if os.path.exists(self.NGINX_DENY_LIST):
                with open(self.NGINX_DENY_LIST, 'r') as f:
                    lines = f.readlines()
                    if len(lines) > 1:
                        old_content_without_first_line = "".join(lines[1:])
        except IOError as e:
            logging.warning(f"Could not read existing deny list: {e}")

        self._export_nginx_deny_list()

        new_content_without_first_line = ""
        try:
            with open(self.NGINX_DENY_LIST, 'r') as f:
                lines = f.readlines()
                if len(lines) > 1:
                    new_content_without_first_line = "".join(lines[1:])
        except IOError as e:
            logging.error(f"Could not read new deny list. Reload skipped. {e}")
            return

        if old_content_without_first_line != new_content_without_first_line:
            logging.info("Nginx deny list changed (ignoring first line). Reloading Nginx.")
            self._reload_nginx()
        else:
            logging.info("Nginx deny list is unchanged (ignoring first line). Skipping reload.")

    def _setup_monitoring(self):
        """Initializes all components for monitoring."""
        self._update_current_public_ip()
        self._initialize_config()
        self._initialize_db()
        self._initialize_unban_file()
        self._unban_class_e_ips() # Call the new unban function at startup
        logging.info("Performing initial deny list generation and check.")
        self._check_and_update_deny_list() # This will populate self.active_blacklist
        try:
            self.inotify = INotify()
            watch_flags = flags.CREATE | flags.MOVED_TO | flags.MODIFY
            if os.path.exists(self.LOG_DIR):
                self.inotify.add_watch(self.LOG_DIR, watch_flags)
                logging.info(f"Started inotify watch on directory: {self.LOG_DIR}")
            else:
                logging.warning(f"Log directory not found: {self.LOG_DIR}.")
            if os.path.exists(self.UNBAN_DIR):
                self.inotify.add_watch(self.UNBAN_DIR, watch_flags)
                logging.info(f"Started inotify watch on directory: {self.UNBAN_DIR}")
        except Exception as e:
            logging.critical(f"Failed to initialize inotify: {e}. Monitor cannot run.")
            self.close()
            exit(1)

    def _handle_inotify_events(self, events: list):
        """Processes file system events."""
        for event in events:
            if event.name == self.UNBAN_FILENAME and event.mask & (flags.MODIFY | flags.CREATE | flags.MOVED_TO):
                logging.info(f"Detected event for unban file: {self.UNBAN_FILE}")
                self._process_unban_requests()
                continue

            filepath = os.path.join(self.LOG_DIR, event.name)
            if event.mask & (flags.CREATE | flags.MOVED_TO) and fnmatch.fnmatch(filepath, self.LOG_DIR_GLOB):
                self._add_new_file_to_config(filepath)

    def _poll_log_files(self) -> bool:
        """Reads new lines from logs and adds them to the queue."""
        had_new_logs = False
        for filepath, file_conf in list(self.config.get("files", {}).items()):
            if self._process_log_file(filepath, file_conf):
                had_new_logs = True
        return had_new_logs

    def _process_log_file(self, filepath: str, file_conf: dict) -> bool:
        """Helper to process a single log file."""
        if ".error" in os.path.basename(filepath):
            return False

        current_cursor = self.pending_cursor_updates.get(filepath, file_conf["cursor"])
        new_lines, new_cursor = self._read_new_log_lines(filepath, current_cursor)

        if new_cursor == current_cursor:
            return False

        self.pending_cursor_updates[filepath] = new_cursor

        if new_cursor < current_cursor:
            logging.info(f"Log file {filepath} was truncated. Resetting cursor.")
            return False

        # new_cursor > current_cursor, so we have new lines
        eligible_lines_count = 0
        for line in new_lines:
            # Filter out 444 responses
            if '" 444 0' in line:
                continue

            match = self.ip_regex.match(line)
            if not match:
                continue

            ip = match.group(1)
            # Filter out private IPs and already blacklisted IPs
            if self._is_private_ip(ip) or ip in self.active_blacklist:
                continue

            self.log_queue.append((filepath, line))
            eligible_lines_count += 1

        if eligible_lines_count > 0:
            logging.info(
                f"Found {len(new_lines)} lines in {filepath}, enqueued {eligible_lines_count}. "
                f"Queue: {len(self.log_queue)}"
            )

        return True

    def _process_log_batch(self) -> bool:
        """Processes a log batch, queries LLM, and updates state."""
        logging.info(f"Processing batch of {min(len(self.log_queue), MAX_QUEUE_SIZE)} logs.")
        batch = [self.log_queue.popleft() for _ in range(min(len(self.log_queue), MAX_QUEUE_SIZE))]
        logs_by_ip = defaultdict(lambda: {'logs': [], 'sections': set()})

        for filepath, line in batch:
            match = self.ip_regex.match(line)
            if match:
                ip = match.group(1)
                # Double-check against active_blacklist before sending to LLM,
                # though _poll_log_files should largely handle this
                if ip not in self.active_blacklist:
                    server_name = self.config["files"].get(filepath, {}).get("server_name", "unknown")
                    logs_by_ip[ip]['logs'].append(line)
                    logs_by_ip[ip]['sections'].add(server_name)

        # Only send logs for IPs not already blacklisted
        filtered_batch_for_llm = []
        for file_path, log_line in batch:
            match = self.ip_regex.match(log_line)
            if match and match.group(1) not in self.active_blacklist:
                filtered_batch_for_llm.append((file_path, log_line))

        if not filtered_batch_for_llm:
            logging.info("Batch contained only already blacklisted IPs or no eligible IPs. Skipping LLM query.")
            # Still update cursors for processed lines
            for path, new_pos in self.pending_cursor_updates.items():
                if path in self.config["files"]:
                    self.config["files"][path]["cursor"] = new_pos
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.pending_cursor_updates.clear()
            return True


        llm_prompt = self._format_logs_for_llm(filtered_batch_for_llm)
        print('=============================\n' + llm_prompt + '\n=============================')
        blacklisted_items = self._query_llm(llm_prompt)
        self._update_current_public_ip()

        if blacklisted_items is not None:
            db_updated = self._update_database(blacklisted_items, logs_by_ip)
            if db_updated:
                self._check_and_update_deny_list()

            for path, new_pos in self.pending_cursor_updates.items():
                if path in self.config["files"]:
                    self.config["files"][path]["cursor"] = new_pos
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.pending_cursor_updates.clear()
            logging.info("Successfully processed batch and updated cursors.")
            return True
        else:
            logging.warning("LLM query failed. Re-queuing batch.")
            self.log_queue.extendleft(reversed(batch))
            return False

    def run(self):
        """The main monitoring loop."""
        try:
            while True:
                events = self.inotify.read(timeout=POLLING_INTERVAL_SECONDS * 1000)
                self._handle_inotify_events(events)
                had_new_logs = self._poll_log_files()

                time_since_check = time.time() - self.last_llm_check_time
                queue_full = len(self.log_queue) >= MAX_QUEUE_SIZE
                timeout_reached = (self.log_queue or had_new_logs) and time_since_check >= MAX_WAIT_SECONDS

                if self.log_queue and (queue_full or timeout_reached):
                    if self._process_log_batch():
                        self.last_llm_check_time = time.time()

                if time.time() - self.last_hourly_export_time >= 3600:
                    logging.info("Performing scheduled 1-hour deny list export and check.")
                    self._check_and_update_deny_list() # This will refresh self.active_blacklist
                    self.last_hourly_export_time = time.time()
        except KeyboardInterrupt:
            logging.info("Shutdown requested.")
        finally:
            self.close()

    def close(self):
        """Gracefully closes resources."""
        if self.inotify:
            self.inotify.close()
            logging.info("inotify watch closed.")
        if self.db_conn:
            self.db_conn.close()
            logging.info("Database connection closed.")
        logging.info("Monitor stopped.")

if __name__ == "__main__":
  
    monitor = LogMonitor(
        log_dir_glob=LOG_DIR_GLOB,
        config_file=CONFIG_FILE,
        db_file=DB_FILE,
        nginx_deny_list=NGINX_DENY_LIST,
        unban_file=UNBAN_FILE
    )
    monitor.run()
