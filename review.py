import os
import glob
import json
import time
import sqlite3
from collections import defaultdict
import asyncio
import subprocess
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from openai import AsyncOpenAI

# Load environment variables
load_dotenv()

# --- Configuration ---
# These are now primarily managed by start.py and passed to BanReviewer
# Default values are kept for standalone testing if needed.
CONFIG_FILE = os.getenv("CONFIG_FILE", "log_monitor_config.json")
LOG_DIR_GLOB = os.getenv("LOG_DIR_GLOB", "/var/log/nginx/saren/wtako.net/*.log")
UNBAN_FILE = os.getenv("UNBAN_FILE", "/tmp/nginx-unban-ips.txt")
REVIEW_INTERVAL_SECONDS = int(os.getenv("REVIEW_INTERVAL_SECONDS", "60"))
SUMMARY_INTERVAL_SECONDS = int(os.getenv("SUMMARY_INTERVAL_SECONDS", str(12 * 60 * 60)))

# --- API Configuration ---
API_KEY = os.getenv("OPENROUTER_API_KEY", "")
API_BASE_URL = os.getenv("API_BASE_URL", "http://100.64.0.8:8000/v1")
LLM_REVIEW_MODEL = os.getenv("LLM_REVIEW_MODEL", "gpt-oss-120b")

# Telegram Topic IDs
TOPIC_ID_SUMMARIES = int(os.getenv("TOPIC_ID_SUMMARIES", "5"))
TOPIC_ID_BANS_REVIEWS = int(os.getenv("TOPIC_ID_BANS_REVIEWS", "3"))


class BanReviewer:

    def __init__(self, db_conn=None):
        """Initializes the BanReviewer instance."""
        self._setup_logging()
        self._validate_api_key()
        self.client = AsyncOpenAI(base_url=API_BASE_URL, api_key=API_KEY)
        self.db_conn = db_conn
        self.monitor_config = self._load_monitor_config()
        self.last_summary_time = 0
        if not self.monitor_config or "files" not in self.monitor_config:
            logging.critical("Monitor config is invalid or empty. Exiting.")
            exit(1)

    def _setup_logging(self):
        """Sets up the application logger."""
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Reviewer] - %(message)s')

    def _validate_api_key(self):
        """Checks for a valid API key and exits if not found."""
        if not API_KEY or "<" in API_KEY:
            logging.critical("OpenRouter API key is not set or is a placeholder. Please set the OPENROUTER_API_KEY environment variable.")
            exit(1)

    def _initialize_db_schema(self):
        """Ensures the database has the 'blacklist' and 'summaries' tables with the necessary columns."""
        cursor = self.db_conn.cursor()

        # Check and alter 'blacklist' table
        cursor.execute("PRAGMA table_info(blacklist)")
        columns = [row[1] for row in cursor.fetchall()]

        if 'ban_hours' not in columns:
            try:
                cursor.execute("ALTER TABLE blacklist ADD COLUMN ban_hours INTEGER")
                logging.info("Added 'ban_hours' column to blacklist table.")
            except sqlite3.OperationalError as e:
                logging.error(f"Failed to add 'ban_hours' column, it might already exist: {e}")
                self.db_conn.rollback()

        if 'verdict' not in columns:
            try:
                cursor.execute("ALTER TABLE blacklist ADD COLUMN verdict TEXT")
                logging.info("Added 'verdict' column to blacklist table.")
            except sqlite3.OperationalError as e:
                logging.error(f"Failed to add 'verdict' column, it might already exist: {e}")
                self.db_conn.rollback()

        # Create 'summaries' table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            summary_text TEXT NOT NULL
        )
        """)
        logging.info("Ensured 'summaries' table exists.")
        self.db_conn.commit()


    def _load_monitor_config(self) -> dict:
        """Loads the main monitor's JSON configuration file."""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.critical(f"Main monitor config file not found at {CONFIG_FILE}. Cannot proceed.")
            return {}
        except json.JSONDecodeError as e:
            logging.critical(f"Error decoding JSON from {CONFIG_FILE}: {e}")
            return {}

    def _fetch_unreviewed_ips(self) -> list:
        """Fetches IPs from the database that have not yet been reviewed."""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                SELECT ip, reason_tldr, confidence, logs, sections
                FROM blacklist
                WHERE ban_hours IS NULL OR ban_hours == -2
            """)
            return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch unreviewed IPs from database: {e}")
            return []

    def _fetch_recent_verdicts(self) -> list:
        """Fetches the last 10 reviewed decisions to provide context to the LLM."""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                SELECT ip, reason_tldr, ban_hours, verdict
                FROM blacklist
                WHERE ban_hours IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            results = cursor.fetchall()
            recent_verdicts = [
                {"ip": row[0], "initial_reason": row[1], "ban_hours": row[2], "verdict": row[3]}
                for row in results
            ]
            return recent_verdicts
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch recent verdicts from database: {e}")
            return []

    def _get_full_logs_for_ip(self, ip: str) -> str:
        """Greps the last 10000 lines of all log files for an IP (or its /24 CIDR) and returns recent lines."""
        try:
            log_files = glob.glob(LOG_DIR_GLOB)
            if not log_files:
                logging.warning(f"No log files found matching {LOG_DIR_GLOB} for historical search.")
                return "No historical logs found (no files matched glob)."

            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                ip_prefix = ".".join(ip_parts[:3]) + "."
            else:
                ip_prefix = ip

            search_pattern = r'\b' + ip.replace('.', r'\.') + r'\b'
            if ip_prefix != ip:
                search_pattern = f'({search_pattern}|\\b{ip_prefix.replace(".", r".")}[0-9]+\\b)'

            # Pipeline: tail (large) -> grep -> grep -v -> tail (small) for performance
            tail_source_cmd = ['tail', '-q', '-n', '10000'] + log_files
            grep_cmd = ['grep', '-E', '--', search_pattern]
            grep_filter_cmd = ['grep', '-v', '" 444 0']
            tail_final_cmd = ['tail', '-n', '100']

            tail_source_proc = subprocess.Popen(tail_source_cmd, stdout=subprocess.PIPE, text=True, errors='ignore')
            grep_proc = subprocess.Popen(grep_cmd, stdin=tail_source_proc.stdout, stdout=subprocess.PIPE, text=True, errors='ignore')
            tail_source_proc.stdout.close()

            grep_filter_proc = subprocess.Popen(grep_filter_cmd, stdin=grep_proc.stdout, stdout=subprocess.PIPE, text=True, errors='ignore')
            grep_proc.stdout.close()

            tail_final_proc = subprocess.Popen(tail_final_cmd, stdin=grep_filter_proc.stdout, stdout=subprocess.PIPE, text=True, errors='ignore')
            grep_filter_proc.stdout.close()

            output, _ = tail_final_proc.communicate(timeout=15)
            return output.strip() if output else "No historical logs found for this IP or its /24 range in the last 10000 lines of logs."

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logging.error(f"Error executing log search command for IP {ip}: {e}")
            return "Error: External command failed or timed out."
        except Exception as e:
            logging.error(f"Unexpected error getting full logs for IP {ip}: {e}")
            return f"Error fetching logs: {e}"

    def _get_context_from_sections(self, sections_str: str) -> str:
        """Builds a consolidated context string from the server section names."""
        if not sections_str:
            return "No specific server section was identified."

        contexts = []
        section_names = {s.strip() for s in sections_str.split(',')}
        name_to_context = {
            file_conf["server_name"]: file_conf.get("system_prompt_context", "No context provided.")
            for file_conf in self.monitor_config.get("files", {}).values()
        }

        memories_by_server = defaultdict(list)
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT server_name, content FROM memories")
            for s_name, content in cursor.fetchall():
                memories_by_server[s_name or "all"].append(content)
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch memories in review.py: {e}")

        for section_name in section_names:
            context = name_to_context.get(section_name, "Context not found for this section.")
            contexts.append(f"[{section_name}]: {context}")

            # Add memories
            server_memories = memories_by_server.get("all", []) + memories_by_server.get(section_name, [])
            if server_memories:
                contexts.append("--- MEMORIES ---")
                contexts.extend(server_memories)
                contexts.append("----------------")

        return "\n".join(contexts)

    async def _ask_llm_for_review(self, review_data: dict) -> dict | None:
        """Sends all collected data to an LLM for a final verdict."""
        system_prompt = """
You are a senior cybersecurity analyst. Your task is to review an automated ban recommendation and act as a final gatekeeper to prevent false positives and determine an appropriate ban duration. Your decisions should be consistent.

You will receive a JSON object with the details of the case. Your analysis must consider all provided context, especially:
- Is this a legitimate, well-known crawler (e.g., Googlebot, AhrefsBot, Bingbot)? These should NOT be banned. Speculate from their behavior and UA, and do NOT guess whether a bot is legit just from IP range, because you don't have the latest ASN information.
- Is this a clear and blatant vulnerability scan? This warrants a long or permanent ban.
- Is the activity ambiguous or low-threat? A short-term ban might be appropriate.
- Is this a false positive? The IP should be unbanned immediately.
- How does this case compare to the `recent_verdicts`? Strive for consistent sentencing for similar offenses.

**AMENDMENT FEATURE**: During your review, you may realize a previous decision was wrong.
For example, you might see that an IP you previously unbanned (`ban_hours: 0`) is part of the same /24 subnet as the current malicious IP (`ip_to_review`), and you would want to change your mind and ban it instead.
If you decide a previous verdict needs to be overturned, use the `amends` field.

Based on your expert review, provide a decision in a strict JSON format. Your entire response must be ONLY the JSON object.

{
  "ban_hours": <integer>,
  "verdict": "<string: Your concise reasoning for the decision>",
  "amends": [
    {
        "ip": "<string: The IP from `recent_verdicts` to amend>",
        "ban_hours": <integer>,
        "verdict": "<string: Your reasoning for the amendment, must start with '**AMENDED**'>"
    }
  ]
}

- The `amends` field is OPTIONAL. It is a JSON array of amendment objects. Only include it if you are changing past verdicts.
- `ban_hours` options:
  - `-1`: Permanent ban. For clear, malicious, high-volume hacking attempts.
  - `0`: Unban immediately (or confirm not guilty). This was a false positive.
  - `1-720`: Temporary ban for N hours. For suspicious but not definitively malicious activity.
"""
        user_content_json = json.dumps(review_data, indent=2)

        preview = review_data.copy()
        if 'triggering_logs' in preview and preview['triggering_logs']:
            preview['triggering_logs'] = f"<{len(preview['triggering_logs'].splitlines())} lines of logs provided>"
        if 'historical_logs' in preview and preview['historical_logs']:
            preview['historical_logs'] = f"<{len(preview['historical_logs'].splitlines())} lines of logs provided>"
        if 'recent_verdicts' in preview:
            preview['recent_verdicts'] = f"<{len(preview.get('recent_verdicts', []))} recent verdicts provided>"

        print("\n" + "="*20 + " [ Sending for Review ] " + "="*20)
        print(json.dumps(preview, indent=2))
        print("="*64 + "\n")

        try:
            logging.info(f"Requesting review for IP: {review_data.get('ip_to_review')}")
            completion = await self.client.chat.completions.create(
                model=LLM_REVIEW_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content_json}
                ],
                response_format={"type": "json_object"},
                temperature=0.6
            )
            response_content = completion.choices[0].message.content.strip().strip('```').strip('json').strip()
            data = json.loads(response_content)

            if isinstance(data, dict) and "ban_hours" in data and "verdict" in data:
                return data
            logging.warning(f"LLM review response was malformed. Response: {response_content}")
            return None

        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON from LLM review response: {e}\nResponse text: {response_content}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during LLM review query: {e}")
        return None

    def _update_db_with_verdict(self, ip: str, ban_hours: int, verdict: str):
        """Updates the database with the final review decision."""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "UPDATE blacklist SET ban_hours = ?, verdict = ? WHERE ip = ?",
                (ban_hours, verdict, ip)
            )
            self.db_conn.commit()
            logging.info(f"Verdict for {ip} stored. Ban Hours: {ban_hours}, Verdict: {verdict}")
            if ban_hours >= 0:
                with open(UNBAN_FILE, 'w') as f:
                    f.write('1.1.1.1\n') # Signal to potentially trigger an unban script
        except sqlite3.Error as e:
            logging.error(f"Failed to update database with verdict for IP {ip}: {e}")
            self.db_conn.rollback()

    def _process_amendments(self, primary_ip: str, verdict_result: dict):
        """Processes any amendments to past verdicts."""
        if "amends" in verdict_result and isinstance(verdict_result["amends"], list):
            for amend_data in verdict_result["amends"]:
                if not isinstance(amend_data, dict):
                    logging.warning(f"Skipping malformed item in 'amends' list (not a dict): {amend_data}")
                    continue
                amend_ip = amend_data.get("ip")
                amend_ban_hours = amend_data.get("ban_hours")
                amend_verdict = amend_data.get("verdict")

                if all([amend_ip, isinstance(amend_ban_hours, int), amend_verdict]):
                    logging.info(f"Amending verdict for IP {amend_ip} based on new review for {primary_ip}.")
                    self._update_db_with_verdict(amend_ip, amend_ban_hours, amend_verdict)
                else:
                    logging.warning(f"Malformed 'amends' object received for {primary_ip} review. Skipping amendment. Data: {amend_data}")

    def _fetch_data_for_summary(self) -> dict | None:
        """Fetches and aggregates data since the last summary for the report."""
        try:
            cursor = self.db_conn.cursor()

            # Determine the start timestamp for the summary period
            cursor.execute("SELECT MAX(timestamp) FROM summaries")
            last_summary_ts = cursor.fetchone()[0]

            if last_summary_ts:
                start_timestamp = last_summary_ts
                logging.info(f"Fetching data for summary since last summary at {datetime.fromtimestamp(start_timestamp).isoformat()}")
            else:
                start_timestamp = int(time.time()) - SUMMARY_INTERVAL_SECONDS
                logging.info(f"No previous summary found. Fetching data from the last {SUMMARY_INTERVAL_SECONDS // 3600} hours.")
            cursor.execute("""
                SELECT ip, reason_tldr, ban_hours, verdict
                FROM blacklist
                WHERE verdict IS NOT NULL AND timestamp >= ?
            """, (start_timestamp,))
            rows = cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch data for summary: {e}")
            return None

        if not rows:
            return None

        stats = {"total_reviews": len(rows), "permanent_bans": 0, "temporary_bans": 0, "false_positives": 0, "amendments": 0}
        incidents = []
        boring_keywords = ['wordpress', 'wp-login', '.env', 'phpmyadmin', 'backup']

        for row in rows:
            ip, reason, ban_hours, verdict = row
            if ban_hours == -1: stats["permanent_bans"] += 1
            elif ban_hours > 0: stats["temporary_bans"] += 1
            elif ban_hours == 0: stats["false_positives"] += 1
            if verdict and verdict.strip().startswith("**AMENDED**"): stats["amendments"] += 1

            # is_boring = any(keyword in reason.lower() or keyword in verdict.lower() for keyword in boring_keywords)
            # if not is_boring and ban_hours != 0:
            incidents.append({"ip": ip, "reason": reason, "ban_hours": ban_hours, "verdict": verdict})

        return {"stats": stats, "incidents": incidents, "last_summary_ts": last_summary_ts}

    def _fetch_previous_summaries(self) -> list:
        """Fetches recent summaries from the database (last 7 days, max 10)."""
        try:
            cursor = self.db_conn.cursor()
            seven_days_ago_ts = int(time.time()) - (7 * 24 * 60 * 60)
            cursor.execute("""
                SELECT timestamp, summary_text
                FROM summaries
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (seven_days_ago_ts,))

            summaries = [f"--- {datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M')} 的摘要 ---\n{row[1]}" for row in cursor.fetchall()]
            return summaries
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch previous summaries: {e}")
            return []

    def _store_summary(self, summary_text: str, incidents_json: str):
        """Stores the newly generated summary and its incidents in the database."""
        try:
            cursor = self.db_conn.cursor()
            insert_query = "INSERT INTO summaries (timestamp, summary_text, incidents) VALUES (?, ?, ?)"
            values = (int(time.time()), summary_text, incidents_json)
            try:
                cursor.execute(insert_query, values)
            except sqlite3.OperationalError as e:
                # One-time migration attempt if the column is missing
                if "no column named incidents" in str(e).lower():
                    logging.warning("Attempting to add 'incidents' column to 'summaries' table.")
                    self.db_conn.rollback()
                    cursor.execute("ALTER TABLE summaries ADD COLUMN incidents TEXT NOT NULL DEFAULT '[]'")
                    self.db_conn.commit()
                    logging.info("Successfully added 'incidents' column. Retrying insert.")
                    cursor.execute(insert_query, values)
                else:
                    raise  # Re-raise other operational errors
            self.db_conn.commit()
            logging.info("Successfully stored new summary in the database.")
        except sqlite3.Error as e:
            logging.error(f"Failed to store summary in database: {e}")
            self.db_conn.rollback()

    async def _ask_llm_for_summary(self, incidents: list, previous_summaries: list, timeframe: str) -> str | None:
        """Generates a narrative summary of notable incidents using the LLM in Traditional Chinese."""
        system_prompt = """
您是一位資深網路安全分析師AI。您的任務是為團隊撰寫一份關於重大安全事件的敘述性摘要。

您將收到過去幾小時的入侵偵測事件列表，以及最近幾天的摘要供您參考。您的摘要應具備以下特點：
- **您的整個回應必須僅為純文字，並以繁體中文書寫。**
- 請勿使用任何Markdown或特殊格式，如 *、_ 或 `。
- 使用簡單的段落和列表（例如，使用連字號 - 作為列表項）。
- 突出 `incidents` 中最有趣或最嚴重的安全事件，或疑似人類行為(非全自動)的惡意事件。
- 盡量過濾無關痛癢的攻擊，例如針對PHP站點或WordPress漏洞惡意掃描十分頻密，而團隊沒什麼後端是PHP。不是很特別的話，請輕輕帶過。
- 把重點放在針對性的攻擊而非惡意掃描器。
- 對於針對性的攻擊，描述任何可觀察到的攻擊模式（例如，來自單一ASN的協同掃描，多個IP針對同一漏洞的攻擊)
- 若有事件是裁決為臨時封鎖或誤報，描述行為和修正原因。
- 參考 `previous_summaries` 以識別新趨勢或持續存在的威脅。
- 最後以一段簡短的聲明總結基於这些事件的整體安全狀況，並建議任何可新增的nginx設定。

基本的統計數據（總審查次數、封鎖次數等）已經格式化，不是您的責任。請專注於對所提供事件的質化分析。
"""
        previous_summaries_text = "\n\n".join(previous_summaries) if previous_summaries else "沒有可用的先前摘要。"
        user_content = f"""
這是供您摘要的事件列表 ({timeframe})：
{json.dumps(incidents, indent=2, ensure_ascii=False)}

這是過去幾天的摘要供您參考：
{previous_summaries_text}
"""
        logging.info("Requesting narrative summary for notable incidents from LLM.")
        try:
            completion = await self.client.chat.completions.create(
                model=LLM_REVIEW_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                temperature=0.6
            )
            summary_text = completion.choices[0].message.content.strip()
            return summary_text
        except Exception as e:
            logging.error(f"An unexpected error occurred during LLM summary generation: {e}")
            return None

    def set_telegram_callback(self, callback):
        """Sets a callback function for sending Telegram messages."""
        self.telegram_callback = callback

    def _send_telegram_message(self, text: str, topic_id: int | None = None):
        """Sends a message via the shared Telegram callback."""
        if hasattr(self, 'telegram_callback') and self.telegram_callback:
            self.telegram_callback(text, topic_id)
        else:
            logging.warning("Telegram callback not set, message not sent: %s", text)

    def _fetch_incidents_for_summary_by_timestamp(self, summary_ts: int) -> str | None:
        """Fetches the raw incidents JSON for a summary closest to a given timestamp."""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("""
                SELECT incidents
                FROM summaries
                ORDER BY ABS(timestamp - ?)
                LIMIT 1
            """, (summary_ts,))
            result = cursor.fetchone()
            return result[0] if result else None
        except sqlite3.Error as e:
            logging.error(f"Failed to fetch incidents for summary at ts {summary_ts}: {e}")
            return None

    async def _ask_llm_for_telegram_reply(self, original_message: str, user_reply: str, incidents_json: str | None) -> str | None:
        """Asks the LLM to formulate a response to a user's reply on Telegram."""
        system_prompt = """
You are a helpful cybersecurity analyst assistant AI. A user has replied to one of your monitoring summaries on Telegram. Your task is to provide a concise and helpful answer based on the context of the original summary, the user's query, and the raw incident data.

- The user's message is a reply to the `original_message`.
- Your response should be in the same language as the user's query (assume Traditional Chinese if unsure).
- Keep your answer brief and to the point.
- Use the provided `incident_data` to answer specific questions about the events that led to the summary.
- You do not have access to real-time data or the database beyond what's provided. Base your answer only on the text provided.
"""
        incidents_context = ""
        if incidents_json:
            try:
                incidents_data = json.loads(incidents_json)
                if incidents_data:
                    pretty_incidents = json.dumps(incidents_data, indent=2, ensure_ascii=False)
                    incidents_context = f"""
FOR YOUR CONTEXT, HERE IS THE RAW INCIDENT DATA RELATED TO THE ORIGINAL MESSAGE:
---
{pretty_incidents}
---
"""
            except (json.JSONDecodeError, TypeError):
                logging.warning("Could not parse incidents JSON for Telegram reply context.")

        user_content = f"""
{incidents_context}
ORIGINAL MESSAGE:
---
{original_message}
---

USER'S REPLY:
---
{user_reply}
---

Based on the above, please provide a helpful response to the user.
"""
        logging.info(f"Requesting LLM response for Telegram reply.")
        try:
            completion = await self.client.chat.completions.create(
                model=LLM_REVIEW_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                temperature=0.5
            )
            response_text = completion.choices[0].message.content.strip()
            return response_text
        except Exception as e:
            logging.error(f"An unexpected error occurred during LLM reply generation: {e}")
            return "抱歉，我在處理您的請求時遇到錯誤。"

    async def _run_summary_task(self):
        """Orchestrates the creation and sending of the daily summary."""
        logging.info("Starting summary task.")
        summary_data = self._fetch_data_for_summary()
        if not summary_data or summary_data.get("stats", {}).get("total_reviews", 0) == 0:
            logging.info("No reviewed incidents in the summary period to summarize.")
            # Store an empty summary to advance the timestamp
            self._store_summary("期間內無事件。", '[]')
            return

        stats = summary_data["stats"]
        last_ts = summary_data.get("last_summary_ts")

        if last_ts:
            hours_since_last = (time.time() - last_ts) / 3600
            time_frame_str = f"過去 {hours_since_last:.1f} 小時"
        else:
            hours_since_last = SUMMARY_INTERVAL_SECONDS / 3600
            time_frame_str = f"過去 {int(hours_since_last)} 小時"

        stats_header = (
            f"安全摘要 ({time_frame_str})\n\n"
            f"總審查事件數: {stats['total_reviews']}\n"
            f"永久封鎖數: {stats['permanent_bans']}\n"
            f"臨時封鎖數: {stats['temporary_bans']}\n"
            f"已避免的誤報: {stats['false_positives']}\n"
            f"已修正的裁決: {stats['amendments']}"
        )
        llm_narrative = ""
        previous_summaries = self._fetch_previous_summaries()

        if summary_data["incidents"]:
            incidents_json = json.dumps(summary_data["incidents"], ensure_ascii=False)
            narrative_part = await self._ask_llm_for_summary(summary_data["incidents"], previous_summaries, time_frame_str)
            if narrative_part:
                llm_narrative = "\n\n入侵事件與分析:\n" + narrative_part
                self._store_summary(narrative_part, incidents_json)
            else:
                logging.error("Summary generation failed; did not receive narrative from LLM.")
                self._store_summary("摘要生成失敗。", '[]')
        else:
            llm_narrative = "\n\n無特別入侵事件可報告。"
            self._store_summary("無特別入侵事件可報告。", '[]')

        full_summary = stats_header + llm_narrative
        print('*************************')
        print(full_summary)
        print('*************************')
        self._send_telegram_message(full_summary, topic_id=TOPIC_ID_SUMMARIES)

    async def _process_single_review(self, entry, recent_verdicts):
        """Processes a single IP review asynchronously."""
        ip, reason, confidence, logs, sections = entry
        review_data = {
            "ip_to_review": ip,
            "initial_reason": reason,
            "initial_confidence": confidence,
            "affected_sections": sections,
            "triggering_logs": logs,
            "server_context": self._get_context_from_sections(sections),
            "historical_logs": await asyncio.to_thread(self._get_full_logs_for_ip, ip),
            "recent_verdicts": recent_verdicts,
        }
        verdict_result = await self._ask_llm_for_review(review_data)
        
        if verdict_result:
            ban_hours = verdict_result.get("ban_hours")
            verdict_text = verdict_result.get("verdict")
            self._update_db_with_verdict(ip, ban_hours, verdict_text)
            self._process_amendments(ip, verdict_result)

            # Send message for every review
            prefix = "[Review]" if ban_hours != -1 else "[Ban]"
            server_tag = f" [{sections}]" if sections else ""
            msg = f"{prefix}{server_tag} {ip}\nBan Hours: {ban_hours}\nVerdict: {verdict_text}"
            self._send_telegram_message(msg, topic_id=TOPIC_ID_BANS_REVIEWS)
        else:
            logging.warning(f"Review for IP {ip} failed. Marking to prevent retry loop.")
            self._update_db_with_verdict(ip, -2, "Review failed due to API or parsing error.")

    async def run(self):
        """Main loop to periodically check for reviews and generate summaries."""
        logging.info("Starting Ban Reviewer process.")

        if not self.db_conn:
            raise RuntimeError("Database connection not initialized. BanReviewer must be provided with a db_conn.")

        self._initialize_db_schema()
        await self._run_summary_task()
        self.last_summary_time = time.time()

        try:
            while True:
                if time.time() - self.last_summary_time >= SUMMARY_INTERVAL_SECONDS:
                    await self._run_summary_task()
                    self.last_summary_time = time.time()

                try:
                    unreviewed_entries = self._fetch_unreviewed_ips()
                    if not unreviewed_entries:
                        logging.info(f"No new entries to review. Waiting for {REVIEW_INTERVAL_SECONDS} seconds.")
                    else:
                        logging.info(f"Found {len(unreviewed_entries)} new entries to review.")
                        recent_verdicts = self._fetch_recent_verdicts()

                        # Process all reviews in parallel
                        tasks = [self._process_single_review(entry, recent_verdicts) for entry in unreviewed_entries]
                        await asyncio.gather(*tasks)
                        logging.info("Review cycle complete.")

                except sqlite3.Error as e:
                    logging.critical(f"Database error during review cycle: {e}")
                except Exception as e:
                    logging.critical(f"An unexpected error occurred during review cycle: {e}", exc_info=True)
                
                await asyncio.sleep(REVIEW_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logging.info("Ban Reviewer task cancelled.")
        except Exception as e:
            logging.error(f"Error in Ban Reviewer main loop: {e}", exc_info=True)
        finally:
            logging.info("Ban Reviewer stopped.")


if __name__ == "__main__":
    print("This script should be run via start.py")
