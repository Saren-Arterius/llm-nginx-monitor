import os
import logging
import threading
import asyncio
import sqlite3
import re
from dotenv import load_dotenv
from telegram import Bot
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
from ban import LogMonitor
from review import BanReviewer

# Load environment variables
load_dotenv()

# Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_GROUP_ID = os.getenv("TELEGRAM_GROUP_ID", "")
DB_FILE = os.getenv("DB_FILE", "blacklist.db")
UNBAN_FILE = os.getenv("UNBAN_FILE", "/tmp/nginx-unban-ips.txt")
TOPIC_ID_BANS_REVIEWS = int(os.getenv("TOPIC_ID_BANS_REVIEWS", "3"))

# Log Monitor Configuration
LOG_DIR_GLOB = os.getenv("LOG_DIR_GLOB", "/var/log/nginx/saren/wtako.net/*.log")
CONFIG_FILE = os.getenv("CONFIG_FILE", "log_monitor_config.json")
NGINX_DENY_LIST = os.getenv("NGINX_DENY_LIST", "/etc/nginx/conf.d/blacklist.conf")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Start] - %(message)s')

class SharedBot:
    def __init__(self, token, group_id, log_monitor, ban_reviewer):
        self.token = token
        self.group_id = group_id
        self.log_monitor = log_monitor
        self.ban_reviewer = ban_reviewer
        self.bot = Bot(token=token)

    async def send_message(self, text, topic_id=None, reply_to_message_id=None):
        """Asynchronous method to send a telegram message."""
        await self.bot.send_message(
            chat_id=self.group_id,
            text=text,
            message_thread_id=topic_id,
            reply_to_message_id=reply_to_message_id
        )

    def run(self):
        app = ApplicationBuilder().token(self.token).build()

        async def memory_cmd(update, context):
            if str(update.effective_chat.id) != self.group_id: return
            args = context.args
            if not args: return
            cmd = args[0]
            
            try:
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    if cmd == "add" and len(args) >= 3:
                        s_name, content = args[1], " ".join(args[2:])
                        valid_servers = [f['server_name'] for f in self.log_monitor.config.get('files', {}).values()]
                        if s_name != "all" and s_name not in valid_servers:
                            await update.message.reply_text(f"Invalid server: {s_name}", message_thread_id=TOPIC_ID_BANS_REVIEWS)
                        else:
                            cursor.execute("INSERT INTO memories (server_name, content) VALUES (?, ?)", (s_name, content))
                            await update.message.reply_text("Memory added.", message_thread_id=TOPIC_ID_BANS_REVIEWS)
                    elif cmd == "list":
                        cursor.execute("SELECT id, server_name, content FROM memories")
                        rows = cursor.fetchall()
                        resp = "\n".join([f"{r[0]}. [{r[1]}]: {r[2]}" for r in rows]) or "No memories."
                        await update.message.reply_text(resp, message_thread_id=TOPIC_ID_BANS_REVIEWS)
                    elif cmd == "delete" and len(args) >= 2:
                        cursor.execute("DELETE FROM memories WHERE id = ?", (args[1],))
                        await update.message.reply_text(f"Deleted {args[1]}.", message_thread_id=TOPIC_ID_BANS_REVIEWS)
                    elif cmd == "replace" and len(args) >= 3:
                        cursor.execute("UPDATE memories SET content = ? WHERE id = ?", (" ".join(args[2:]), args[1]))
                        await update.message.reply_text(f"Replaced {args[1]}.", message_thread_id=TOPIC_ID_BANS_REVIEWS)
            except Exception as e:
                await update.message.reply_text(f"Error: {e}", message_thread_id=TOPIC_ID_BANS_REVIEWS)

        async def unban_cmd(update, context):
            if str(update.effective_chat.id) != self.group_id: return
            ips = "".join(context.args).split(',')
            try:
                with open(UNBAN_FILE, 'a') as f:
                    for ip in ips:
                        if ip.strip():
                            f.write(f"{ip.strip()}\n")
                await update.message.reply_text(f"Queued unban for {len(ips)} IPs.", message_thread_id=TOPIC_ID_BANS_REVIEWS)
            except Exception as e:
                await update.message.reply_text(f"Error: {e}", message_thread_id=TOPIC_ID_BANS_REVIEWS)

        async def logs_cmd(update, context):
            if str(update.effective_chat.id) != self.group_id: return
            message = update.effective_message
            if not message.reply_to_message:
                await message.reply_text("Please reply to a ban record to fetch logs.")
                return

            original_text = message.reply_to_message.text or ""
            # Extract IP (v4 or v6)
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)', original_text)
            if not ip_match:
                await message.reply_text("Could not find an IP address in the quoted message.")
                return

            ip = ip_match.group(1)
            await message.reply_text(f"Fetching logs for {ip}...")

            try:
                # Use the existing logic from BanReviewer to get logs
                logs = self.ban_reviewer._get_full_logs_for_ip(ip)
                lines = logs.splitlines()
                
                if len(lines) <= 50:
                    response = logs if logs else "No logs found."
                else:
                    first_25 = lines[:25]
                    last_25 = lines[-25:]
                    skipped = len(lines) - 50
                    response = "\n".join(first_25) + f"\n\n... [{skipped} lines skipped] ...\n\n" + "\n".join(last_25)
                
                # Telegram has a 4096 char limit, truncate if necessary
                if len(response) > 4000:
                    response = response[:4000] + "... (truncated)"
                
                await message.reply_text(f"Logs for {ip}:\n\n{response}")
            except Exception as e:
                await message.reply_text(f"Error fetching logs: {e}")

        async def reply_unban_cmd(update, context):
            if str(update.effective_chat.id) != self.group_id: return
            message = update.effective_message
            if not message.reply_to_message:
                await message.reply_text("Please reply to a ban record to unban.")
                return

            original_text = message.reply_to_message.text or ""
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)', original_text)
            if not ip_match:
                await message.reply_text("Could not find an IP address in the quoted message.")
                return

            ip = ip_match.group(1)
            try:
                with open(UNBAN_FILE, 'a') as f:
                    f.write(f"{ip}\n")
                await message.reply_text(f"Queued unban for {ip}.")
            except Exception as e:
                await message.reply_text(f"Error: {e}")

        async def handle_reply(update, context):
            message = update.effective_message
            if not (message and str(message.chat_id) == self.group_id and message.reply_to_message and not message.from_user.is_bot):
                return

            reply_to_msg = message.reply_to_message
            original_text = reply_to_msg.text or ""
            original_ts = int(reply_to_msg.date.timestamp())
            user_reply = message.text or ""

            if original_text and user_reply:
                logging.info(f"Received Telegram reply to process: '{user_reply[:50]}...'")
                incidents_json = self.ban_reviewer._fetch_incidents_for_summary_by_timestamp(original_ts)
                llm_response = await self.ban_reviewer._ask_llm_for_telegram_reply(original_text, user_reply, incidents_json)
                if llm_response:
                    await message.reply_text(llm_response)

        app.add_handler(CommandHandler("memory", memory_cmd))
        app.add_handler(CommandHandler("unban", unban_cmd))
        app.add_handler(CommandHandler("logs", logs_cmd))
        app.add_handler(MessageHandler(filters.REPLY & filters.Regex(r'^/unban'), reply_unban_cmd))
        app.add_handler(MessageHandler(filters.REPLY & filters.Regex(r'^/logs'), logs_cmd))
        app.add_handler(MessageHandler(filters.REPLY & ~filters.COMMAND, handle_reply))
        
        logging.info("Shared Telegram bot starting...")
        
        async def post_init(application):
            await application.bot.send_message(
                chat_id=self.group_id,
                text="🚀 Nginx Monitor Bot started and monitoring logs.",
                message_thread_id=TOPIC_ID_BANS_REVIEWS
            )

        app.post_init = post_init
        return app

async def main():
    # Shared database connection
    db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)

    # Initialize components
    monitor = LogMonitor(
        log_dir_glob=LOG_DIR_GLOB,
        config_file=CONFIG_FILE,
        nginx_deny_list=NGINX_DENY_LIST,
        unban_file=UNBAN_FILE,
        db_conn=db_conn
    )
    
    reviewer = BanReviewer(db_conn=db_conn)
    
    # Initialize shared bot
    shared_bot = SharedBot(TELEGRAM_BOT_TOKEN, TELEGRAM_GROUP_ID, monitor, reviewer)
    
    # Set callbacks (now using async send_message)
    def telegram_callback(text, topic_id=None):
        asyncio.create_task(shared_bot.send_message(text, topic_id))
    
    monitor.set_telegram_callback(telegram_callback)
    reviewer.set_telegram_callback(telegram_callback)
    
    # Initialize Telegram App
    app = shared_bot.run()
    
    logging.info("All components starting in async loop...")
    
    # Run everything together
    async with app:
        await app.initialize()
        await app.start()
        await app.updater.start_polling()
        
        await asyncio.gather(
            monitor.run(),
            reviewer.run(),
        )
        
        await app.updater.stop()
        await app.stop()
        await app.shutdown()

def ban():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutdown requested.")

if __name__ == "__main__":
    ban()