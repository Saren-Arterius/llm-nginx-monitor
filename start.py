import os
import logging
import threading
import asyncio
import sqlite3
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
        self.loop = asyncio.new_event_loop()
        self.bot = Bot(token=token)

    def send_message_sync(self, text, topic_id=None, reply_to_message_id=None):
        """Synchronous wrapper to send a telegram message."""
        async def send():
            await self.bot.send_message(
                chat_id=self.group_id,
                text=text,
                message_thread_id=topic_id,
                reply_to_message_id=reply_to_message_id
            )
        asyncio.run_coroutine_threadsafe(send(), self.loop)

    def run(self):
        asyncio.set_event_loop(self.loop)
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
                    for ip in ips: f.write(f"{ip.strip()}\n")
                await update.message.reply_text(f"Queued unban for {len(ips)} IPs.", message_thread_id=TOPIC_ID_BANS_REVIEWS)
            except Exception as e:
                await update.message.reply_text(f"Error: {e}", message_thread_id=TOPIC_ID_BANS_REVIEWS)

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
                llm_response = self.ban_reviewer._ask_llm_for_telegram_reply(original_text, user_reply, incidents_json)
                if llm_response:
                    await message.reply_text(llm_response)

        app.add_handler(CommandHandler("memory", memory_cmd))
        app.add_handler(CommandHandler("unban", unban_cmd))
        app.add_handler(MessageHandler(filters.REPLY & ~filters.COMMAND, handle_reply))
        
        logging.info("Shared Telegram bot starting...")
        app.run_polling(stop_signals=None)

def ban():
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
    
    # Set callbacks
    monitor.set_telegram_callback(shared_bot.send_message_sync)
    reviewer.set_telegram_callback(shared_bot.send_message_sync)
    
    # Start threads
    monitor_thread = threading.Thread(target=monitor.run, daemon=True)
    reviewer_thread = threading.Thread(target=reviewer.run, daemon=True)
    bot_thread = threading.Thread(target=shared_bot.run, daemon=True)
    
    monitor_thread.start()
    reviewer_thread.start()
    bot_thread.start()
    
    logging.info("All components started. Press Ctrl+C to stop.")
    
    try:
        while True:
            monitor_thread.join(1)
            reviewer_thread.join(1)
            bot_thread.join(1)
    except KeyboardInterrupt:
        logging.info("Shutdown requested.")

if __name__ == "__main__":
    ban()