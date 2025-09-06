# LLM-Powered Nginx Log Monitor & Automated Ban System

This project provides a sophisticated, two-stage system for automatically detecting and banning malicious actors by monitoring Nginx access logs. It leverages Large Language Models (LLMs) to analyze log data, make intelligent banning decisions, and provide detailed summaries of security events.

The system is split into two main components:
1.  **`main.py` (Log Monitor):** Performs real-time log monitoring, sends suspicious log batches to an LLM for initial analysis, and applies immediate bans to identified threats.
2.  **`review.py` (Ban Reviewer):** Acts as a secondary, more detailed analysis layer. It reviews the automated bans, gathers more historical context, and uses an LLM to determine an appropriate ban duration (e.g., permanent, temporary, or unban/false positive). It can also generate periodic summaries for human review via Telegram.

## Features

- **Real-time Log Monitoring:** Uses `inotify` to watch Nginx log files for changes.
- **AI-Powered Threat Detection:** Batches log entries and sends them to an LLM for analysis to identify malicious patterns like vulnerability scanning.
- **Automated IP Blacklisting:** Automatically generates an Nginx `deny` list (`blacklist.conf`) using the `geo` module to efficiently block malicious IPs.
- **Two-Stage Analysis:**
    - **Stage 1 (Detect & Block):** Quickly identifies and blocks active threats.
    - **Stage 2 (Review & Sentence):** Performs a deeper analysis to determine a final verdict and ban duration, reducing false positives.
- **Contextual Reviews:** The reviewer script gathers historical logs and server context to give the LLM a complete picture before it makes a final decision.
- **Periodic Summaries:** Generates daily summaries of security incidents, analysis, and trends, and reports them to a Telegram group.
- **Manual Unban:** A simple text file (`/tmp/nginx-unban-ips.txt`) can be used to manually unban one or more IPs.
- **Persistent State:** Uses a SQLite database (`blacklist.db`) to track all banned IPs, reasons, verdicts, and ban history.

## How It Works

1.  **Monitoring (`main.py`):**
    - The script continuously monitors Nginx access log files specified in the configuration.
    - New log entries (from public IPs) are collected into a queue.
    - When the queue is full or a timeout is reached, the batch of logs is sent to an LLM for initial analysis.
    - The LLM returns a list of IPs it deems malicious.
    - These IPs are added to the `blacklist.db` with an "unreviewed" status.

2.  **Blocking (`main.py`):**
    - After the database is updated, `main.py` regenerates `/etc/nginx/conf.d/blacklist.conf`. This file uses Nginx's `geo` module to set a variable (`$is_denied`) to `1` for any IP in the blacklist.
    - It then triggers `sudo nginx -s reload` to apply the changes.
    - Your Nginx server configuration uses this `$is_denied` variable to return a `444` (Connection Closed Without Response) for any request from a blocked IP.

3.  **Reviewing (`review.py`):**
    - This script periodically queries `blacklist.db` for IPs that haven't been reviewed.
    - For each unreviewed IP, it gathers:
        - The original triggering logs.
        - The server context (from `log_monitor_config.json`).
        - Historical logs for that IP/subnet from all log files.
        - A list of recent verdicts for other IPs to ensure consistency.
    - It sends this comprehensive package to a senior analyst LLM for a final verdict on the `ban_hours` (`-1` for permanent, `0` for unban, `1+` for a temporary ban).
    - The final verdict and reasoning are stored back in the database.

4.  **Reporting (`review.py`):**
    - Once every 12 hours, the script generates a summary of all reviewed incidents.
    - It uses an LLM to create a human-readable narrative in Traditional Chinese, highlighting interesting trends or attacks.
    - The summary is sent to a configured Telegram group. The script can also handle user replies to these summaries.

## Components

- **`main.py`**: The real-time log monitor and initial banning agent.
- **`review.py`**: The ban reviewer, sentencing agent, and report generator.
- **`nginx-snippets/`**: Example Nginx configuration snippets demonstrating how to use the `$is_denied` variable.
- **`blacklist.db`**: SQLite database storing state about banned IPs.
- **`log_monitor_config.json`**: Configuration for log files. Auto-generated on first run.

---

## Setup and Installation

### 1. Prerequisites

- Python 3.x
- Nginx
- `sudo` access for the user running the scripts.

### 2. Python Dependencies

Install the required Python libraries.

```bash
pip install openai inotify-simple
```

### 3. API and Bot Credentials

The scripts require API keys set as environment variables.

```bash
export OPENROUTER_API_KEY="your_openrouter_api_key_here"
export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"
export TELEGRAM_GROUP_ID="your_telegram_group_id"
```

**Note:** The LLM models (`@preset/wtako-nginx-llm`) in the scripts appear to be custom presets. You will likely need to replace them with generally available models on OpenRouter.ai (e.g., `mistralai/mistral-7b-instruct` or `openai/gpt-4o`).

### 4. Configure File Paths

The scripts have path constants defined at the top. Ensure they match your system's layout. The most important ones are:
- `main.py`: `LOG_DIR_GLOB`, `NGINX_DENY_LIST`, `UNBAN_FILE`.
- `review.py`: `DB_FILE`, `CONFIG_FILE`, `LOG_DIR_GLOB`.

### 5. Nginx Configuration

You need to configure Nginx to use the `blacklist.conf` file generated by `main.py`.

1.  **Include the blacklist file** in your main `nginx.conf` within the `http` block.

    ```nginx /etc/nginx/nginx.conf
    http {
        # ... other http settings ...

        # Defines the $is_denied variable based on the client's IP
        include /etc/nginx/conf.d/blacklist.conf;

        # ... rest of http settings ...
    }
    ```

2.  **Use the `$is_denied` variable** in your server blocks to deny access. You can add this logic directly or use the provided snippets. This should be one of the very first rules in your `server` block.

    ```nginx /etc/nginx/sites-available/your-site.conf
    server {
        listen 80;
        server_name example.com;

        # Block banned IPs immediately
        if ($is_denied) {
            return 444;
        }

        # ... rest of your server configuration ...
    }
    ```
    The files in `nginx-snippets/` show more advanced examples of this.

### 6. Sudo Permissions

The `main.py` script needs passwordless `sudo` permission to reload Nginx. Run `sudo visudo` and add the following line, replacing `<user>` with the user that will run the script.

```
# Allow the <user> user to reload nginx without a password
<user> ALL=(ALL) NOPASSWD: /usr/sbin/nginx -s reload
```
*(Verify the path to your Nginx binary with `which nginx`)*

### 7. Initial Run

On the first run, `main.py` will create `log_monitor_config.json`. You should **edit this file** to provide more specific context for each of your sites in the `system_prompt_context` field. This will greatly improve the LLM's accuracy.

```json log_monitor_config.json
{
    "files": {
        "/var/log/nginx/saren/wtako.net/myservice.log": {
            "server_name": "myservice",
            "cursor": 12345,
            "system_prompt_context": "This server 'myservice' hosts a public API for a mobile app. It does not use PHP or WordPress."
        }
    }
}
```

## Running the System

Both `main.py` and `review.py` are long-running daemons. It is highly recommended to run them as services using `systemd` or `supervisor`.

For manual execution:

**Terminal 1: Run the Log Monitor**
```bash
python3 main.py
```

**Terminal 2: Run the Ban Reviewer**
```bash
python3 review.py
```

## Usage

### Manual Unbanning

To unban one or more IPs, simply add them to `/tmp/nginx-unban-ips.txt`, one per line. The `main.py` script will detect the change, remove the IPs from the database, regenerate `blacklist.conf`, and reload Nginx. The file will be cleared after processing.

```bash
echo "198.51.100.10" > /tmp/nginx-unban-ips.txt
echo "203.0.113.25" >> /tmp/nginx-unban-ips.txt
```