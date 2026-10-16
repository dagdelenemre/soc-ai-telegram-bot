#!/usr/bin/env python3
import os
import sys
import re
import json
import time
import subprocess
import urllib.request
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # IDE and local repository execution
    from core.soc_config import load_soc_config
except ImportError:
    # Production flattened execution (/usr/local/bin)
    from soc_config import load_soc_config  # type: ignore

config = load_soc_config()
GROQ_API_KEY = config.get("GROQ_API_KEY")
SERVER_IP = config.get("SERVER_IP", "255.255.255.255")

STATE_FILE = "/var/lib/soc/last_run"
WARN_FILE = "/var/lib/soc/last_warn"
DB_PATH = "/var/lib/soc/soc_logs.db"

def mask_sensitive(text):
    text = re.sub(r'\b(([0-9]{1,3}\.){3})[0-9]{1,3}\b', r'\1XXX', text)
    text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_MASKED]', text)
    text = re.sub(r'(?i)(password|pass|pwd)=[^ &]*', r'\1=[PASS_MASKED]', text)
    text = re.sub(r'Bearer [a-zA-Z0-9._-]+', 'Bearer [TOKEN_MASKED]', text)
    return text

def get_last_run():
    try:
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    except:
        return "3 minutes ago"

def run_cmd(cmd, input=None):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=input)
        return res.stdout
    except:
        return ""

# --- Time window filtering ---
# Log timestamps are parsed and compared as datetimes. Comparing them as strings
# (the previous awk approach) breaks at month/year changes for nginx
# ("31/Oct/..." >= "01/Nov/...") and on days 1-9 for syslog ("Nov  5" vs "Nov 05").

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# nginx $time_local: [31/Oct/2026:23:50:00 +0300]
NGINX_ACCESS_TS = re.compile(r'\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-]\d{4}))?\]')
# Classic syslog: "Nov  5 10:30:00 host ..." (day padded with a space, no year)
SYSLOG_TS = re.compile(r'([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ')
# RFC 3339 syslog (newer Ubuntu): "2026-11-05T10:30:00.123456+03:00 host ..."
ISO_TS = re.compile(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?(?:\s|$)')
RELATIVE_SINCE = re.compile(r'\s*(\d+)\s+(second|minute|hour|day|week)s?\s+ago\s*$')

def _offset_tz(text):
    # "+0300", "+03:00" or "Z" -> tzinfo
    return datetime.strptime(text, "%z").tzinfo

def _to_local_naive(dt):
    # Everything is compared as naive local time, like datetime.now() in the state file
    if dt.tzinfo is not None:
        return dt.astimezone().replace(tzinfo=None)
    return dt

def parse_last_run(last_run, now=None):
    """Turns the state file value (datetime.isoformat() or e.g. '3 minutes ago') into a datetime."""
    now = now or datetime.now()
    try:
        since = _to_local_naive(datetime.fromisoformat(last_run.strip()))
    except ValueError:
        m = RELATIVE_SINCE.match(last_run)
        if m:
            since = now - timedelta(**{m.group(2) + "s": int(m.group(1))})
        else:
            # Unreadable state: fall back to the default window instead of the whole file
            since = now - timedelta(minutes=3)
    # Log lines have second precision; a line from the same second as the last run is kept
    return since.replace(microsecond=0)

def parse_nginx_access_ts(line):
    m = NGINX_ACCESS_TS.search(line)
    if not m or m.group(2) not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, off = m.groups()
    try:
        dt = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
        if off:
            dt = dt.replace(tzinfo=_offset_tz(off))
        return _to_local_naive(dt)
    except ValueError:
        return None

def parse_syslog_ts(line, now=None):
    m = ISO_TS.match(line)
    if m:
        try:
            dt = datetime(*(int(g) for g in m.groups()[:6]))
            if m.group(7):
                dt = dt.replace(tzinfo=_offset_tz(m.group(7)))
            return _to_local_naive(dt)
        except ValueError:
            return None
    m = SYSLOG_TS.match(line)
    if not m or m.group(1) not in MONTHS:
        return None
    # Classic syslog has no year: assume the current one, unless that puts the line
    # in the future (December lines read in January belong to last year)
    now = now or datetime.now()
    mon, day, hh, mm, ss = MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    for year in (now.year, now.year - 1):
        try:
            dt = datetime(year, mon, day, hh, mm, ss)
        except ValueError:  # e.g. Feb 29 in a non-leap year
            continue
        if dt <= now + timedelta(days=1):
            return dt
    return None

def filter_since(lines, since, parse_ts):
    """Returns the lines logged at or after `since`, joined as text.

    A line without a parsable timestamp (e.g. a continuation line) belongs to the
    last timestamped line before it and is kept or dropped together with it.
    Lines before the first timestamped line are dropped, since their age is unknown.
    """
    out = []
    keep = False
    for line in lines:
        ts = parse_ts(line)
        if ts is not None:
            keep = ts >= since
        if keep:
            out.append(line if line.endswith("\n") else line + "\n")
    return "".join(out)

def read_since(path, since, parse_ts):
    try:
        with open(path, "r", errors="replace") as f:
            return filter_since(f, since, parse_ts)
    except OSError:
        return ""

def ip_exclusion(cf_pattern):
    """
    grep -E alternation of addresses to leave out: Cloudflare ranges plus our own IP.
    An unset SERVER_IP must not add an empty branch ("...|"), which matches every
    line and would silently drop all nginx and UFW output.
    """
    if SERVER_IP:
        return f"{cf_pattern}|{re.escape(SERVER_IP)}"
    return cf_pattern

def nginx_access_since(since, cf_pattern):
    new_lines = read_since("/var/log/nginx/access.log", since, parse_nginx_access_ts)
    return run_cmd(f"grep -vE '\" (444|403|301|302) ' | grep -vE '{ip_exclusion(cf_pattern)}'", input=new_lines)

def collect_raw_logs(last_run):
    cf_pattern = r"173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    since = parse_last_run(last_run)

    nginx_out = nginx_access_since(since, cf_pattern)

    ssh_cmd1 = f"journalctl -u ssh --since '{last_run}' 2>/dev/null"
    now = datetime.now()
    ssh_out = run_cmd(ssh_cmd1) + "\n" + read_since("/var/log/auth.log", since, lambda line: parse_syslog_ts(line, now))

    ufw_cmd = f"journalctl -k --since '{last_run}' 2>/dev/null | grep 'UFW BLOCK' | grep -vE 'SRC=({ip_exclusion(cf_pattern)})' | tail -30"
    ufw_out = run_cmd(ufw_cmd)

    return f"=== NGINX ACCESS ===\n{nginx_out}\n=== AUTH/SSH ===\n{ssh_out}\n=== UFW ===\n{ufw_out}"

def collect_logs(last_run):
    cf_pattern = r"173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."

    date_str = run_cmd(f"date -d '{last_run}' '+%Y/%m/%d %H:%M:%S'").strip()
    nginx_err = run_cmd(f"awk -v since='{date_str}' '{{ if (substr($0,1,19) >= since) print }}' /var/log/nginx/error.log 2>/dev/null | grep -v 'signal process\\|graceful\\|reopening'")

    ssh_out = run_cmd(f"journalctl -u ssh --since '{last_run}' 2>/dev/null | grep -v 'session opened\\|session closed\\|pam_unix'")

    syslog = run_cmd(f"journalctl --since '{last_run}' -p warning 2>/dev/null | grep -v 'sudo\\|cron\\|certbot\\|systemd\\|rsyslog\\|logrotate\\|CRON\\|UFW' | tail -8")

    nginx_acc = nginx_access_since(parse_last_run(last_run), cf_pattern)

    logs = f"=== NGINX ERROR ===\n{mask_sensitive(nginx_err)}\n"
    logs += f"=== AUTH/SSH ===\n{mask_sensitive(ssh_out)}\n"
    logs += f"=== SYSLOG ===\n{mask_sensitive(syslog)}\n"
    logs += f"=== NGINX ACCESS ===\n{mask_sensitive(nginx_acc)}\n"
    return logs

def analyze_with_groq(logs):
    prompt = f"""Analyze the following server logs. Report only real threats you detect.

Output format:
🔍 ANALYSIS RESULT
Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}

- Category: [name]
  Severity: [LOW/MEDIUM/HIGH/CRITICAL]
  Description: [description]
  Action: [action]

No threats: CLEAN

LOGS:
{logs}"""

    models = [
        'moonshotai/kimi-k2-instruct',
        'llama-3.3-70b-versatile',
        'groq/compound',
        'groq/compound-mini',
        'llama-3.1-8b-instant'
    ]
    
    for attempt, model in enumerate(models, 1):
        print(f"[{datetime.now()}] Attempting model ({attempt}/{len(models)}): {model}", file=sys.stderr)
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1500,
            "temperature": 0.1
        }
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        )
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            if 'choices' in data:
                content = data['choices'][0]['message']['content'].strip()
                content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL|re.IGNORECASE).strip()
                if 'ANALYSIS RESULT' in content:
                    content = content[content.index('ANALYSIS RESULT'):]
                if not content:
                    raise Exception("EMPTY_RESPONSE")
                print(f"[{datetime.now()}] Analysis successful: {model}", file=sys.stderr)
                return content
        except Exception as e:
            wait_secs = 2 ** attempt
            print(f"[{datetime.now()}] {model} failed ({e}). Waiting {wait_secs}s...", file=sys.stderr)
            run_cmd(f"echo '[{datetime.now()}] MODEL_FAIL: {model} -> {e}' >> /var/log/soc-analyzer.log")
            time.sleep(wait_secs)
            
    print(f"[{datetime.now()}] CRITICAL: All Groq models failed!", file=sys.stderr)
    run_cmd(f"echo '[{datetime.now()}] ANALYSIS_ERROR: All models rejected' >> /var/log/soc-analyzer.log")
    return "ANALYSIS_FAILED"

def send_telegram(msg):
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    payload = json.dumps({"chat_id": chat_id, "text": msg}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except:
        pass

def main():
    os.makedirs("/var/lib/soc", exist_ok=True)
    last_run = get_last_run()
    
    raw_logs = collect_raw_logs(last_run)
    print(f"[{datetime.now()}] Rule engine running...")
    rule_res = subprocess.run(["python3", "/usr/local/bin/soc-rule-engine.py"], input=raw_logs, text=True, capture_output=True)
    rule_output = rule_res.stdout.strip()
    rule_exit = rule_res.returncode
    
    if rule_output and rule_output != "CLEAN":
        print(rule_output)
        if rule_exit >= 1:
            print(f"[{datetime.now()}] Automated ban starting...")
            ban_in = f"{rule_output}\n---RAW---\n{raw_logs}"
            subprocess.run(["python3", "/usr/local/bin/soc-auto-ban.py"], input=ban_in, text=True)
            
    print(f"[{datetime.now()}] SOC Log Analyzer started...")
    logs = collect_logs(last_run)
    log_size = len(logs)
    print(f"[{datetime.now()}] {log_size} bytes of log collected")
    
    if log_size > 15000:
        logs = logs[:15000]
        print(f"[{datetime.now()}] Log truncated to 15000 bytes")
        
    analysis = analyze_with_groq(logs)
    print(f"[{datetime.now()}] Groq analysis completed")
    print(analysis)
    
    if analysis == "ANALYSIS_FAILED":
        try:
            with open(WARN_FILE, "r") as f:
                last_warn = int(f.read().strip())
        except:
            last_warn = 0
            
        now_ts = int(time.time())
        if now_ts - last_warn > 1800:
            send_telegram(f"⚠️ SOC System Warning\n\nGroq AI log analysis failed.\nDate: {datetime.now().strftime('%d/%m/%Y %H:%M')}\nReason: All models failed.\n\n📋 Rule engine continues to run.\n🔧 Manual check may be required.")
            with open(WARN_FILE, "w") as f:
                f.write(str(now_ts))
        with open(STATE_FILE, "w") as f:
            f.write(datetime.now().isoformat())
        sys.exit(0)
        
    # Notifications
    with open("/tmp/soc_analysis.tmp", "w") as f1, open("/tmp/soc_raw.tmp", "w") as f2:
        f1.write(analysis)
        f2.write(raw_logs)
        
    subprocess.run(["python3", "/usr/local/bin/soc-notifier.py", "/tmp/soc_analysis.tmp", "/tmp/soc_raw.tmp"])
    
    # DB Save
    subprocess.run(["python3", "/usr/local/bin/soc-db-save.py", str(log_size), "1"], input=analysis, text=True)
    
    with open(STATE_FILE, "w") as f:
        f.write(datetime.now().isoformat())

if __name__ == "__main__":
    main()
