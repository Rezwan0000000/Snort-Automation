import time
import re
import subprocess
import requests
from collections import defaultdict
from tabulate import tabulate
import os

# === Config ===
ALERT_FILE = "/var/log/snort/alert"
SUSPICIOUS_THRESHOLD = 5
check_interval = 2
LOG_FILE = "blocked_ips.log"

# === Telegram Bot Credentials ===
BOT_TOKEN = "your_bot_token_here"
CHAT_ID = "your_chat_id_here"

seen_lines = set()
ip_counts = defaultdict(int)
already_blocked = set()

def send_telegram(ip, count):
    try:
        msg = f"🚨 *Suspicious IP Blocked!*\n\n*IP:* `{ip}`\n*Alerts:* {count}\n*Action:* 🔒 Blocked"
        payload = {
            'chat_id': CHAT_ID,
            'text': msg,
            'parse_mode': 'Markdown'
        }
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        response = requests.post(url, data=payload)

        if response.status_code == 200:
            print(f"[+] Telegram alert sent for IP: {ip}")
        else:
            print(f"[!] Telegram error {response.status_code}: {response.text}")

    except Exception as e:
        print(f"[!] Failed to send Telegram alert for {ip}: {e}")

def log_blocked_ip(ip, count):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{ip},{count},Blocked\n")

def tail_alerts():
    print("[*] Watching Snort alerts in real-time (Telegram enabled)...\n")
    while True:
        try:
            with open(ALERT_FILE, 'r') as f:
                lines = f.readlines()

            new_lines = [line for line in lines if line not in seen_lines]

            for line in new_lines:
                seen_lines.add(line)
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s*->', line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] += 1

                    if ip_counts[ip] >= SUSPICIOUS_THRESHOLD and ip not in already_blocked:
                        subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                        already_blocked.add(ip)
                        send_telegram(ip, ip_counts[ip])
                        log_blocked_ip(ip, ip_counts[ip])
                        print_table()

        except FileNotFoundError:
            print(f"[!] File not found: {ALERT_FILE}")
        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(check_interval)

def print_table():
    os.system('clear')
    table = []
    for ip, count in ip_counts.items():
        status = "Blocked" if ip in already_blocked else "Pending"
        table.append([ip, count, status])
    print(tabulate(table, headers=["IP Address", "Alert Count", "Status"], tablefmt="grid"))

if __name__ == "__main__":
    tail_alerts()
