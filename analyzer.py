import json
import os
from collections import Counter, defaultdict
from datetime import datetime

from config import LOG_FILE

import time
import json
import os

def live():
    if not os.path.exists(LOG_FILE):
        print("[-] No logs found")
        return

    print("\n📡 NATASHA LIVE ATTACK STREAM")
    print("Press Ctrl+C to exit")
    print("────────────────────────────────────────")

    try:
        with open(LOG_FILE, "r") as f:
            # Move to end of file (tail -f behavior)
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                try:
                    e = json.loads(line)

                    service = e.get("service", "unknown").upper()
                    ip = e.get("ip", "N/A")

                    if "password" in e:
                        msg = "Credential attempt"
                        icon = "🔐"
                    elif e.get("event") == "command":
                        msg = f"Command: {e.get('command')}"
                        icon = "⌨️"
                    else:
                        msg = "Activity detected"
                        icon = "📄"

                    print(f"{icon} [{service:<6}] {ip:<15} → {msg}")

                except json.JSONDecodeError:
                    continue

    except KeyboardInterrupt:
        print("\n[✓] Live view closed\n")



# ──────────────────── View Logs ────────────────────
def view():
    if not os.path.exists(LOG_FILE):
        print("[-] No logs found")
        return

    with open(LOG_FILE, "r") as f:
        print(f.read())

# ──────────────────── Analyze Logs ────────────────────
def analyze():
    if not os.path.exists(LOG_FILE):
        print("[-] No logs to analyze")
        return

    with open(LOG_FILE, "r") as f:
        events = [json.loads(line) for line in f if line.strip()]

    if not events:
        print("[-] No events recorded")
        return

    print("\n[*] NATASHA Local Analysis (Telemetry Summary)\n")

    service_count = Counter()
    ip_count = Counter()
    credential_hits = 0
    command_hits = 0

    for e in events:
        service_count[e.get("service")] += 1
        ip_count[e.get("ip")] += 1

        if "password" in e:
            credential_hits += 1

        if e.get("event") == "command":
            command_hits += 1

    print("[+] Events by service:")
    for svc, cnt in service_count.items():
        print(f"    {svc.upper():7} : {cnt}")

    print("\n[+] Top source IPs:")
    for ip, cnt in ip_count.most_common(5):
        print(f"    {ip:15} : {cnt} events")

    print("\n[+] Indicators:")
    print(f"    Credential submissions : {credential_hits}")
    print(f"    Commands executed      : {command_hits}")

    print("\n[✓] Local analysis complete")
    print("    (Deep correlation handled by Moonnight)\n")

# ──────────────────── Export ────────────────────
def export():
    if not os.path.exists(LOG_FILE):
        print("[-] No logs to export")
        return

    print("[✓] Telemetry export ready")
    print(f"    File   : {LOG_FILE}")
    print("    Format : JSON (line-delimited)")
    print("    Target : Moonnight SIEM\n")
