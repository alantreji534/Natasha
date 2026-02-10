import threading
import os
import json

from banner import show
from honeypots import ssh_honeypot, http_honeypot, ftp_honeypot, telnet_honeypot
import analyzer

# ───────── Colors ─────────
RED = "\033[91m"
RESET = "\033[0m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"

# ───────── Service Status ─────────
SERVICE_STATUS = {
    "ssh": False,
    "http": False,
    "ftp": False,
    "telnet": False
}

LOG_FILE = "logs/events.json"

def update_service_status(service, running):
    if service in SERVICE_STATUS:
        SERVICE_STATUS[service] = running

# ───────── Main CLI ─────────
def main():
    show()

    while True:
        cmd = input(f"{RED}Natasha> {RESET}").strip().lower()

        if cmd == "help":
            print(f"""
{RED}{BOLD}
╔══════════════════════════════════════════════════════════╗
║            NATASHA COMMAND INTERFACE ({WHITE}v2.0.1{RED})            ║
╠══════════════════════════════════════════════════════════╣
║ {WHITE}SERVICE CONTROL{RED}                                          ║
║  ├─ start ssh | http | ftp | telnet                      ║
║  ├─ start all                                            ║
║  ├─ stop  ssh | http | ftp | telnet                      ║
║  └─ stop  all                                            ║
╠══════════════════════════════════════════════════════════╣
║ {WHITE}MONITORING & VISIBILITY{RED}                                  ║
║  ├─ status        → show running honeypots               ║
║  ├─ logs          → formatted attack events              ║
║  ├─ view          → alias for logs                       ║
║  └─ live          → real-time attack stream              ║
╠══════════════════════════════════════════════════════════╣
║ {WHITE}ANALYSIS & EXPORT{RED}                                        ║
║  ├─ analyze       → local telemetry summary              ║
║  └─ export        → export logs for Moonnight SIEM       ║
╠══════════════════════════════════════════════════════════╣
║ {WHITE}SYSTEM{RED}                                                   ║
║  └─ exit           → shutdown NATASHA                    ║
╚══════════════════════════════════════════════════════════╝
{RESET}
""")

        elif cmd == "start ssh":
            threading.Thread(target=ssh_honeypot.start, daemon=True).start()
            update_service_status("ssh", True)

        elif cmd == "start http":
            threading.Thread(target=http_honeypot.start, daemon=True).start()
            update_service_status("http", True)

        elif cmd == "start ftp":
            threading.Thread(target=ftp_honeypot.start, daemon=True).start()
            update_service_status("ftp", True)

        elif cmd == "start telnet":
            threading.Thread(target=telnet_honeypot.start, daemon=True).start()
            update_service_status("telnet", True)

        elif cmd == "start all":
            for hp, svc in zip(
                [ssh_honeypot, http_honeypot, ftp_honeypot, telnet_honeypot],
                ["ssh", "http", "ftp", "telnet"]
            ):
                threading.Thread(target=hp.start, daemon=True).start()
                update_service_status(svc, True)

        elif cmd == "stop all":
            ssh_honeypot.stop()
            http_honeypot.stop()
            ftp_honeypot.stop()
            telnet_honeypot.stop()
            for svc in SERVICE_STATUS:
                update_service_status(svc, False)
            print("All honeypots stopped")

        elif cmd == "status":
            print(f"\n{RED}╔════════════ SERVICE STATUS ════════════╗{RESET}")
            for svc, state in SERVICE_STATUS.items():
                icon = "🟢" if state else "🔴"
                print(f" {icon} {svc.upper():7} : {'RUNNING' if state else 'STOPPED'}")
            print(f"{RED}╚════════════════════════════════════════╝{RESET}\n")

        elif cmd in ("logs", "view"):
            if not os.path.exists(LOG_FILE):
                print("[-] No logs found")
                continue

            print("\n📡 ATTACK TELEMETRY\n")
            with open(LOG_FILE) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                        service = e.get("service", "unknown").upper()
                        ip = e.get("ip", "N/A")

                        if "password" in e:
                            print(f"🔐 [{service}] {ip} → credential attempt")
                        elif e.get("event") == "command":
                            print(f"⌨️  [{service}] {ip} → {e.get('command')}")
                        else:
                            print(f"📄 [{service}] {ip} → activity")
                    except:
                        continue

        elif cmd == "live":
            analyzer.live()

        elif cmd == "analyze":
            analyzer.analyze()

        elif cmd == "export":
            analyzer.export()

        elif cmd == "exit":
            print("Exiting NATASHA")
            break

        elif cmd == "":
            continue

        else:
            print("Unknown command. Type 'help'.")

# ───────── Entry Point ─────────
if __name__ == "__main__":
    main()
