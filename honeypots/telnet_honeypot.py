import socket, time, json, os
from logger import log
from config import TELNET_PORT

_running = False
SESSION_DIR = "logs/telnet_sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

def start():
    global _running
    _running = True

    s = socket.socket()
    s.bind(("0.0.0.0", TELNET_PORT))
    s.listen(50)
    print("[+] Telnet honeypot running on port", TELNET_PORT)

    while _running:
        try:
            client, addr = s.accept()
        except:
            continue

        try:
            client.send(b"login: ")
            user = client.recv(1024).decode(errors="ignore").strip()

            client.send(b"password: ")
            pwd = client.recv(1024).decode(errors="ignore").strip()

            log({
                "service": "telnet",
                "ip": addr[0],
                "username": user,
                "password": pwd
            })

            session_id = f"telnet-{addr[0]}-{int(time.time())}"
            start_time = time.time()
            last_cmd = start_time

            session = {
                "session_id": session_id,
                "service": "telnet",
                "ip": addr[0],
                "username": user,
                "events": [],
                "timing": [],
                "actor_type": "UNKNOWN"
            }

            client.send(b"\nBusyBox v1.31.1 (built-in shell)\n# ")

            while True:
                try:
                    data = client.recv(1024)
                    if not data:
                        break
                except:
                    break

                cmd = data.decode(errors="ignore").strip()
                now = time.time()
                delta = round(now - last_cmd, 2)
                last_cmd = now

                intent = "command_exec"
                if cmd in ["ps", "ifconfig", "ip"]:
                    intent = "recon"
                elif cmd.startswith("wget"):
                    intent = "payload_fetch"

                session["timing"].append(delta)
                session["events"].append({
                    "time": round(now - start_time, 2),
                    "command": cmd,
                    "delta": delta,
                    "intent": intent
                })

                if cmd in ["exit", "logout"]:
                    break
                elif cmd == "ps":
                    client.send(b"PID USER CMD\n1 root init\n22 root telnetd\n")
                elif cmd == "ifconfig":
                    client.send(b"eth0 inet 192.168.0.10\n")
                else:
                    client.send(b"sh: command not found\n")

                client.send(b"# ")

            # ---- classify bot vs human ----
            if session["timing"]:
                avg = sum(session["timing"]) / len(session["timing"])
                session["actor_type"] = "BOT" if avg < 0.4 else "HUMAN"

            with open(f"{SESSION_DIR}/{session_id}.json", "w") as f:
                json.dump(session, f, indent=2)

            client.close()

        except:
            try:
                client.close()
            except:
                pass

def stop():
    global _running
    _running = False
