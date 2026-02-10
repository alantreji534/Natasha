import socket, time, json, os
from logger import log
from config import FTP_PORT

_running = False
SESSION_DIR = "logs/ftp_sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

def start():
    global _running
    _running = True

    s = socket.socket()
    s.bind(("0.0.0.0", FTP_PORT))
    s.listen(50)
    print("[+] FTP honeypot running on port", FTP_PORT)

    while _running:
        try:
            client, addr = s.accept()
        except:
            continue

        try:
            client.send(b"220 FTP Server Ready\r\n")

            session_id = f"ftp-{addr[0]}-{int(time.time())}"
            start_time = time.time()
            last_cmd = start_time

            session = {
                "session_id": session_id,
                "service": "ftp",
                "ip": addr[0],
                "events": [],
                "timing": [],
                "actor_type": "UNKNOWN"
            }

            while True:
                data = client.recv(1024)
                if not data:
                    break

                cmd = data.decode(errors="ignore").strip()
                now = time.time()
                delta = round(now - last_cmd, 2)
                last_cmd = now

                session["timing"].append(delta)

                intent = "command_exec"
                if cmd.startswith("USER"):
                    intent = "auth"
                elif cmd.startswith("PASS"):
                    intent = "auth"
                elif cmd.startswith("RETR"):
                    intent = "payload_download"
                elif cmd.startswith("STOR"):
                    intent = "payload_upload"

                session["events"].append({
                    "time": round(now - start_time, 2),
                    "command": cmd,
                    "delta": delta,
                    "intent": intent
                })

                if cmd.startswith("USER"):
                    user = cmd.split(" ", 1)[1] if " " in cmd else ""
                    log({"service": "ftp", "ip": addr[0], "username": user})
                    client.send(b"331 Username OK, need password\r\n")

                elif cmd.startswith("PASS"):
                    pwd = cmd.split(" ", 1)[1] if " " in cmd else ""
                    log({"service": "ftp", "ip": addr[0], "password": pwd})
                    client.send(b"530 Login incorrect\r\n")

                elif cmd.startswith("QUIT"):
                    client.send(b"221 Goodbye\r\n")
                    break

                else:
                    client.send(b"500 Command not supported\r\n")

            if session["timing"]:
                avg = sum(session["timing"]) / len(session["timing"])
                session["actor_type"] = "BOT" if avg < 0.3 else "HUMAN"

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
