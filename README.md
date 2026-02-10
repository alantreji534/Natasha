
# Natasha
NATASHA is a high-interaction honeypot framework built for SOC engineers. It simulates realistic SSH, HTTP, FTP, and Telnet services, captures live attacker behavior, provides real-time CLI visibility, and exports clean telemetry for Moonnight(coustom SIEM tool )
=======
# 🕷️ NATASHA
### The Black Widow of Cyber Security

NATASHA is a high-interaction honeypot framework designed for SOC engineers and blue teams.  
It simulates realistic network services, captures live attacker behavior, and exports clean telemetry for SIEM platforms like **Moonnight**.

---

## 🚀 Features

- High-interaction **SSH, HTTP, FTP, Telnet** honeypots  
- Realistic service banners and behaviors  
- Live CLI attack stream (`live` command)  
- Structured JSON telemetry (`events.json`)  
- SOC-friendly command interface  
- Designed as a **sensor**, not a SIEM  

---

## 🧠 Architecture

Attacker
↓
[NATASHA Honeypots]
↓
logs/events.json
↓
Moonnight SIEM (correlation & intelligence) 


NATASHA focuses on **collection and deception**.  
Correlation, narratives, and ML analysis belong to **Moonnight**.

---

## ⚙️ Installation

```bash
git clone https://github.com/alantreji534/Natasha
cd natasha
chmod +x setup.sh
./setup.sh
source natasha-venv/bin/activate

▶️ Usage

python natasha.py


start all        Start all honeypots
status           Show service status
live             Real-time attack feed
logs / view      View formatted events
analyze          Local telemetry summary
export           Prepare logs for Moonnight
exit             Shutdown NATASHA


📡 Live Attack Stream

🔐 [SSH   ] 45.83.12.9   → Credential attempt
⌨️ [SSH   ] 45.83.12.9   → Command: ls
🔐 [HTTP  ] 91.204.18.7  → Login attempt


🔐 Ethics & Disclaimer

NATASHA is intended only for defensive security, research, and education.
Do not deploy on networks you do not own or have permission to monitor.

🧩 Part of the Moonnight Ecosystem

NATASHA is designed to integrate with Moonnight SIEM, where:

session reconstruction

attacker narratives

threat scoring

ML correlation

are performed.

🕸️ License

MIT License



    MIT License

Copyright (c) 2026 Alan T. Reji

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

