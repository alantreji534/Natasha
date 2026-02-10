import socket
import time
import json
import os
import random
import string
import threading
import hashlib
from logger import log
from config import SSH_PORT

# =========================
# Runtime control
# =========================
_running = False
_sessions = {}

# =========================
# Paths
# =========================
SESSION_DIR = "logs/sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# =========================
# Realistic system simulation
# =========================

# Random hostnames and domain suffixes
HOSTNAMES = ["server01", "prod-web-03", "db-master", "ubuntu-aws", "debian-vps"]
DOMAIN_SUFFIXES = [".local", ".lan", ".internal", ".corp", ".company.com"]

# Real user accounts with realistic UIDs
USERS = {
    "root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
    "admin": {"uid": 1000, "gid": 1000, "home": "/home/admin", "shell": "/bin/bash"},
    "ubuntu": {"uid": 1001, "gid": 1001, "home": "/home/ubuntu", "shell": "/bin/bash"},
    "www-data": {"uid": 33, "gid": 33, "home": "/var/www", "shell": "/usr/sbin/nologin"},
    "mysql": {"uid": 107, "gid": 114, "home": "/nonexistent", "shell": "/bin/false"},
    "nginx": {"uid": 101, "gid": 101, "home": "/var/cache/nginx", "shell": "/bin/false"},
}

# Realistic filesystem with timestamps and permissions
FS = {
    "/": {
        "entries": ["home", "etc", "var", "tmp", "usr", "bin", "sbin", "lib", "opt", "boot", "dev", "proc", "sys"],
        "mode": "drwxr-xr-x",
        "size": 4096,
        "mtime": "Apr 19  2023"
    },
    "/home": {
        "entries": ["admin", "ubuntu", "www-data"],
        "mode": "drwxr-xr-x",
        "size": 4096,
        "mtime": "May 12 10:34"
    },
    "/home/admin": {
        "entries": [".bashrc", ".bash_history", ".ssh", ".profile", "notes.txt", "backup.sh", "logs"],
        "mode": "drwxr-x---",
        "size": 4096,
        "mtime": "Jun 15 14:22"
    },
    "/home/ubuntu": {
        "entries": [".bashrc", ".bash_history", ".ssh"],
        "mode": "drwxr-x---",
        "size": 4096,
        "mtime": "Mar 08 09:15"
    },
    "/etc": {
        "entries": ["passwd", "shadow", "group", "hosts", "ssh", "nginx", "mysql", "crontab", "fstab", "resolv.conf"],
        "mode": "drwxr-xr-x",
        "size": 4096,
        "mtime": "Jun 20 08:45"
    },
    "/var": {
        "entries": ["log", "www", "lib", "tmp", "backups"],
        "mode": "drwxr-xr-x",
        "size": 4096,
        "mtime": "Jan 10 2023"
    },
    "/var/log": {
        "entries": ["auth.log", "syslog", "nginx", "mysql", "kernel.log", "dmesg"],
        "mode": "drwxr-xr-x",
        "size": 4096,
        "mtime": "Jun 21 11:30"
    },
    "/tmp": {
        "entries": [".X11-unix", ".ICE-unix", "systemd-private-*", "ssh-*"],
        "mode": "drwxrwxrwt",
        "size": 4096,
        "mtime": "Jun 21 12:00"
    },
    "/root": {
        "entries": [".bashrc", ".ssh", ".profile", "scripts"],
        "mode": "drwx------",
        "size": 4096,
        "mtime": "Jun 18 16:45"
    }
}

# Realistic file contents with variations
FILES = {
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
ubuntu:x:1001:1001:Ubuntu User,,,:/home/ubuntu:/bin/bash
mysql:x:107:114:MySQL Server,,,:/nonexistent:/bin/false
nginx:x:101:101:nginx user,,,:/var/cache/nginx:/bin/false
""",
    
    "/etc/shadow": """root:*:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
sys:*:19000:0:99999:7:::
sync:*:19000:0:99999:7:::
games:*:19000:0:99999:7:::
man:*:19000:0:99999:7:::
lp:*:19000:0:99999:7:::
mail:*:19000:0:99999:7:::
news:*:19000:0:99999:7:::
uucp:*:19000:0:99999:7:::
proxy:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
backup:*:19000:0:99999:7:::
list:*:19000:0:99999:7:::
irc:*:19000:0:99999:7:::
gnats:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
systemd-network:!:19000:0:99999:7:::
systemd-resolve:!:19000:0:99999:7:::
systemd-timesync:!:19000:0:99999:7:::
messagebus:!:19000:0:99999:7:::
syslog:!:19000:0:99999:7:::
_apt:!:19000:0:99999:7:::
tss:!:19000:0:99999:7:::
uuidd:!:19000:0:99999:7:::
tcpdump:!:19000:0:99999:7:::
landscape:!:19000:0:99999:7:::
pollinate:!:19000:0:99999:7:::
sshd:!:19000:0:99999:7:::
systemd-coredump:!:19000:0:99999:7:::
admin:$6$rounds=656000$v.L8cR9CJdJX6mFS$abc123...:19000:0:99999:7:::
ubuntu:$6$rounds=656000$xYZ789$def456...:19000:0:99999:7:::
mysql:!:19000:0:99999:7:::
nginx:!:19000:0:99999:7:::
""",
    
    "/home/admin/.bash_history": """cd ~
ls -la
sudo apt update
sudo apt upgrade -y
cd /var/www/html
git pull origin main
systemctl restart nginx
cat /etc/passwd
ps aux | grep nginx
netstat -tulpn
ssh-keygen -t rsa
exit
""",
    
    "/home/admin/notes.txt": """Server Maintenance Notes
========================
2023-06-15: Applied security patches for nginx and OpenSSH
2023-06-10: Database backup completed successfully
2023-06-05: Updated SSL certificates for domain
2023-06-01: Monitored suspicious login attempts from 203.0.113.45

TODO:
- Schedule monthly security audit
- Test new firewall rules
- Update monitoring scripts
- Rotate SSH keys next month

Credentials (temp):
FTP: admin / TempPass123!
MySQL: root / MySQL@2023# (change soon!)
""",
    
    "/var/log/auth.log": """Jun 21 10:15:01 server01 CRON[12345]: pam_unix(cron:session): session opened for user root by (uid=0)
Jun 21 10:15:01 server01 CRON[12345]: pam_unix(cron:session): session closed for user root
Jun 21 10:17:22 server01 sshd[23456]: Accepted password for admin from 192.168.1.100 port 54321 ssh2
Jun 21 10:17:23 server01 sshd[23456]: pam_unix(sshd:session): session opened for user admin by (uid=0)
Jun 21 10:30:45 server01 sshd[34567]: Failed password for root from 203.0.113.45 port 12345 ssh2
Jun 21 10:30:47 server01 sshd[34567]: Failed password for root from 203.0.113.45 port 12345 ssh2
Jun 21 10:30:49 server01 sshd[34567]: Failed password for root from 203.0.113.45 port 12345 ssh2
Jun 21 10:30:51 server01 sshd[34567]: Connection closed by authenticating user root 203.0.113.45 port 12345 [preauth]
Jun 21 11:05:12 server01 sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update
Jun 21 11:05:12 server01 sudo: pam_unix(sudo:session): session opened for user root by admin(uid=1000)
Jun 21 11:05:25 server01 sudo: pam_unix(sudo:session): session closed for user root
""",
    
    "/var/log/syslog": """Jun 21 09:00:01 server01 systemd[1]: Started Daily apt download activities.
Jun 21 09:00:02 server01 systemd[1]: Starting apt-daily.service - Daily apt download activities...
Jun 21 09:00:10 server01 systemd[1]: apt-daily.service: Deactivated successfully.
Jun 21 09:00:10 server01 systemd[1]: Finished apt-daily.service - Daily apt download activities.
Jun 21 09:25:01 server01 CRON[9876]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
Jun 21 10:00:01 server01 systemd[1]: Starting apt-daily-upgrade.service - Daily apt upgrade and clean activities...
Jun 21 10:00:15 server01 systemd[1]: apt-daily-upgrade.service: Deactivated successfully.
Jun 21 10:00:15 server01 systemd[1]: Finished apt-daily-upgrade.service - Daily apt upgrade and clean activities.
Jun 21 11:30:45 server01 kernel: [123456.789012] TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.
""",
}

# Realistic process lists (different for each session)
def generate_ps_output():
    base_time = time.time() - random.randint(3600, 86400)
    
    processes = [
        ("root", "1", "0.0", "0.1", "22568", "4100", "?", "Ss", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:02", "/sbin/init splash"),
        ("root", str(random.randint(100,200)), "0.0", "0.1", "7168", "3100", "?", "S", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "[kworker/u8:0]"),
        ("root", str(random.randint(201,300)), "0.0", "0.1", "0", "0", "?", "S", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "[rcu_sched]"),
        ("root", "542", "0.0", "0.2", "72284", "8120", "?", "Ss", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:01", "/usr/sbin/sshd -D"),
        ("root", str(random.randint(600,700)), "0.0", "0.2", "102384", "9120", "?", "Ss", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "/usr/sbin/rsyslogd -n"),
        ("root", str(random.randint(701,800)), "0.0", "0.1", "31200", "4100", "?", "Ss", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "/usr/sbin/cron -f"),
        ("mysql", "980", "0.2", "1.4", "345612", "60200", "?", "Sl", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", f"0:{random.randint(1,59):02d}", "/usr/sbin/mysqld"),
        ("root", "901", "0.0", "0.3", "93560", "15400", "?", "S", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", f"0:0{random.randint(1,9)}", "nginx: master process /usr/sbin/nginx -g daemon on;"),
        ("www-data", str(random.randint(902,910)), "0.0", "0.2", "94560", "9400", "?", "S", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "nginx: worker process"),
        ("www-data", str(random.randint(911,920)), "0.0", "0.2", "94560", "9400", "?", "S", f"{random.randint(1,23):02d}:{random.randint(10,59):02d}", "0:00", "nginx: worker process"),
    ]
    
    header = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    return header + "\n".join([f"{p[0]:<12}{p[1]:>5} {p[2]:>4} {p[3]:>4} {p[4]:>6} {p[5]:>5} {p[6]:<8} {p[7]:<4} {p[8]:>9} {p[9]:>7} {p[10]}" for p in processes])

def generate_top_output():
    load = random.uniform(0.1, 2.5)
    uptime = random.randint(3600, 2592000)
    days = uptime // 86400
    hours = (uptime % 86400) // 3600
    minutes = (uptime % 3600) // 60
    
    return f"""top - {random.randint(10,23):02d}:{random.randint(10,59):02d}:{random.randint(10,59):02d} up {days} days, {hours:2d}:{minutes:02d},  {random.randint(1,5)} user,  load average: {load:.2f}, {load*0.8:.2f}, {load*0.6:.2f}
Tasks:  {random.randint(80,150)} total,   {random.randint(1,3)} running, {random.randint(70,140)} sleeping,   0 stopped,   0 zombie
%Cpu(s):  {random.uniform(0.5,5.0):4.1f} us,  {random.uniform(0.1,2.0):4.1f} sy,  {random.uniform(0.0,0.5):4.1f} ni, {random.uniform(92.0,99.0):4.1f} id,  {random.uniform(0.0,0.5):4.1f} wa,  {random.uniform(0.0,0.2):4.1f} hi,  {random.uniform(0.0,0.3):4.1f} si,  {random.uniform(0.0,0.1):4.1f} st
MiB Mem :   {random.randint(2000,32000):5d} total,   {random.randint(500,8000):5d} free,   {random.randint(1000,16000):5d} used,   {random.randint(500,8000):5d} buff/cache
MiB Swap:   {random.randint(1000,16000):5d} total,   {random.randint(800,15000):5d} free,   {random.randint(200,1000):5d} used.   {random.randint(1000,8000):5d} avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
    980 mysql     20   0   345612  60200   8900 S   0.2  1.4   0:03.21 mysqld
    901 root      20   0    93560  15400   2100 S   0.1  0.3   0:00.98 nginx
    {random.randint(884,890)} admin     20   0   112340  21400   4200 S   0.1  0.5   0:00.22 bash
    {random.randint(891,900)} root      20   0   162840  12400   3100 S   0.0  0.2   0:00.15 sshd: admin [priv]
    {random.randint(1500,1600)} root      20   0    93560   5400   1200 S   0.0  0.1   0:00.03 nginx: worker process
"""

# =========================
# Realistic network commands
# =========================
def generate_ifconfig():
    return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::20c:29ff:fea1:bcd2  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:a1:bc:d2  txqueuelen 1000  (Ethernet)
        RX packets 1234567  bytes 987654321 (941.9 MiB)
        RX errors 0  dropped 12  overruns 0  frame 0
        TX packets 765432  bytes 123456789 (117.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 45678  bytes 56789012 (54.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 45678  bytes 56789012 (54.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
"""

def generate_netstat():
    return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      542/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      901/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      980/mysqld
tcp        0      0 192.168.1.23:22         203.0.113.45:54321      ESTABLISHED 2345/sshd: admin [p
tcp        0      0 192.168.1.23:443        192.168.1.100:65432     TIME_WAIT   -
tcp6       0      0 :::22                   :::*                    LISTEN      542/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      901/nginx
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
udp        0      0 192.168.1.23:123        0.0.0.0:*                           -
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     STREAM     LISTENING     12345    /var/run/mysqld/mysqld.sock
unix  2      [ ACC ]     STREAM     LISTENING     23456    /var/run/nginx.sock
unix  2      [ ACC ]     STREAM     LISTENING     34567    /run/systemd/private
"""

# =========================
# Interactive delays (makes it feel real)
# =========================
def random_delay(min_ms=50, max_ms=300):
    """Add realistic typing/processing delay"""
    delay = random.uniform(min_ms/1000.0, max_ms/1000.0)
    time.sleep(delay)

def network_delay():
    """Simulate network latency"""
    time.sleep(random.uniform(0.01, 0.05))

# ... rest of the imports and code ...

# =========================
# SSH banner variations
# =========================
SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n",
    b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n",
    b"SSH-2.0-OpenSSH_8.6p1 Ubuntu-4\r\n",
]

MOTDs = [
    "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/advantage\n\n  System information as of ",
    "Welcome to Debian GNU/Linux 11 (bullseye)\n\nLast login: ",
    "CentOS Linux 7 (Core)\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\n\n",
]

# ... rest of the code ...

# =========================
# Command completion simulation
# =========================
COMMAND_HISTORY = {
    "admin": ["ls", "cd", "pwd", "cat", "ps", "top", "netstat", "ifconfig", "whoami", "uname -a"],
    "root": ["systemctl status nginx", "journalctl -xe", "apt update", "ufw status", "fail2ban-client status"],
}

def suggest_completion(cmd, user):
    """Simulate bash completion"""
    if len(cmd) < 2:
        return None
    
    suggestions = []
    for history_cmd in COMMAND_HISTORY.get(user, []):
        if history_cmd.startswith(cmd):
            suggestions.append(history_cmd)
    
    if suggestions:
        return random.choice(suggestions)
    return None

# =========================
# Fake shell environment
# =========================
class FakeShell:
    def __init__(self, user, client_addr):
        self.user = user
        self.client_addr = client_addr
        self.cwd = USERS.get(user, USERS["admin"])["home"]
        self.hostname = random.choice(HOSTNAMES)
        self.domain = random.choice(DOMAIN_SUFFIXES)
        self.prompt_counter = 0
        self.last_command = ""
        self.command_history = []
        
    def get_prompt(self):
        self.prompt_counter += 1
        color = "01;32" if self.user == "root" else "01;34"
        return f"\033[{color}m{self.user}@{self.hostname}{self.domain}\033[0m:\033[01;34m{self.cwd}\033[0m$ "
    
    def execute(self, cmd):
        self.command_history.append(cmd)
        self.last_command = cmd
        return self._handle_command(cmd)
    
    def _handle_command(self, cmd):
        # Simulate command execution with realistic output
        parts = cmd.strip().split()
        if not parts:
            return ""
        
        command = parts[0]
        
        # Add random command not found sometimes
        if random.random() < 0.01:
            return f"bash: {command}: command not found\n"
        
        if command == "pwd":
            return f"{self.cwd}\n"
        
        elif command == "ls":
            flags = parts[1:] if len(parts) > 1 else []
            path = self.cwd
            if flags and not flags[0].startswith("-"):
                path = self._resolve_path(flags[0])
            
            if path not in FS:
                return f"ls: cannot access '{path}': No such file or directory\n"
            
            entries = FS[path]["entries"]
            mode = FS[path]["mode"]
            size = FS[path]["size"]
            mtime = FS[path]["mtime"]
            
            if "-l" in flags:
                output = f"total {size}\n"
                for entry in entries:
                    if "*" in entry:  # Skip wildcard entries in -l
                        continue
                    is_dir = "." not in entry and not entry.endswith(".txt") and not entry.endswith(".log")
                    entry_mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    entry_size = random.randint(1024, 8192) if is_dir else random.randint(100, 5000)
                    output += f"{entry_mode} 1 {self.user} {self.user} {entry_size:>6} {mtime} {entry}\n"
                return output
            else:
                return "  ".join([e for e in entries if "*" not in e]) + "\n"
        
        elif command == "cd":
            target = parts[1] if len(parts) > 1 else "~"
            new_path = self._resolve_path(target)
            if new_path in FS:
                self.cwd = new_path
                return ""
            else:
                return f"bash: cd: {target}: No such file or directory\n"
        
        elif command == "cat":
            if len(parts) < 2:
                return "cat: missing file operand\n"
            
            file_path = self._resolve_path(parts[1])
            
            # Special handling for sensitive files
            if file_path == "/etc/shadow" and self.user != "root":
                return f"cat: {file_path}: Permission denied\n"
            
            if file_path in FILES:
                # Add occasional file not found to seem real
                if random.random() < 0.005:
                    return f"cat: {file_path}: No such file or directory\n"
                return FILES[file_path]
            else:
                # Some files exist but aren't in our list
                if random.random() < 0.3:
                    return f"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nSed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n"
                return f"cat: {file_path}: No such file or directory\n"
        
        elif command == "whoami":
            return f"{self.user}\n"
        
        elif command == "uname":
            if "-a" in cmd:
                return f"Linux {self.hostname} 5.15.0-{random.randint(70,90)}-generic x86_64 GNU/Linux\n"
            return "Linux\n"
        
        elif command in ["ps", "top", "ifconfig", "netstat", "ss"]:
            # These commands are handled by the main loop
            return None
        
        elif command == "history":
            output = ""
            for i, cmd in enumerate(self.command_history[-20:], 1):
                output += f"{i:5}  {cmd}\n"
            return output
        
        elif command == "echo":
            return " ".join(parts[1:]) + "\n"
        
        elif command == "date":
            return time.strftime("%a %b %d %H:%M:%S %Z %Y\n")
        
        elif command == "w" or command == "who":
            users = ["admin", "ubuntu", "root"]
            output = f" {time.strftime('%H:%M')} up {random.randint(1,30)} days, {random.randint(1,23)}:{random.randint(10,59)},  {len(users)} users,  load average: {random.uniform(0.1, 2.5):.2f}, {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 1.5):.2f}\n"
            output += "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            for user in users:
                tty = f"pts/{random.randint(0,3)}"
                from_ip = f"{random.randint(192,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                login = f"{random.randint(8,16):02d}:{random.randint(10,59):02d}"
                idle = f"{random.randint(0,60):02d}:{random.randint(10,59)}"
                output += f"{user:<8} {tty:<8} {from_ip:<16} {login:<7} {idle:<6} 0.00s  0.00s -bash\n"
            return output
        
        elif command.startswith("sudo"):
            if self.user == "root":
                return "# Command would execute as root\n"
            else:
                return f"[sudo] password for {self.user}: \n"
        
        else:
            # 5% chance command exists but we simulate it
            if random.random() < 0.05:
                return f"{command}: command executed successfully\n"
            return f"bash: {command}: command not found\n"
    
    def _resolve_path(self, path):
        if path == "~":
            return USERS.get(self.user, USERS["admin"])["home"]
        elif path.startswith("~/"):
            user_home = USERS.get(self.user, USERS["admin"])["home"]
            return os.path.join(user_home, path[2:])
        elif not path.startswith("/"):
            return os.path.join(self.cwd, path)
        return path

# =========================
# SSH Honeypot
# =========================
def start():
    global _running
    _running = True
    
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(5)
    
    banner = random.choice(SSH_BANNERS)
    print(f"[+] SSH honeypot running on port {SSH_PORT}")
    print(f"[+] Using banner: {banner.decode().strip()}")
    
    while _running:
        try:
            client, addr = sock.accept()
            # Accept in non-blocking mode to handle stop() properly
            client.setblocking(True)
            
            # Start session in new thread
            thread = threading.Thread(target=handle_session, args=(client, addr, banner))
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            if _running:
                print(f"[-] Accept error: {e}")
            break

def handle_session(client, addr, banner):
    session_id = f"ssh-{addr[0]}-{int(time.time())}-{random.randint(1000,9999)}"
    _sessions[session_id] = {"active": True}
    
    try:
        # Send SSH banner
        network_delay()
        client.send(banner)
        
        # Authentication phase
        client.send(b"login: ")
        user_raw = client.recv(1024)
        if not user_raw:
            client.close()
            return
            
        user = user_raw.decode(errors="ignore").strip()
        network_delay()
        
        client.send(b"password: ")
        pass_raw = client.recv(1024)
        if not pass_raw:
            client.close()
            return
            
        password = pass_raw.decode(errors="ignore").strip()
        
        # Log authentication attempt
        log({
            "service": "ssh",
            "ip": addr[0],
            "user": user,
            "password": password,
            "session_id": session_id,
            "event": "auth_attempt"
        })
        
        # Accept any credentials (honeypot)
        shell = FakeShell(user if user in USERS else "admin", addr[0])
        
        # Send MOTD
        motd = random.choice(MOTDs)
        motd += time.strftime("%a %b %d %H:%M:%S %Z %Y")
        motd += "\n\n"
        
        network_delay()
        client.send(motd.encode())
        
        # Send last login info
        last_login = f"Last login: {random.choice(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'])} "
        last_login += f"{random.randint(1,30)} {random.choice(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'])} "
        last_login += f"{random.randint(10,23):02d}:{random.randint(10,59):02d}:{random.randint(10,59):02d} "
        last_login += f"from {random.randint(192,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}\n"
        
        network_delay()
        client.send(last_login.encode())
        
        # Main shell loop
        while _sessions.get(session_id, {}).get("active", True):
            try:
                # Send prompt
                prompt = shell.get_prompt()
                client.send(prompt.encode())
                
                # Receive command with timeout
                client.settimeout(5.0)
                data = client.recv(4096)
                client.settimeout(None)
                
                if not data:
                    break
                
                cmd = data.decode(errors="ignore").strip()
                
                # Skip empty commands
                if not cmd:
                    continue
                
                # Log command
                log({
                    "service": "ssh",
                    "session_id": session_id,
                    "ip": addr[0],
                    "user": user,
                    "command": cmd,
                    "cwd": shell.cwd,
                    "event": "command"
                })
                
                # Simulate typing delay
                random_delay(len(cmd) * 10, len(cmd) * 30)
                
                # Handle special commands that need custom output
                output = None
                
                if cmd.startswith("ps"):
                    output = generate_ps_output()
                elif cmd == "top":
                    output = generate_top_output()
                elif cmd == "ifconfig":
                    output = generate_ifconfig()
                elif cmd.startswith(("netstat", "ss")):
                    output = generate_netstat()
                elif cmd.startswith("sudo"):
                    # Simulate sudo password prompt
                    client.send(f"[sudo] password for {user}: ".encode())
                    try:
                        client.settimeout(2.0)
                        client.recv(1024)  # Read password (ignore it)
                        client.settimeout(None)
                    except:
                        pass
                    
                    if user == "root":
                        output = f"[sudo] password for {user}: \nSorry, try again.\n"
                    else:
                        output = f"[sudo] password for {user}: \n{user} is not in the sudoers file. This incident will be reported.\n"
                elif cmd.startswith("su"):
                    # Simulate su password prompt
                    client.send(b"Password: ")
                    try:
                        client.settimeout(2.0)
                        client.recv(1024)
                        client.settimeout(None)
                    except:
                        pass
                    output = "su: Authentication failure\n"
                elif cmd in ["exit", "logout", "quit"]:
                    client.send(b"Connection closed.\n")
                    break
                elif cmd == "clear":
                    client.send(b"\033[2J\033[H")
                    continue
                
                # If not a special command, use shell
                if output is None:
                    output = shell.execute(cmd)
                
                if output:
                    # Add occasional stderr messages
                    if random.random() < 0.02:
                        error_msg = random.choice([
                            "bash: cannot set terminal process group (-1): Inappropriate ioctl for device\n",
                            "bash: no job control in this shell\n",
                            f"bash: {random.choice(['/usr/bin/clear', '/bin/ls'])}: Input/output error\n"
                        ])
                        output += error_msg
                    
                    network_delay()
                    client.send(output.encode())
                
                # Simulate slight processing delay
                time.sleep(random.uniform(0.01, 0.1))
                
            except socket.timeout:
                # Client idle timeout
                continue
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"Session error: {e}")
                break
        
    except Exception as e:
        print(f"Session setup error: {e}")
    finally:
        client.close()
        _sessions[session_id] = {"active": False}
        log({
            "service": "ssh",
            "session_id": session_id,
            "ip": addr[0],
            "event": "session_end"
        })

def stop():
    global _running
    _running = False
    # Mark all sessions as inactive
    for session_id in _sessions:
        _sessions[session_id] = {"active": False}