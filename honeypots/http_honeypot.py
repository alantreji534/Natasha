from http.server import BaseHTTPRequestHandler, HTTPServer
import time, json, os, urllib.parse, random, threading, socket
from logger import log
from config import HTTP_PORT
import ssl  # For HTTPS simulation

SESSION_DIR = "logs/http_sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# =========================
# Realistic company configurations
# =========================
COMPANIES = [
    {
        "name": "Acme Corporation",
        "domain": "acme-corp.com",
        "theme_color": "#2E5BFF",
        "logo": "acme_logo.png",
        "favicon": "favicon.ico",
        "welcome_message": "Secure Employee Portal - Access internal tools and resources",
        "forgot_password_url": "https://helpdesk.acme-corp.com/reset",
        "it_support": "IT Support: 1-800-555-0199",
        "copyright": "© 2024 Acme Corporation. All rights reserved."
    },
    {
        "name": "Global Tech Solutions",
        "domain": "globaltech.com",
        "theme_color": "#00A86B",
        "logo": "globaltech_logo.png",
        "favicon": "favicon.ico",
        "welcome_message": "Global Tech Solutions - Internal Management System",
        "forgot_password_url": "https://support.globaltech.com/password",
        "it_support": "Contact IT: support@globaltech.com",
        "copyright": "© 2024 Global Tech Solutions"
    },
    {
        "name": "Synergy Systems",
        "domain": "synergysys.local",
        "theme_color": "#FF6B35",
        "logo": "synergy_logo.png",
        "favicon": "favicon.ico",
        "welcome_message": "Synergy Systems - Project Management Dashboard",
        "forgot_password_url": "mailto:it-help@synergysys.local",
        "it_support": "Internal: Ext. 5555",
        "copyright": "Synergy Systems Internal Use Only"
    }
]

# Real employee names for error messages
EMPLOYEE_NAMES = [
    "John Smith", "Maria Garcia", "Robert Chen", "Sarah Johnson",
    "David Williams", "Lisa Brown", "Michael Davis", "Jennifer Miller",
    "James Wilson", "Patricia Moore", "Richard Taylor", "Linda Anderson",
    "Charles Thomas", "Barbara Jackson", "Thomas White", "Susan Harris"
]

# Common passwords to log as "previously used" in fake history
COMMON_PASSWORDS = [
    "Summer2024!", "Winter2023#", "Password123", "Welcome123",
    "Admin@2024", "P@ssw0rd", "Qwerty123!", "Company@2023",
    "SecurePass1", "TempPass2024"
]

# Fake employee database (for realistic behavior)
FAKE_EMPLOYEES = {
    "jsmith": {"name": "John Smith", "department": "Engineering", "last_login": "2024-01-15 09:32"},
    "mgarcia": {"name": "Maria Garcia", "department": "Marketing", "last_login": "2024-01-14 14:22"},
    "rchen": {"name": "Robert Chen", "department": "Finance", "last_login": "2024-01-13 11:45"},
    "sjohnson": {"name": "Sarah Johnson", "department": "HR", "last_login": "2024-01-12 16:30"},
    "administrator": {"name": "System Admin", "department": "IT", "last_login": "2024-01-15 08:15"},
    "admin": {"name": "Administrator", "department": "IT", "last_login": "2024-01-14 10:20"},
    "root": {"name": "Root User", "department": "System", "last_login": "2024-01-13 12:00"},
}

# =========================
# Realistic error messages
# =========================
ERROR_MESSAGES = [
    "Invalid username or password. Please try again.",
    "Your account has been temporarily locked due to multiple failed login attempts.",
    "The password you entered is incorrect. Please check your caps lock key.",
    "This account is currently disabled. Please contact IT support.",
    "Your password has expired. Please reset it using the link below.",
    "Multi-factor authentication required. Please check your mobile device.",
    "Your session has timed out. Please log in again.",
    "Access denied from your current location. Please use VPN.",
    "Too many failed attempts. Try again in 15 minutes.",
    "Account not found. Please check your username and try again."
]

# =========================
# Tracking and rate limiting
# =========================
failed_attempts = {}
sessions = {}
last_request_time = {}

# =========================
# Enhanced HTTP Handler
# =========================
class RealisticLoginPortal(BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        self.company = random.choice(COMPANIES)
        self.session_id = None
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Suppress default server logs"""
        pass
    
    def _rate_limit_check(self, ip):
        """Simulate rate limiting"""
        now = time.time()
        if ip in last_request_time:
            elapsed = now - last_request_time[ip]
            if elapsed < 0.5:  # 500ms minimum between requests
                time.sleep(0.5)
        last_request_time[ip] = now
        
        # Track failed attempts
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        
        return failed_attempts[ip] < 5  # Allow up to 5 failed attempts
    
    def _create_session(self):
        """Create a realistic session ID"""
        return f"SESS-{random.randint(100000, 999999)}-{random.randint(1000, 9999)}-{int(time.time())}"
    
    def _generate_csrf_token(self):
        """Generate a fake CSRF token"""
        import hashlib
        return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[:32]
    
    def _get_user_agent_info(self, user_agent):
        """Extract info from User-Agent header"""
        info = {
            "browser": "Unknown",
            "os": "Unknown",
            "device": "Desktop"
        }
        
        ua = user_agent.lower()
        if "chrome" in ua:
            info["browser"] = "Chrome"
        elif "firefox" in ua:
            info["browser"] = "Firefox"
        elif "safari" in ua and "chrome" not in ua:
            info["browser"] = "Safari"
        elif "edge" in ua:
            info["browser"] = "Edge"
        
        if "windows" in ua:
            info["os"] = "Windows"
        elif "mac" in ua:
            info["os"] = "macOS"
        elif "linux" in ua:
            info["os"] = "Linux"
        elif "android" in ua:
            info["os"] = "Android"
            info["device"] = "Mobile"
        elif "iphone" in ua or "ipad" in ua:
            info["os"] = "iOS"
            info["device"] = "Mobile"
        
        return info
    
    def _send_login_page(self, error=None, username="", show_captcha=False):
        """Send realistic login page"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        
        # Set session cookie
        if not self.session_id:
            self.session_id = self._create_session()
        self.send_header("Set-Cookie", f"session_id={self.session_id}; HttpOnly; SameSite=Strict")
        
        self.end_headers()
        
        csrf_token = self._generate_csrf_token()
        captcha_html = ""
        
        if show_captcha:
            captcha_html = """
            <div class="captcha">
                <h4>Security Verification</h4>
                <img src="/captcha.png" alt="CAPTCHA" style="border: 1px solid #ddd; padding: 5px;">
                <input type="text" name="captcha" placeholder="Enter characters above" required>
            </div>
            """
        
        error_html = f'<div class="alert alert-danger">{error}</div>' if error else ""
        
        # Randomly show "previous password" field for some users
        show_prev_password = random.random() < 0.3
        
        prev_password_field = ""
        if show_prev_password:
            prev_password_field = f"""
            <div class="form-group">
                <label for="prev_password">Previous Password (if changed recently):</label>
                <input type="password" class="form-control" id="prev_password" name="prev_password" placeholder="Optional">
            </div>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{self.company['name']} - Employee Portal</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0;
                    padding: 20px;
                }}
                .login-container {{
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    width: 100%;
                    max-width: 440px;
                    overflow: hidden;
                }}
                .login-header {{
                    background: {self.company['theme_color']};
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .login-header h1 {{
                    margin: 0;
                    font-size: 24px;
                    font-weight: 600;
                }}
                .login-header p {{
                    margin: 10px 0 0;
                    opacity: 0.9;
                    font-size: 14px;
                }}
                .login-body {{
                    padding: 40px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                .form-group label {{
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: #333;
                }}
                .form-control {{
                    width: 100%;
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    font-size: 14px;
                    transition: border-color 0.3s;
                }}
                .form-control:focus {{
                    outline: none;
                    border-color: {self.company['theme_color']};
                    box-shadow: 0 0 0 3px rgba({int(self.company['theme_color'][1:3], 16)}, {int(self.company['theme_color'][3:5], 16)}, {int(self.company['theme_color'][5:7], 16)}, 0.1);
                }}
                .btn-login {{
                    background: {self.company['theme_color']};
                    color: white;
                    border: none;
                    padding: 14px;
                    width: 100%;
                    border-radius: 6px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: background 0.3s;
                }}
                .btn-login:hover {{
                    background: {self.company['theme_color']}dd;
                }}
                .alert {{
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                    font-size: 14px;
                }}
                .alert-danger {{
                    background: #fee;
                    border: 1px solid #fcc;
                    color: #c00;
                }}
                .login-footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    text-align: center;
                    font-size: 12px;
                    color: #666;
                }}
                .login-footer a {{
                    color: {self.company['theme_color']};
                    text-decoration: none;
                }}
                .login-footer a:hover {{
                    text-decoration: underline;
                }}
                .security-notice {{
                    background: #f8f9fa;
                    border-left: 4px solid {self.company['theme_color']};
                    padding: 12px;
                    margin-bottom: 20px;
                    font-size: 12px;
                    color: #666;
                }}
                .captcha {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                }}
                .two-factor {{
                    background: #f0fff4;
                    border: 1px solid #c6f6d5;
                    padding: 15px;
                    border-radius: 6px;
                    margin-bottom: 20px;
                }}
                .two-factor h4 {{
                    margin-top: 0;
                    color: #22543d;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="login-header">
                    <h1><i class="fas fa-shield-alt"></i> {self.company['name']}</h1>
                    <p>{self.company['welcome_message']}</p>
                </div>
                
                <div class="login-body">
                    {error_html}
                    
                    <div class="security-notice">
                        <i class="fas fa-info-circle"></i> For security reasons, please log in with your corporate credentials.
                    </div>
                    
                    <form method="POST" action="/">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        
                        <div class="form-group">
                            <label for="username"><i class="fas fa-user"></i> Username</label>
                            <input type="text" class="form-control" id="username" name="username" 
                                   value="{username}" placeholder="employee.id@{self.company['domain']}" required autofocus>
                        </div>
                        
                        <div class="form-group">
                            <label for="password"><i class="fas fa-lock"></i> Password</label>
                            <input type="password" class="form-control" id="password" name="password" 
                                   placeholder="••••••••" required>
                        </div>
                        
                        {prev_password_field}
                        
                        {captcha_html}
                        
                        <div class="form-group">
                            <div class="form-check">
                                <input type="checkbox" class="form-check-input" id="remember" name="remember">
                                <label class="form-check-label" for="remember">Remember this device</label>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn-login">
                            <i class="fas fa-sign-in-alt"></i> Sign In
                        </button>
                    </form>
                    
                    <div class="login-footer">
                        <p>
                            <a href="{self.company['forgot_password_url']}"><i class="fas fa-key"></i> Forgot Password?</a> | 
                            <a href="/help"><i class="fas fa-question-circle"></i> Need Help?</a>
                        </p>
                        <p>{self.company['it_support']}</p>
                        <p>{self.company['copyright']}</p>
                        <p style="font-size: 10px; opacity: 0.6;">
                            v4.2.1 • Last updated: Jan 15, 2024 • {random.randint(100, 999)} active sessions
                        </p>
                    </div>
                </div>
            </div>
            
            <script>
                // Simulate loading delay
                setTimeout(() => {{
                    document.querySelector('.btn-login').disabled = false;
                }}, {random.randint(100, 500)});
                
                // Detect password managers
                if (window.navigator.credentials) {{
                    console.log('Password manager API available');
                }}
                
                // Add subtle animations
                document.addEventListener('DOMContentLoaded', function() {{
                    const form = document.querySelector('form');
                    form.style.opacity = '0';
                    form.style.transform = 'translateY(20px)';
                    setTimeout(() => {{
                        form.style.transition = 'opacity 0.3s, transform 0.3s';
                        form.style.opacity = '1';
                        form.style.transform = 'translateY(0)';
                    }}, 100);
                }});
            </script>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode('utf-8'))
    
    def _send_two_factor_page(self, username, method="sms"):
        """Send 2FA verification page"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        phone_number = f"+1 ({random.randint(200, 999)}) {random.randint(100, 999)}-{random.randint(1000, 9999)}"
        email = f"{username}@{self.company['domain']}"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Two-Factor Authentication</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 40px; max-width: 500px; margin: 0 auto; }}
            .container {{ background: #f8f9fa; padding: 30px; border-radius: 10px; }}
            .code {{ font-size: 32px; letter-spacing: 5px; text-align: center; margin: 20px 0; }}
        </style>
        </head>
        <body>
            <div class="container">
                <h2><i class="fas fa-mobile-alt"></i> Two-Factor Authentication Required</h2>
                <p>For added security, please enter the verification code sent to:</p>
                <div class="two-factor">
                    <h4>{'Your phone ' + phone_number if method == 'sms' else 'Your email ' + email}</h4>
                    <input type="text" class="form-control code" placeholder="000000" maxlength="6">
                    <p style="font-size: 12px; color: #666;">Code expires in 5 minutes</p>
                </div>
                <button class="btn-login">Verify</button>
                <p><a href="/">← Back to login</a></p>
            </div>
        </body>
        </html>
        """
        
        self.wfile.write(html.encode('utf-8'))
    
    def _send_dashboard(self, username):
        """Send fake dashboard after "successful" login"""
        self.send_response(302)
        self.send_header("Location", "/dashboard")
        self.end_headers()
    
    def _log_attack(self, data, status="failed"):
        """Log attack details comprehensively"""
        ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "")
        referer = self.headers.get("Referer", "")
        
        ua_info = self._get_user_agent_info(user_agent)
        
        session_data = {
            "service": "http",
            "status": status,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ip": ip,
            "user_agent": user_agent,
            "browser": ua_info["browser"],
            "os": ua_info["os"],
            "device": ua_info["device"],
            "referer": referer,
            "headers": dict(self.headers),
            "data": data,
            "company": self.company["name"],
            "session_id": self.session_id,
            "path": self.path
        }
        
        log(session_data)
        
        # Save to session file
        sid = f"http-{ip}-{int(time.time())}-{random.randint(1000, 9999)}"
        with open(f"{SESSION_DIR}/{sid}.json", "w") as f:
            json.dump(session_data, f, indent=2)
    
    def _simulate_processing_delay(self):
        """Simulate server processing time"""
        delay = random.uniform(0.1, 1.5)
        time.sleep(delay)
    
    def do_GET(self):
        """Handle GET requests"""
        ip = self.client_address[0]
        
        if not self._rate_limit_check(ip):
            self.send_response(429)  # Too Many Requests
            self.end_headers()
            self.wfile.write(b"Too many requests. Please try again later.")
            return
        
        self._simulate_processing_delay()
        
        if self.path == "/":
            self._send_login_page()
        elif self.path == "/dashboard":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/captcha.png":
            self.send_response(404)
            self.end_headers()
        elif self.path == "/help":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            help_html = f"""
            <html><body>
            <h2>Help & Support</h2>
            <p>For login assistance, contact IT support at: {self.company["it_support"]}</p>
            <p><a href="/">← Back to login</a></p>
            </body></html>
            """
            self.wfile.write(help_html.encode('utf-8'))
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"""User-agent: *
Disallow: /admin/
Disallow: /config/
Disallow: /backup/
Allow: /
""")
        elif self.path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
        else:
            # 404 page for unknown routes
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_404 = """
            <html><body>
            <h2>404 - Page Not Found</h2>
            <p>The requested URL was not found on this server.</p>
            <p><a href="/">← Back to login</a></p>
            </body></html>
            """
            self.wfile.write(html_404.encode('utf-8'))
    
    def do_POST(self):
        """Handle POST requests (login attempts)"""
        ip = self.client_address[0]
        
        if not self._rate_limit_check(ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Too many requests. Please try again later.")
            return
        
        self._simulate_processing_delay()
        
        # Parse form data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = urllib.parse.parse_qs(post_data)
        
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        prev_password = data.get("prev_password", [""])[0]
        csrf_token = data.get("csrf_token", [""])[0]
        
        # Log the attempt with rich metadata
        attack_data = {
            "username": username,
            "password": password,
            "prev_password": prev_password if prev_password else None,
            "csrf_token": csrf_token,
            "has_csrf": bool(csrf_token),
            "content_type": self.headers.get("Content-Type", ""),
            "cookies": self.headers.get("Cookie", "")
        }
        
        # Simulate different failure modes
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        
        # Occasionally require 2FA for "admin" accounts
        if username.lower() in ["admin", "administrator", "root"] and random.random() < 0.4:
            self._log_attack(attack_data, "2fa_triggered")
            self._send_two_factor_page(username)
            return
        
        # Occasionally accept credentials to make it seem real
        if random.random() < 0.05:  # 5% chance of "success"
            self._log_attack(attack_data, "accepted_fake")
            self._send_dashboard(username)
            
            # Reset failed attempts on "success"
            if ip in failed_attempts:
                failed_attempts[ip] = 0
            return
        
        # Main failure handling
        self._log_attack(attack_data, "failed")
        
        # Choose error message based on attempt count
        if failed_attempts[ip] >= 3:
            error_msg = random.choice([
                "Multiple failed attempts. Your account has been temporarily locked.",
                "Too many failed login attempts. Please try again in 15 minutes.",
                "Security lock activated. Contact IT support to unlock your account."
            ])
            show_captcha = True
        elif username.lower() in FAKE_EMPLOYEES:
            employee = FAKE_EMPLOYEES[username.lower()]
            error_msg = f"Invalid password for {employee['name']} ({employee['department']}). Last login: {employee['last_login']}"
            show_captcha = False
        else:
            error_msg = random.choice(ERROR_MESSAGES)
            show_captcha = random.random() < 0.3
        
        # Send error page
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        error_page = f"""
        <html>
        <head><title>Login Failed</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 40px; text-align: center; }}
            .error {{ color: #dc3545; background: #f8d7da; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        </style>
        </head>
        <body>
            <h2>Login Failed</h2>
            <div class="error">
                <strong>Error:</strong> {error_msg}
            </div>
            <p>Attempts from your IP: {failed_attempts[ip]}/5</p>
            <p><a href="/">← Try again</a></p>
            <p style="font-size: 12px; color: #666;">
                If you continue to experience issues, contact {self.company['it_support']}
            </p>
        </body>
        </html>
        """
        
        self.wfile.write(error_page.encode('utf-8'))

def start():
    """Start the HTTP honeypot"""
    print(f"[+] Starting HTTP honeypot on port {HTTP_PORT}")
    print(f"[+] Serving realistic corporate login portals")
    
    server = HTTPServer(("0.0.0.0", HTTP_PORT), RealisticLoginPortal)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] HTTP honeypot stopped")
    except Exception as e:
        print(f"[-] HTTP honeypot error: {e}")

def stop():
    """Stop the HTTP honeypot"""
    # This is a simplified stop function
    # In production, you'd need proper thread control
    pass