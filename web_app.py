import os
import sys
import json
import csv
import time
import re
from functools import wraps
from collections import defaultdict

from flask import Flask, request, redirect, url_for, abort, make_response, render_template, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.utils import secure_filename  # <-- Add this import

# Corrected module import from 'EmailAnalyzersrc' to 'EmailAnalyzer'
from analyzer import EmailAnalyzer

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

template_dir = resource_path('templates')
static_dir = resource_path('static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-here')

# Initialize Flask-WTF CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Define the upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize the Email Analyzer
analyzer = EmailAnalyzer()

# Fix: Initialize global request counts to resolve "request_counts is not defined"
request_counts = defaultdict(int)
rate_limits = defaultdict(list)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Add strict security headers to all Flask responses
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Rate limiting decorator
def rate_limit(func):
    @wraps(func)
    def wrapped_func(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()
        
        # Sliding window tracking (10 requests per minute limit)
        rate_limits[client_ip] = [t for t in rate_limits[client_ip] if now - t < 60]
        if len(rate_limits[client_ip]) >= 10:
            abort(429)  # Too Many Requests
            
        rate_limits[client_ip].append(now)
        return func(*args, **kwargs)
    return wrapped_func

# ---------------------------------------------------------------------------
# View Routes
# ---------------------------------------------------------------------------

@app.route('/')
@app.route('/index.html')
def index():
    """Renders the dashboard.html template securely from the templates directory"""
    return render_template('dashboard.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Input validation/sanitization
    if not username or not password:
        return 'Missing username or password', 400

    username = re.sub(r'[^a-zA-Z0-9_]', '', username)

    # Process login
    user = User(username)
    login_user(user)
    return 'Login successful', 200

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    return 'Protected content', 200

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200
    else:
        return 'Invalid file type', 400

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'eml'}

# ---------------------------------------------------------------------------
# API Routes (CSRF exempted to allow standard fetch requests)
# ---------------------------------------------------------------------------

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("20 per minute")
@csrf.exempt
def api_analyze():
    try:
        data = request.get_json(force=True)
        email_content = data.get('email_content', '')
        
        # Validate input size (prevent DoS)
        if len(email_content) > 10 * 1024 * 1024:  # 10MB limit
            return jsonify({'error': 'Input size exceeds limit'}), 400
            
        # Sanitize input
        email_content = email_content.replace('\x00', '')
        email_content = ''.join(c for c in email_content if c.isprintable() or c in '\n\t\r')
        
        result = analyzer.analyze_email(email_content)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/history', methods=['GET'])
def api_history():
    logs = []
    if os.path.exists(analyzer.feedback_csv_path):
        try:
            with open(analyzer.feedback_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    links_raw = row.get('defanged_links', '[]')
                    atts_raw = row.get('attachments', '[]')
                    try:
                        defanged_links = json.loads(links_raw)
                    except Exception:
                        defanged_links = []
                    try:
                        attachments = json.loads(atts_raw)
                    except Exception:
                        attachments = []

                    logs.append({
                        'timestamp': row.get('timestamp', ''),
                        'subject': row.get('subject', ''),
                        'from': row.get('from', ''),
                        'body_text': row.get('body_text', '').replace(' [NEWLINE] ', '\n'),
                        'model_prediction': row.get('model_prediction', ''),
                        'human_verdict': row.get('human_verdict', ''),
                        'defanged_links': defanged_links,
                        'attachments': attachments
                    })
        except Exception:
            pass
    
    logs.reverse()
    return jsonify(logs[:30])

@app.route('/api/clear_history', methods=['POST'])
@csrf.exempt
def api_clear_history():
    if os.path.exists(analyzer.feedback_csv_path):
        try:
            os.remove(analyzer.feedback_csv_path)
        except Exception:
            pass
    if os.path.exists(analyzer.model_path):
        try:
            os.remove(analyzer.model_path)
        except Exception:
            pass
    analyzer.__init__()
    return jsonify({'status': 'success'})

@app.route('/api/delete_log', methods=['POST'])
@csrf.exempt
def api_delete_log():
    try:
        data = request.get_json(force=True)
        timestamp_to_delete = data.get('timestamp', '')
        rows_to_keep = []
        headers = []
        if os.path.exists(analyzer.feedback_csv_path):
            with open(analyzer.feedback_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                headers = next(reader, [])
                for row in reader:
                    if row and row[0] != timestamp_to_delete:
                        rows_to_keep.append(row)
                        
            with open(analyzer.feedback_csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if headers:
                    writer.writerow(headers)
                writer.writerows(rows_to_keep)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/feedback', methods=['POST'])
@csrf.exempt
def api_feedback():
    try:
        data = request.get_json(force=True)
        metadata = data.get('metadata', {})
        prediction = data.get('prediction', '')
        confidence = data.get('confidence', 0.0)
        verdict = data.get('verdict', '')
        
        logged = False
        retrained = False
        
        if not metadata and not prediction:
            retrained = analyzer.retrain_model()
        else:
            if verdict != prediction:
                logged = analyzer.log_feedback(metadata, prediction, confidence, verdict)
                if logged:
                    retrained = analyzer.retrain_model()
        
        return jsonify({
            'status': 'success',
            'logged': logged,
            'retrained': retrained
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/whitelist', methods=['GET'])
def api_whitelist():
    return jsonify(list(analyzer.whitelisted_domains))

@app.route('/api/whitelist/add', methods=['POST'])
@csrf.exempt
def api_whitelist_add():
    try:
        data = request.get_json(force=True)
        domain = data.get('domain', '')
        success = analyzer.add_to_whitelist(domain)
        return jsonify({'status': 'success' if success else 'failed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/whitelist/delete', methods=['POST'])
@csrf.exempt
def api_whitelist_delete():
    try:
        data = request.get_json(force=True)
        domain = data.get('domain', '')
        success = analyzer.remove_from_whitelist(domain)
        return jsonify({'status': 'success' if success else 'failed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/screenshot', methods=['POST'])
@csrf.exempt
def api_screenshot():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        result = analyzer.take_screenshot(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/analyze-link', methods=['POST'])
@csrf.exempt
def api_analyze_link():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'URL parameter is missing'}), 400
        result = analyzer.trace_link_redirects(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ---------------------------------------------------------------------------
# Playwright Sandbox Action Routes
# ---------------------------------------------------------------------------

@app.route('/api/sandbox/start', methods=['POST'])
@csrf.exempt
def api_sandbox_start():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        result = analyzer.start_sandbox(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/click', methods=['POST'])
@csrf.exempt
def api_sandbox_click():
    try:
        data = request.get_json(force=True)
        x_pct = float(data.get('x_pct', 0))
        y_pct = float(data.get('y_pct', 0))
        result = analyzer.click_sandbox(x_pct, y_pct)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/type', methods=['POST'])
@csrf.exempt
def api_sandbox_type():
    try:
        data = request.get_json(force=True)
        text = data.get('text', '')
        result = analyzer.type_sandbox(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/key', methods=['POST'])
@csrf.exempt
def api_sandbox_key():
    try:
        data = request.get_json(force=True)
        key = data.get('key', '')
        result = analyzer.key_sandbox(key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/navigate', methods=['POST'])
@csrf.exempt
def api_sandbox_navigate():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        result = analyzer.navigate_sandbox(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/stop', methods=['POST'])
@csrf.exempt
def api_sandbox_stop():
    try:
        result = analyzer.stop_sandbox()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sandbox/scroll', methods=['POST'])
@csrf.exempt
def api_sandbox_scroll():
    try:
        data = request.get_json(force=True)
        direction = data.get('direction', 'down')
        result = analyzer.scroll_sandbox(direction)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/shutdown', methods=['POST'])
@csrf.exempt
def api_shutdown():
    # Releases and closes persistent playwrites
    try:
        analyzer.stop_sandbox()
    except Exception:
        pass
    
    # Gracefully shut down the python process
    print("[*] Dashboard tab closed. Shutting down Email Assessor process...")
    # Delay termination slightly to allow response dispatch
    def terminate():
        time.sleep(0.5)
        os._exit(0)
    
    Timer(0.1, terminate).start()
    return jsonify({'status': 'shutting_down'})

# ---------------------------------------------------------------------------
# Execution Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    from threading import Timer, Thread
    import subprocess
    import tempfile
    import glob
    
    # PyInstaller environment path fix for Playwright
    # Force Playwright to search for browsers in the user's local AppData folder instead of the temporary extraction dir
    if getattr(sys, 'frozen', False):
        user_profile = os.environ.get('USERPROFILE') or os.environ.get('HOME') or ''
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = os.path.join(user_profile, 'AppData', 'Local', 'ms-playwright')

    def _find_chromium_executable():
        """
        Locate the Playwright-managed Chromium binary by scanning the ms-playwright directory.
        This avoids using sync_playwright() which has side effects and threading issues.
        Returns the path to chrome.exe or None.
        """
        pw_dir = os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '')
        if not pw_dir:
            user_profile = os.environ.get('USERPROFILE') or os.environ.get('HOME') or ''
            pw_dir = os.path.join(user_profile, 'AppData', 'Local', 'ms-playwright')
        
        if not os.path.isdir(pw_dir):
            return None
        
        # Playwright stores Chromium as: ms-playwright/chromium-<version>/chrome-win/chrome.exe
        patterns = [
            os.path.join(pw_dir, 'chromium-*', 'chrome-win', 'chrome.exe'),
            os.path.join(pw_dir, 'chromium-*', 'chrome-linux', 'chrome'),
            os.path.join(pw_dir, 'chromium-*', 'chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'),
        ]
        for pattern in patterns:
            matches = glob.glob(pattern)
            if matches:
                # Use the newest version (last alphabetically)
                matches.sort()
                return matches[-1]
        return None

    # Auto-installation routine: verify if Chromium binary is installed, otherwise download it
    def check_and_install_playwright():
        # First check if the binary already exists on disk (fast, no side effects)
        chromium_path = _find_chromium_executable()
        if chromium_path and os.path.exists(chromium_path):
            print(f"[*] Playwright Chromium engine verified at: {chromium_path}")
            return
        
        print("[!] Playwright Chromium driver not found. Starting automatic installation...")
        try:
            # Find the playwright CLI module bundled inside the EXE or virtualenv
            # CRITICAL: Do NOT use sys.executable in frozen apps — it points to EmailAssessor.exe
            # which would re-launch the entire app in an infinite loop.
            import playwright
            pw_package_dir = os.path.dirname(playwright.__file__)
            pw_cli = os.path.join(pw_package_dir, '__main__.py')
            
            if getattr(sys, 'frozen', False):
                # In frozen mode, use the playwright CLI script directly with the bundled Python
                # Since we can't call python directly from a frozen exe, use the playwright driver
                pw_driver_dir = os.path.join(pw_package_dir, 'driver')
                # Look for the playwright driver executable
                driver_patterns = [
                    os.path.join(pw_driver_dir, 'package', 'cli.js'),
                    os.path.join(pw_driver_dir, 'node.exe'),
                ]
                node_exe = os.path.join(pw_driver_dir, 'node.exe')
                cli_js = os.path.join(pw_driver_dir, 'package', 'cli.js')
                
                if os.path.exists(node_exe) and os.path.exists(cli_js):
                    subprocess.run([node_exe, cli_js, 'install', 'chromium'], check=True, timeout=120)
                    print("[*] Playwright Chromium engine installed successfully!")
                else:
                    print(f"[x] Playwright driver not found in bundled package. Run 'playwright install chromium' manually.")
            else:
                # Non-frozen (development) mode: safe to use sys.executable
                subprocess.run([sys.executable, '-m', 'playwright', 'install', 'chromium'], check=True, timeout=120)
                print("[*] Playwright Chromium engine installed successfully!")
        except Exception as e:
            print(f"[x] Auto-install failed: {e}")
            print("[x] Please run 'playwright install chromium' manually for sandbox features.")

    # Run check in a background thread to prevent delaying server startup
    Thread(target=check_and_install_playwright, daemon=True).start()

    def open_browser():
        """
        Open the Email Assessor dashboard in its own isolated Chromium window.
        This deliberately bypasses the OS default browser (Brave, Edge, Firefox, etc.)
        so the app always runs inside its own controlled Chromium environment.
        
        NEVER calls webbrowser.open() — if Chromium isn't available, it simply
        prints the URL to the terminal and lets the user open it themselves.
        """
        chromium_path = _find_chromium_executable()
        
        if chromium_path and os.path.exists(chromium_path):
            try:
                # Create an isolated temporary user-data-dir so the embedded Chromium:
                # 1. Never shares profile data with the user's Edge/Chrome/Brave
                # 2. Won't try to restore old sessions (prevents infinite tab spawning)
                # 3. Won't show "set as default browser" prompts
                user_data_dir = os.path.join(tempfile.gettempdir(), 'email_assessor_chromium_profile')
                os.makedirs(user_data_dir, exist_ok=True)
                
                subprocess.Popen([
                    chromium_path,
                    f'--app=http://127.0.0.1:5000',
                    f'--user-data-dir={user_data_dir}',
                    '--window-size=1280,900',
                    '--disable-extensions',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-background-networking',
                    '--disable-sync',
                    '--disable-session-crashed-bubble',
                    '--disable-infobars',
                    '--disable-features=TranslateUI',
                ])
                print("[*] Opened Email Assessor in its own isolated Chromium window.")
                return
            except Exception as e:
                print(f"[!] Could not launch embedded Chromium window: {e}")
        
        # NO fallback to webbrowser.open() — that would open Edge/Brave/Firefox
        # which breaks the self-contained app experience.
        print("")
        print("  ================================================================")
        print("  [!] Chromium browser not yet installed.")
        print("  [!] Please open this URL manually in any browser:")
        print("  [!]   http://127.0.0.1:5000")
        print("  [!]")
        print("  [!] Chromium is being installed in the background.")
        print("  [!] Restart the app after installation completes.")
        print("  ================================================================")
        print("")

    print(f"================================================================")
    print(f"[*] Email Assessor running securely via Flask at http://127.0.0.1:5000")
    print(f"[*] Opening in a dedicated Chromium window (not your default browser).")
    print(f"[*] Close the app window or press Ctrl+C in this terminal to exit.")
    print(f"================================================================")
    
    Timer(1.5, open_browser).start()
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=False)