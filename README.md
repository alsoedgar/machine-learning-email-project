# 📧 Email Assessor: Forensic-Grade Local Phishing & Link Sandboxing Dashboard

Email Assessor is a **100% private, local-first** Human-in-the-Loop (HITL) email security dashboard and CLI assistant. It parses raw email header/body strings or EML files, extracts and hashes attachments, analyzes sender metadata and routing paths (e.g. detecting geographic anomalies like SMTP relays through random locations), runs local machine learning text classification, and executes isolated Playwright link tracing to map redirect paths and capture safe webpage screenshots.

---

# Preview images:

# Preview Images

<img src="https://github.com/user-attachments/assets/4d739cd3-8285-4b44-8e97-72cf4ff623da" width="85%" alt="Dashboard Overview" />

<img src="https://github.com/user-attachments/assets/8773d602-707c-4a9b-98cf-779d735c01a8" width="85%" alt="Dark Mode Analysis" />

<img src="https://github.com/user-attachments/assets/20ca0efd-8c60-445c-b569-66dc9538ad5c" width="45%" alt="Forensics Pane" />

<img src="https://github.com/user-attachments/assets/4b7abd69-217a-4e61-9415-34c4fd20d624" width="45%" alt="Sandbox View" />

<img src="https://github.com/user-attachments/assets/5c97493c-d836-44d8-bfb8-9f5f1b420b3d" width="75%" alt="Log Analytics" />

<img src="https://github.com/user-attachments/assets/1ccac1f1-c193-4f23-a26b-1fbde57e6300" width="60%" alt="Extracted Indicators" />

<img src="https://github.com/user-attachments/assets/29220243-e3c3-4ffa-9ae7-91f874d511f6" width="50%" alt="Feedback Log" />

---

## 🔒 Strict Privacy & Local-First Architecture

Unlike cloud-based security products, Email Assessor is designed with privacy and local security as its core principles:

1. **Zero External API Dependencies:** The application does not use external cloud LLMs (like OpenAI or Anthropic) or remote scanning APIs. All parsing, text classification, and heuristic assessments run completely in-memory on your CPU.
2. **Localhost Binding:** The Flask web server binds strictly to the loopback interface (`127.0.0.1:5000`). This ensures that only you, on your local machine, can access your analysis dashboard. It is inaccessible from your LAN or Wi-Fi network.
3. **Private Local Datasets:** All logged training discrepancies, whitelist entries, and temporary files remain inside the local project folder. No telemetry is gathered or transmitted.

---

## 🛡️ Hardened Browser Sandbox (Link Tracing & Live Sandbox Security)

To inspect links safely, the application launches a headless Chromium instance using **Playwright**. To ensure that visiting malicious links cannot compromise your host machine, local network, or browser, we enforce strict security configurations across both static tracing and the **Live Interactive Sandbox**:

* **1. Intranet & DNS Rebinding Protection (SSRF Prevention):** The backend resolves any target domain to its IP address via DNS *before* launching the browser or executing navigations. If the host resolves to a private network, loopback, or local subnet (`127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`), the request is immediately rejected. This prevents a malicious link from executing Server-Side Request Forgery (SSRF) or DNS rebinding to probe local network services.
* **2. Execution Process Isolation:** Chromium runs as an unprivileged, headless background process. It does not share cookies, session tokens, login history, cache, or credentials with your default web browser.
* **3. Zero Client-Side Script Execution (Base64 Proxy Delivery):** When you interact with a page in **Live Mode**, the target website's scripts and code *never* reach your browser. Your mouse clicks are translated into coordinates, sent to the server as API requests, and executed by Playwright. The server returns a clean base64-encoded PNG screenshot of the updated state. No malicious payloads, drive-by downloads, or scripts can execute on your local device.
* **4. Stripped Device & Sensor Permissions:** All active device integrations are completely disabled:
  * Camera, Microphone, and Midi Access: Blocked.
  * Geolocation, Push Notifications, and Clipboard: Blocked.
* **5. Escape & Popup Prevention:** Chromium launches with `--block-new-web-contents` enabled, which automatically catches and kills any script attempts to spawn popups, new tabs, prompt dialogs, or frame escapes.
* **6. Volatile Session Lifecycles:** When you close the sandbox modal, the backend kills the Playwright instance, instantly destroying the browser context, session memory, local storage, and volatile cache.

---

## 📂 Project Directory Structure & Key Elements

Here is what each component of the project does:

```
├── web_app.py               # Flask server hosting the local web dashboard and API endpoints
├── cli.py                   # Command-line interface for analyzing emails directly in the terminal
├── analyzer.py              # Core EmailAnalyzer orchestrating parsing, heuristics, ML predictions, and Playwright tracing
├── test_analyzer.py         # Unit testing suite validating parser safety, hashing, and classifiers
├── requirements.txt         # List of Python dependencies (Flask, Playwright, BeautifulSoup, etc.)
│
├── utils/
│   ├── parser.py            # EmailParser: decodes MIME payloads, subject, body text/HTML, and attachment content
│   ├── heuristics.py        # HeuristicsAnalyzer: detects display name mismatches, suspicious TLDs, and defangs URLs
│   └── features.py          # EmailFeatureExtractor: checks for brand spoofing and offline IP routing anomalies
│
├── models/
│   ├── classifier.py        # NaiveBayesClassifier: pure-Python bag-of-words and bigrams text classifier
│   └── ensemble.py          # HybridPhishingClassifier: fuses Naive Bayes text results with metadata & header features
│
├── static/
│   ├── dashboard.js         # Frontend controller managing tabs, background link tracing, rendering, and modal views
│   └── dashboard.css        # Styles for dark mode, visual threat rings, preview thumbnails, and lightboxes
│
├── templates/
│   └── dashboard.html       # Web dashboard markup, including annotated viewers, trace chains, and lightbox modals
│
└── data/
    ├── seed_dataset.json    # Pre-merged dataset containing labeled emails (Safe, Spam, Malicious)
    ├── ceas08_sample.csv    # Bundled CEAS_08 sample dataset
    ├── kuladeep_sample.csv  # Bundled Synthetic phishing dataset
    └── DATASETS.md          # Comprehensive instructions for downloading larger datasets (e.g., from Kaggle/HuggingFace)
```

---

## 🚀 How to Use Email Assessor

There are **three ways** to use this tool depending on your needs:

---

### ⚡ Option 1: Download the Pre-Built Executable (Easiest — No Python Required)

If you just want to use the app without installing anything:

1. Go to the [**Releases**](../../releases) page of this repository.
2. Download **`EmailAssessor.exe`** (Windows) from the latest release.
3. Double-click `EmailAssessor.exe` — the app will start automatically and open your browser to the dashboard.

> **Note:** On first launch Windows may show a SmartScreen warning since the app is unsigned. Click **"More info" → "Run anyway"** to proceed. The app runs entirely locally and makes no external connections.

---

### 🌐 Option 2: Run the Web Dashboard from Source Code

If you want to run the full web app with all features from the source:

#### Prerequisites
- **Python 3.10+** must be installed on your computer.

```powershell
# 1. Clone or download this repository, then open a terminal in the project folder

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate        # Windows
# source .venv/bin/activate     # Mac / Linux

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Install Playwright's Chromium browser (required for link tracing)
playwright install chromium

# 5. Launch the dashboard
python web_app.py
```

Your browser will automatically open to 👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### 💻 Option 3: Use the Command-Line Interface (CLI)

If you prefer a terminal-based workflow, the CLI provides the same full analysis without a browser:

```powershell
# Analyze by pasting/typing email content interactively:
python cli.py

# Analyze a saved .eml file directly:
python cli.py -f "path/to/your/email.eml"
```

The CLI outputs a color-coded security report with verdict, indicators, defanged links, and origin IP routing.

---

## ℹ️ Gmail / Google Relay Geolocation Notice

Gmail strips the originating sender's actual residential IP address from email headers to protect user privacy. Consequently, the oldest SMTP relay IP recorded in the `Received` headers of a Gmail message belongs to Google's own server infrastructure (often geolocating to Palo Alto, Mountain View, or other Google datacenter locations in California).

To clarify this and prevent analyst confusion, the application:
1. **Detects Google ISP Names:** Inspects the originating ISP and flags Google-owned relay gateways.
2. **Dynamic Location Labeling:** Appends a `[Google Mail Relay]` tag to resolved locations.
3. **Forensic Info Notice:** Renders an informational banner in the **Sender Origin** tab explaining that the geolocation represents Google's datacenter relay network, rather than the physical location of the sender.

---

## 🏗️ Building the Executable Yourself

If you want to compile your own `EmailAssessor.exe` from source:

```powershell
# Install PyInstaller
pip install pyinstaller

# Build the single-file executable
pyinstaller --noconfirm --onefile --windowed `
  --add-data "templates;templates" `
  --add-data "static;static" `
  --add-data "data;data" `
  --icon="static/icon.ico" `
  --name="EmailAssessor" `
  web_app.py
```

The compiled executable will appear in the `dist/` folder.

---

## 🤝 Sharing & Distributing Safely

To package this folder for teammates:
1. **Clean Dynamic Files:** Delete the following files if they have been generated:
   - `feedback_log.csv` (contains records of emails you have flagged)
   - `model_state.json` (holds your local trained vocabulary)
2. **Regeneration:** When the recipient runs the code, it will automatically train a fresh model file from the seed dataset.
