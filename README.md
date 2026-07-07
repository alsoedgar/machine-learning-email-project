# 📧 Email Assessor: Forensic-Grade Local Phishing & Link Sandboxing Dashboard

Email Assessor is a **100% private, local-first** Human-in-the-Loop (HITL) email security dashboard and CLI assistant. It parses raw email header/body strings or EML files, extracts and hashes attachments, analyzes sender metadata and routing paths (e.g. detecting geographic anomalies like SMTP relays through random locations), runs local machine learning text classification, and executes isolated Playwright link tracing to map redirect paths and capture safe webpage screenshots.

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

## 🚀 Setup & Execution

### Prerequisites
* Ensure **Python 3.10+** is installed on your computer.

### 1. Install Dependencies
Run the following commands in your terminal to set up a virtual environment and install the required dependencies:
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows)
.\.venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Install Playwright Chromium binaries
playwright install chromium
```

### 2. Run the Web Dashboard
Start the local Flask app server:
```bash
python web_app.py
```
Open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 3. Run the CLI tool
Run the colorized interactive terminal assistant:
```bash
python cli.py
```

## ℹ️ Gmail / Google Relay Geolocation Notice

Gmail strips the originating sender's actual residential IP address from email headers to protect user privacy. Consequently, the oldest SMTP relay IP recorded in the `Received` headers of a Gmail message belongs to Google's own server infrastructure (often geolocating to Palo Alto, Mountain View, or other Google datacenter locations in California).

To clarify this and prevent analyst confusion, the application:
1. **Detects Google ISP Names:** Inspects the originating ISP and flags Google-owned relay gateways.
2. **Dynamic Location Labeling:** Appends a `[Google Mail Relay]` tag to resolved locations.
3. **Forensic Info Notice:** Renders an informational banner in the **Sender Origin** tab explaining that the geolocation represents Google's datacenter relay network, rather than the physical location of the sender.

---

## 🤝 Sharing & Distributing Safely

To package this folder for teammates:
1. **Clean Dynamic Files:** Delete the following files if they have been generated:
   - `feedback_log.csv` (contains records of emails you have flagged)
   - `model_state.json` (holds your local trained vocabulary)
2. **Regeneration:** When the recipient runs the code, it will automatically train a fresh model file from the seed dataset.
