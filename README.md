# 📧 Email Assessor: Forensic-Grade Local Phishing & Link Sandboxing Dashboard

Email Assessor is a **100% private, local-first** Human-in-the-Loop (HITL) email security dashboard and CLI assistant. It parses raw email header/body strings or EML files, extracts and hashes attachments, analyzes sender metadata and routing paths (e.g. detecting geographic anomalies like SMTP relays through random locations), runs local machine learning text classification, and executes isolated Playwright link tracing to map redirect paths and capture safe webpage screenshots.

---

# Preview images (Using fake information):

### 🖥️ Core Dashboard Layouts
| Light Mode Dashboard | Dark Mode Analytics |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/4d739cd3-8285-4b44-8e97-72cf4ff623da" width="100%" /> | <img src="https://github.com/user-attachments/assets/8773d602-707c-4a9b-98cf-779d735c01a8" width="100%" /> |

### 🔍 Deep Dive & Sandbox Views
| Forensics & Cross-Log Alerts | Email Sandbox Viewer |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/20ca0efd-8c60-445c-b569-66dc9538ad5c" width="80%" /> | <img src="https://github.com/user-attachments/assets/4b7abd69-217a-4e61-9415-34c4fd20d624" width="80%" /> |

### 📊 Logs & Indicators
| Feature / Log Breakdowns |
| :---: |
| <img src="https://github.com/user-attachments/assets/5c97493c-d836-44d8-bfb8-9f5f1b420b3d" width="70%" /> |
| <img src="https://github.com/user-attachments/assets/1ccac1f1-c193-4f23-a26b-1fbde57e6300" width="70%" /> |
| <img src="https://github.com/user-attachments/assets/29220243-e3c3-4ffa-9ae7-91f874d511f6" width="70%" /> |

---

## 🔒 Strict Privacy & Local-First Architecture

Unlike cloud-based security products, Email Assessor is designed with privacy and local security as its core principles:

1. **Zero External API Dependencies:** The application does not use external cloud LLMs (like OpenAI or Anthropic) or remote scanning APIs. All parsing, text classification, and heuristic assessments run completely in-memory on your CPU.
2. **Localhost Binding:** The Flask web server binds strictly to the loopback interface (`127.0.0.1:5000`). This ensures that only you, on your local machine, can access your analysis dashboard. It is inaccessible from your LAN or Wi-Fi network.
3. **Private Local Datasets:** All logged training discrepancies, whitelist entries, and temporary files remain inside the local project folder. No telemetry is gathered or transmitted.

---

## 🛡️ Hardened Browser Sandbox (Link Tracing & Live Sandbox Security)

To inspect links safely, the application launches a headless Chromium instance using **Playwright**. To ensure that visiting malicious links cannot compromise your host machine, local network, or browser, we enforce strict security configurations across both static tracing and the **Live Interactive Sandbox**:

* **1. Intranet & DNS Rebinding Protection (SSRF Prevention):** The backend resolves any target domain to its IP address via DNS *before* launching the browser or executing navigations. If the host resolves to a private network, loopback, or local subnet (`127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`), the request is immediately rejected. Additionally, **every sub-resource request** (fetch, XHR, WebSocket, image, iframe) is intercepted via Playwright's `page.route('**/*')` and validated against the same IP blocklist at runtime, preventing multi-step DNS rebinding attacks that bypass pre-flight checks.
* **2. Docker Gateway & WSL2 Bypass Blockers:** To prevent malicious scripts from exploiting host-only bridge networks (such as Docker WSL2 instances on Windows), the analyzer explicitly blocks traffic targeting Docker internal host interfaces (`host.docker.internal`, `gateway.docker.internal`, and `host.wsl`), as well as Docker gateway IP ranges (`172.16.0.0/12`).
* **3. Execution Process Isolation & Active Sandboxing:** Chromium runs with the native browser sandbox fully enabled (do NOT run with `--no-sandbox` flags). It does not share cookies, session tokens, login history, cache, or credentials with your default web browser.
* **4. Resource & Memory Caps (DoS Mitigation):** Chromium launch configurations are restricted with strict memory controls (`--js-flags="--max-old-space-size=512"`). This caps the browser's JavaScript engine heap at **512MB RAM**, preventing crash-loops, Canvas leaks, or infinite resource leaks from locking up your host operating system.
* **5. Zero Client-Side Script Execution (Base64 Proxy Delivery):** When you interact with a page in **Live Mode**, the target website's scripts and code *never* reach your browser. Your mouse clicks are translated into coordinates, sent to the server as API requests, and executed by Playwright. The server returns a clean base64-encoded PNG screenshot of the updated state. No malicious payloads, drive-by downloads, or scripts can execute on your local device.
* **6. Stripped Device & Sensor Permissions:** All active device integrations are completely disabled:
  * Camera, Microphone, and Midi Access: Blocked.
  * Geolocation, Push Notifications, and Clipboard: Blocked.
* **7. Escape & Popup Prevention:** Chromium launches with `--block-new-web-contents` and `--mute-audio` enabled, which automatically catches and kills any script attempts to spawn popups, new tabs, prompt dialogs, audio alerts, or frame escapes. The dashboard HTML also includes a `<base target="_self">` tag and overrides `window.open()` to prevent any accidental external browser tab opens.
* **8. Volatile Session Lifecycles:** When you close the sandbox modal, the backend kills the Playwright instance, instantly destroying the browser context, session memory, local storage, and volatile cache.
* **9. Browser Anti-Fingerprinting Stealth:** All Playwright browser contexts are configured with a realistic desktop User-Agent string, standard locales (`en-US`), timezone overrides, and runtime script injection that removes `navigator.webdriver` and defines `window.chrome` — making it significantly harder for Cloudflare, reCAPTCHA, and other bot-detection systems to block analysis.
* **10. Isolated Chromium App Window:** The dashboard opens in Playwright's own embedded Chromium binary with a dedicated `--user-data-dir`, not your default browser (Edge, Brave, Firefox, etc.). This prevents profile contamination, session restore loops, and ensures no browser extensions can interfere with analysis.

---

## 🐋 Docker Deployment (Recommended for Maximum Security)

> [!IMPORTANT]
> **For the strongest security posture, we strongly recommend running Email Assessor inside Docker.** Docker provides OS-level process isolation that protects your host machine even if a Chromium zero-day exploit is triggered by a malicious link. The standalone EXE runs Playwright directly on your host OS — Docker adds an entire container boundary between the malicious content and your files.

### Why Docker is More Secure

| Protection Layer | Standalone EXE | Docker Container |
|:---|:---:|:---:|
| Chromium browser sandbox | ✅ | ✅ |
| SSRF / DNS rebinding blockers | ✅ | ✅ |
| Resource memory caps | ✅ | ✅ |
| OS-level process isolation | ❌ | ✅ |
| Read-only filesystem | ❌ | ✅ |
| Linux capability drops | ❌ | ✅ |
| Network egress filtering | App-level | App-level + Docker bridge |
| Disposable environment | ❌ | ✅ |
| Privilege escalation prevention | ❌ | ✅ |

### Prerequisites

1. Install [**Docker Desktop**](https://www.docker.com/products/docker-desktop/) for your operating system.
2. Ensure Docker Desktop is running before proceeding.

### Quick Start (One Command)

```powershell
# Clone the repository and launch
git clone https://github.com/alsoedgar/machine-learning-email-project.git
cd machine-learning-email-project
docker compose up --build -d
```

The first build will:
- Install all Python dependencies
- Download and install the Playwright Chromium browser (~140MB)
- Pre-train the ML classifier from the seed dataset
- Set up the non-root user and filesystem permissions

Once built, the dashboard is available at: 👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### Docker Security Hardening Details

The included `docker-compose.yml` enforces the following security controls:

| Control | Configuration | Purpose |
|:---|:---|:---|
| **Non-root user** | `UID 10001`, no login shell | Prevents container-escape exploits from writing to host OS files |
| **Read-only filesystem** | `read_only: true` | Malware cannot persist on the container disk |
| **tmpfs mounts** | `/tmp` and `/run` (noexec, nosuid) | Writable scratch space with no execute permission |
| **Capability drops** | `cap_drop: ALL`, `cap_add: SYS_ADMIN` | Drops all Linux capabilities except the minimum for Chromium |
| **No privilege escalation** | `no-new-privileges: true` | Blocks setuid binaries from elevating permissions |
| **CPU/Memory limits** | 2 CPUs, 2GB RAM max | Prevents crash-loops from freezing your host OS |
| **Internal network** | `internal: true` on bridge | **Blocks all outbound internet access** from the container |
| **Loopback-only ports** | `127.0.0.1:5000:5000` | Dashboard is inaccessible from your LAN/Wi-Fi |
| **Log rotation** | 10MB max, 3 files | Prevents disk exhaustion from verbose output |
| **Health checks** | Every 30s via curl | Auto-detects and restarts crashed instances |

### Container Management Commands

```powershell
# Start the container (first time or after changes)
docker compose up --build -d

# View live logs
docker compose logs -f email-assessor

# Stop the container
docker compose down

# Full reset — destroy all data, volumes, and cached state
docker compose down --volumes --rmi all
docker compose up --build -d
```

> [!TIP]
> Periodically reset the container to a clean slate to destroy any persistent artifacts. Run:
> ```powershell
> docker compose down --volumes && docker compose up -d --build
> ```

---

## 📂 Project Directory Structure & Key Elements

Here is what each component of the project does:

```
├── web_app.py               # Flask server hosting the local web dashboard and API endpoints
├── cli.py                   # Command-line interface for analyzing emails directly in the terminal
├── analyzer.py              # Core EmailAnalyzer orchestrating parsing, heuristics, ML predictions, and Playwright tracing
├── test_analyzer.py         # Unit testing suite validating parser safety, hashing, and classifiers
├── requirements.txt         # List of Python dependencies (Flask, Playwright, BeautifulSoup, etc.)
├── Dockerfile               # Multi-stage production Docker image with Chromium pre-installed
├── docker-compose.yml       # Hardened container orchestration with security controls
├── .dockerignore            # Excludes build artifacts and dev files from Docker context
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

There are **four ways** to use this tool depending on your needs:

---

### 🐋 Option 1: Docker Container (Recommended — Most Secure)

The safest way to run Email Assessor, especially if you'll be analyzing real phishing emails and following suspicious links.

#### Prerequisites
- [**Docker Desktop**](https://www.docker.com/products/docker-desktop/) installed and running.

```powershell
# 1. Clone the repository
git clone https://github.com/alsoedgar/machine-learning-email-project.git
cd machine-learning-email-project

# 2. Build and launch (everything installs automatically on first run)
docker compose up --build -d

# 3. Open your browser to:
#    http://127.0.0.1:5000
```

> **First build takes 2–5 minutes** (downloading Chromium + dependencies). Subsequent starts are instant.

---

### ⚡ Option 2: Download the Pre-Built Executable (Easiest — No Python Required)

If you just want to use the app without installing anything:

* **Windows:**
  1. Go to the [**Releases**](../../releases) page of this repository.
  2. Download **`EmailAssessor.exe`** (Windows) from the latest release.
  3. Double-click `EmailAssessor.exe` — the app will start automatically and open in its own dedicated Chromium window.
  
  > **Note:** On first launch Windows may show a SmartScreen warning since the app is unsigned. Click **"More info" → "Run anyway"** to proceed.

* **macOS:**
  * The prebuilt `.exe` is a Windows binary and will not run natively on macOS. 
  * Mac users should use **Option 1 (Docker)** or **Option 3 (Source)**. Alternatively, you can follow the instructions in the [Building the Executable Yourself](#-building-the-executable-yourself) section below to compile a native Mac `EmailAssessor.app` bundle in seconds.

---

### 🌐 Option 3: Run the Web Dashboard from Source Code

If you want to run the full web app with all features from the source:

#### Prerequisites
- **Python 3.10+** must be installed on your computer.

* **Windows (PowerShell):**
  ```powershell
  # 1. Clone/download the repo and open terminal in the project folder
  # 2. Create and activate a virtual environment
  python -m venv .venv
  .\.venv\Scripts\activate
  # 3. Install requirements
  pip install -r requirements.txt
  # 4. Install Playwright browser
  playwright install chromium
  # 5. Start the server
  python web_app.py
  ```

* **macOS / Linux (Bash/Zsh):**
  ```bash
  # 1. Clone/download the repo and open terminal in the project folder
  # 2. Create and activate a virtual environment
  python3 -m venv .venv
  source .venv/bin/activate
  # 3. Install requirements
  pip install -r requirements.txt
  # 4. Install Playwright browser
  playwright install chromium
  # 5. Start the server
  python3 web_app.py
  ```

The app will automatically open in its own Chromium window at 👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### 💻 Option 4: Use the Command-Line Interface (CLI)

If you prefer a terminal-based workflow, the CLI provides the same full analysis without a browser:

* **Windows:**
  ```powershell
  python cli.py -f "path/to/your/email.eml"
  ```
* **macOS / Linux:**
  ```bash
  python3 cli.py -f "path/to/your/email.eml"
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

If you want to compile your own standalone application from source:

* **Windows:**
  ```powershell
  pip install pyinstaller
  pyinstaller --noconfirm --onefile --windowed `
    --add-data "templates;templates" `
    --add-data "static;static" `
    --add-data "data;data" `
    --icon="static/icon.ico" `
    --name="EmailAssessor" `
    web_app.py
  ```
  The output will be `dist/EmailAssessor.exe`.

* **macOS:**
  ```bash
  pip install pyinstaller
  # Note the colon (:) separator instead of semicolon (;) for macOS data paths
  pyinstaller --noconfirm --onefile --windowed \
    --add-data "templates:templates" \
    --add-data "static:static" \
    --add-data "data:data" \
    --icon="static/icon.png" \
    --name="EmailAssessor" \
    web_app.py
  ```
  The output will be a standalone Mac application at `dist/EmailAssessor.app`.

---

## 🤝 Sharing & Distributing Safely

To package this folder for teammates:
1. **Clean Dynamic Files:** Delete the following files if they have been generated:
   - `feedback_log.csv` (contains records of emails you have flagged)
   - `model_state.json` (holds your local trained vocabulary)
2. **Regeneration:** When the recipient runs the code, it will automatically train a fresh model file from the seed dataset.

---

## ⚠️ Important Security Best Practices

### 1. Phishing via Visual Mimicry (Analyst Warning)
While the backend environment and browser processes are fully sandboxed, **your eyes are not**. If you open a suspicious link in Live Mode, a highly accurate spoof of a login page (e.g., a Microsoft 365 or Google sign-in form) can still be rendered in the screenshot. 
> [!WARNING]
> **Never type real user credentials** (passwords, 2FA codes, access tokens) into the interactive sandbox text field. Treat all loaded sites as malicious and inspect them visually only.

### 2. Enforcing Container Disposability
Precautionary lifecycles kill the browser threads, but if an advanced exploit successfully escapes Chromium to write artifacts to the container's temporary filesystem, these files can persist as long as the container runs.
> [!TIP]
> Periodically reset the container to a clean slate to destroy any persistent session changes. Run the following command in your terminal:
> ```powershell
> docker compose down --volumes && docker compose up -d --build
> ```

### 3. Standalone EXE Security Considerations
> [!CAUTION]
> The standalone EXE runs Playwright's Chromium **directly on your host OS** without container isolation. While the application-level sandboxing (SSRF protection, memory caps, permission stripping) is still fully active, a theoretical Chromium zero-day exploit could access files with your user's permissions. **If you regularly analyze real-world phishing campaigns, use Docker instead.**
