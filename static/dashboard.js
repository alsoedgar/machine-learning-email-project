// DOM Elements
const emailInput = document.getElementById('emailInput');
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const assessBtn = document.getElementById('assessBtn');

const scanPlaceholder = document.getElementById('scanPlaceholder');
const resultsCard = document.getElementById('resultsCard');

const scoreNumber = document.getElementById('scoreNumber');
const scoreCircle = document.getElementById('scoreCircle');
const resBadge = document.getElementById('resBadge');
const findingsList = document.getElementById('findingsList');
const forensicBody = document.getElementById('forensicBody');

const approveBtn = document.getElementById('approveBtn');
const spamBtn = document.getElementById('spamBtn');
const rejectBtn = document.getElementById('rejectBtn');

const tabAssess = document.getElementById('tabAssess');
const tabHistory = document.getElementById('tabHistory');
const tabSettings = document.getElementById('tabSettings');

const assessTabContent = document.getElementById('assessTabContent');
const historyTabContent = document.getElementById('historyTabContent');
const settingsTabContent = document.getElementById('settingsTabContent');
const historyTableBody = document.getElementById('historyTableBody');

const retrainBtn = document.getElementById('retrainBtn');
const resetStatsBtn = document.getElementById('resetStatsBtn');
const clearAllLogsBtn = document.getElementById('clearAllLogsBtn');
const darkModeToggle = document.getElementById('darkModeToggle');

const toast = document.getElementById('toast');
const toastMsg = document.getElementById('toastMsg');

const globalTooltip = document.getElementById('globalTooltip');

let toastTimeout = null;
function showToast(msg) {
    if (!toast || !toastMsg) return;
    toastMsg.textContent = msg;
    toast.classList.add('show');
    
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
        toast.classList.remove('show');
    }, 2500);
}

// Whitelist elements
const whitelistInput = document.getElementById('whitelistInput');
const addWhitelistBtn = document.getElementById('addWhitelistBtn');
const whitelistList = document.getElementById('whitelistList');

let currentResult = null;

// Statistics initialized strictly to 0
let emailsScanned = parseInt(localStorage.getItem('emailsScanned') || '0');
let blockedThreats = parseInt(localStorage.getItem('blockedThreats') || '0');

// Dark theme initialization and preference memory
function initTheme() {
    const isDark = localStorage.getItem('darkMode') === 'enabled';
    if (isDark) {
        document.body.classList.add('dark-theme');
        darkModeToggle.checked = true;
    } else {
        document.body.classList.remove('dark-theme');
        darkModeToggle.checked = false;
    }
}
initTheme();

darkModeToggle.addEventListener('change', () => {
    if (darkModeToggle.checked) {
        document.body.classList.add('dark-theme');
        localStorage.setItem('darkMode', 'enabled');
        showToast("Dark Mode enabled");
    } else {
        document.body.classList.remove('dark-theme');
        localStorage.setItem('darkMode', 'disabled');
        showToast("Dark Mode disabled");
    }
});

// Synchronize and verify backend state if clean
async function syncStateOnLoad() {
    if (emailsScanned === 0) {
        try {
            await fetch('/api/clear_history', { method: 'POST' });
        } catch (e) {}
    }
    updateStatsUI();
    loadWhitelist();
}
syncStateOnLoad();

function updateStatsUI() {
    document.getElementById('scannedCount').textContent = emailsScanned.toLocaleString();
    document.getElementById('blockedCount').textContent = blockedThreats.toLocaleString();
}

// XSS Prevention - Safe text escaping helper
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
}

// Tab Switching Logic (Controlled securely via CSS class toggles)
tabAssess.addEventListener('click', () => switchTab('assess'));
tabHistory.addEventListener('click', () => {
    switchTab('history');
    loadHistoryTable();
});
tabSettings.addEventListener('click', () => {
    switchTab('settings');
    loadWhitelist();
});

function switchTab(tabName) {
    tabAssess.classList.remove('active');
    tabHistory.classList.remove('active');
    tabSettings.classList.remove('active');
    
    assessTabContent.classList.add('tab-hidden');
    historyTabContent.classList.add('tab-hidden');
    settingsTabContent.classList.add('tab-hidden');

    if (tabName === 'assess') {
        tabAssess.classList.add('active');
        assessTabContent.classList.remove('tab-hidden');
    } else if (tabName === 'history') {
        tabHistory.classList.add('active');
        historyTabContent.classList.remove('tab-hidden');
    } else if (tabName === 'settings') {
        tabSettings.classList.add('active');
        settingsTabContent.classList.remove('tab-hidden');
    }
}

// Analysis Results Sub-Tab Switching Logic
function switchResultsTab(tabName) {
    const panels = ['resultsForensics', 'resultsOrigin', 'resultsLinks'];
    
    // Deactivate all buttons
    document.getElementById('btnResTabForensics').classList.remove('active');
    document.getElementById('btnResTabOrigin').classList.remove('active');
    document.getElementById('btnResTabLinks').classList.remove('active');
    
    document.getElementById('btnResTabForensics').style.background = 'transparent';
    document.getElementById('btnResTabOrigin').style.background = 'transparent';
    document.getElementById('btnResTabLinks').style.background = 'transparent';
    
    document.getElementById('btnResTabForensics').style.fontWeight = '500';
    document.getElementById('btnResTabOrigin').style.fontWeight = '500';
    document.getElementById('btnResTabLinks').style.fontWeight = '500';
    
    document.getElementById('btnResTabForensics').style.color = 'var(--text-muted)';
    document.getElementById('btnResTabOrigin').style.color = 'var(--text-muted)';
    document.getElementById('btnResTabLinks').style.color = 'var(--text-muted)';

    // Hide all panels
    panels.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    // Activate selected
    let btnId = 'btnResTabForensics';
    let panelId = 'resultsForensics';
    if (tabName === 'origin') {
        btnId = 'btnResTabOrigin';
        panelId = 'resultsOrigin';
    } else if (tabName === 'links') {
        btnId = 'btnResTabLinks';
        panelId = 'resultsLinks';
    }

    const btn = document.getElementById(btnId);
    if (btn) {
        btn.classList.add('active');
        btn.style.background = 'var(--card-bg)';
        btn.style.fontWeight = '600';
        btn.style.color = 'var(--text-main)';
    }

    const panel = document.getElementById(panelId);
    if (panel) panel.style.display = 'block';
}

document.getElementById('btnResTabForensics').addEventListener('click', () => switchResultsTab('forensics'));
document.getElementById('btnResTabOrigin').addEventListener('click', () => switchResultsTab('origin'));
document.getElementById('btnResTabLinks').addEventListener('click', () => switchResultsTab('links'));

// Load eml files
uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(evt) {
            emailInput.value = evt.target.result;
            showToast(`Loaded ${file.name}`);
        };
        reader.readAsText(file);
    }
});

// Trigger Analysis
assessBtn.addEventListener('click', async () => {
    const rawContent = emailInput.value.trim();
    if (!rawContent) {
        showToast("Please enter email text first");
        return;
    }
    await analyzeEmailText(rawContent, true);
});

async function analyzeEmailText(rawContent, incrementStats = true) {
    assessBtn.textContent = "Scanning...";
    assessBtn.disabled = true;

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_content: rawContent })
        });

        if (!response.ok) throw new Error("Analysis failed");
        const result = await response.json();
        
        if (incrementStats) {
            emailsScanned++;
            localStorage.setItem('emailsScanned', emailsScanned);
            if (result.assessment === "POTENTIAL PHISHING") {
                blockedThreats++;
                localStorage.setItem('blockedThreats', blockedThreats);
            }
            updateStatsUI();
        }

        displayForensics(result);
        
        // Smooth scroll to results panel to indicate completion
        setTimeout(() => {
            resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    } catch (err) {
        showToast(err.message);
    } finally {
        assessBtn.innerHTML = "Assess Safety";
        assessBtn.disabled = false;
    }
}

// Dynamic Forensic Summary generator
function generateForensicSummary(result) {
    if (result.assessment === "LIKELY SAFE") {
        return "No significant indicators of compromise (IoCs) were identified. The sender domain matches link sources and the Naive Bayes ML classifier predicts the content is safe with high confidence.";
    }
    
    let summaryParts = [];
    if (result.heuristics.flags.domain_mismatch) {
        summaryParts.push("a sender domain mismatch");
    }
    if (result.heuristics.flags.suspicious_tld) {
        summaryParts.push("highly suspicious top-level domains (TLDs) in hyperlinks");
    }
    if (result.heuristics.flags.display_text_mismatch) {
        summaryParts.push("links disguised using mismatched anchor text");
    }
    if (result.heuristics.flags.has_urgency) {
        summaryParts.push("urgent action cues in the text");
    }
    if (result.ml.prediction === "Malicious") {
        summaryParts.push(`ML text classification (confidence: ${Math.round(result.ml.confidence * 100)}%)`);
    }
    
    let summaryText = "This email is flagged as a potential phishing threat due to: ";
    if (summaryParts.length > 0) {
        summaryText += summaryParts.join(", ") + ".";
    } else {
        summaryText += "multiple heuristic threat markers.";
    }
    
    return summaryText;
}

// Basic Markdown parser for structured forensic reports
function formatMarkdown(text) {
    if (!text) return '';
    
    // Normalize all line endings (crucial to resolve OS mismatches and carriage returns)
    let html = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    
    // Render Headings (### Title)
    html = html.replace(/^###[ \t]+(.*?)$/gm, '<h4>$1</h4>');
    
    // Render Bullet Points (- Item)
    html = html.replace(/^-[ \t]+(.*?)$/gm, '<li>$1</li>');
    
    // Render Bold (**Text**)
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Render inline code (`code`)
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    
    // Render double carriage breaks to vertical spaces
    html = html.replace(/\n\n/g, '<div style="height: 0.5rem;"></div>');
    
    // Render single carriage breaks to line breaks
    html = html.replace(/\n/g, '<br>');
    
    return html;
}

// Display Forensics
function displayForensics(result) {
    currentResult = result;
    scanPlaceholder.style.display = 'none';
    resultsCard.style.display = 'flex';
    document.getElementById('techIndicatorsCard').style.display = 'block';
    document.getElementById('forensicCard').style.display = 'flex';

    const malScore = result.ml.score;
    const safetyScore = Math.round((1.0 - malScore) * 100);
    
    scoreNumber.textContent = safetyScore;
    
    const circumference = 251.2;
    const offset = circumference - (safetyScore / 100) * circumference;
    scoreCircle.style.strokeDashoffset = offset;

    // Gauge Colors & Verdict Badge
    if (result.assessment === "POTENTIAL PHISHING") {
        scoreCircle.style.stroke = "var(--threat-color)";
        resBadge.className = "result-badge";
        resBadge.style.backgroundColor = "var(--threat-bg)";
        resBadge.style.color = "var(--threat-color)";
        resBadge.textContent = "POTENTIAL PHISHING";
    } else if (result.assessment === "SPAM DETECTED") {
        scoreCircle.style.stroke = "var(--warning-color)";
        resBadge.className = "result-badge";
        resBadge.style.backgroundColor = "var(--warning-bg)";
        resBadge.style.color = "var(--warning-color)";
        resBadge.textContent = "SPAM DETECTED";
    } else {
        scoreCircle.style.stroke = "var(--safe-color)";
        resBadge.className = "result-badge";
        resBadge.style.backgroundColor = "var(--safe-bg)";
        resBadge.style.color = "var(--safe-color)";
        resBadge.textContent = "LIKELY SAFE";
    }

    // Security Findings List
    findingsList.innerHTML = '';
    
    const senderItem = document.createElement('div');
    senderItem.className = 'finding-item';
    const isMismatch = result.heuristics.flags.domain_mismatch;
    senderItem.innerHTML = `
        <span class="finding-icon">${isMismatch ? '🔴' : '🟢'}</span>
        <div>
            <span class="finding-title">Check sender address</span>
            <div class="finding-text">${escapeHtml(isMismatch ? 'Sender domain mismatch with links!' : 'Sender domain matches link sources.')}</div>
        </div>
    `;
    findingsList.appendChild(senderItem);

    const fakeDomainItem = document.createElement('div');
    fakeDomainItem.className = 'finding-item';
    const hasFake = result.heuristics.flags.fake_domain_detected;
    fakeDomainItem.innerHTML = `
        <span class="finding-icon">${hasFake ? '🔴' : '🟢'}</span>
        <div>
            <span class="finding-title">Domain Verification</span>
            <div class="finding-text">${escapeHtml(hasFake ? 'Suspicious lookalike or non-existent domains detected!' : 'All domains appear active and legitimate.')}</div>
        </div>
    `;
    findingsList.appendChild(fakeDomainItem);

    const hasLinks = result.heuristics.defanged_links.length > 0;
    const linkItem = document.createElement('div');
    linkItem.className = 'finding-item';
    let linkText = 'No hyperlinks found in body.';
    let linkIcon = '🟢';
    if (hasLinks) {
        if (result.heuristics.flags.suspicious_tld || result.heuristics.flags.display_text_mismatch) {
            linkIcon = '🔴';
            linkText = 'Suspicious links or domain disguises detected!';
        } else {
            linkIcon = '🟡';
            linkText = `Extracted ${result.heuristics.defanged_links.length} defanged links.`;
        }
    }
    linkItem.innerHTML = `
        <span class="finding-icon">${linkIcon}</span>
        <div>
            <span class="finding-title">Hyperlinks Inspector</span>
            <div class="finding-text">${escapeHtml(linkText)}</div>
        </div>
    `;
    findingsList.appendChild(linkItem);

    if (result.reasons && result.reasons.length > 0) {
        result.reasons.forEach(reason => {
            const item = document.createElement('div');
            item.className = 'finding-item';
            item.innerHTML = `
                <span class="finding-icon">🟡</span>
                <div>
                    <span class="finding-title">Threat Indicator</span>
                    <div class="finding-text">${escapeHtml(reason)}</div>
                </div>
            `;
            findingsList.appendChild(item);
        });
    }

    // Populate IoC Box (Forensic Summary)
    const iocBox = document.getElementById('iocBox');
    const iocSummary = document.getElementById('iocSummary');
    
    // Generate personalized summary
    iocSummary.innerHTML = formatMarkdown(result.summary || generateForensicSummary(result));

    // Reset results tab view to Forensics on new analysis
    switchResultsTab('forensics');

    // Populate Sender & Routing Origin Details
    if (result.origin) {
        document.getElementById('originIP').textContent = result.origin.ip || 'Unknown';
            document.getElementById('originLocation').textContent = result.origin.location || 'Unknown';
            document.getElementById('originISP').textContent = result.origin.isp || 'Unknown ISP';
            
            const vpnEl = document.getElementById('originVPN');
            if (result.origin.is_vpn) {
                vpnEl.textContent = 'Yes (VPN/Proxy Detected)';
                vpnEl.style.color = 'var(--threat-color)';
            } else {
                vpnEl.textContent = 'No';
                vpnEl.style.color = 'var(--text-main)';
            }
            
            const hostingEl = document.getElementById('originHosting');
            if (result.origin.is_hosting) {
                hostingEl.textContent = 'Yes (Hosting Server)';
                hostingEl.style.color = 'var(--warning-color)';
            } else {
                hostingEl.textContent = 'No';
                hostingEl.style.color = 'var(--text-main)';
            }
            
            const wlStatusEl = document.getElementById('whitelistStatus');
            if (result.heuristics && result.heuristics.is_whitelisted) {
                wlStatusEl.textContent = 'Whitelisted';
                wlStatusEl.style.color = 'var(--safe-color)';
            } else {
                wlStatusEl.textContent = 'Not Whitelisted';
                wlStatusEl.style.color = 'var(--text-muted)';
            }
            
            const originWarningEl = document.getElementById('originWarning');
            const hasGeoAnomaly = result.metadata_features && result.metadata_features.origin_network_anomaly > 0;
            const hasBrandMismatch = result.metadata_features && result.metadata_features.display_brand_mismatch > 0;
            
            if (hasGeoAnomaly) {
                originWarningEl.style.display = 'block';
                originWarningEl.style.backgroundColor = 'var(--threat-bg)';
                originWarningEl.style.color = 'var(--threat-color)';
                originWarningEl.style.border = '1px solid rgba(229, 62, 62, 0.2)';
                
                let warningText = '🚨 CRITICAL: ';
                if (result.origin.is_vpn) {
                    warningText += 'Anonymous VPN/Proxy origin';
                } else if (result.origin.is_hosting) {
                    warningText += 'Automated hosting datacenter origin';
                } else {
                    warningText += 'Route originates from high-risk subnet (Nigeria)';
                }
                originWarningEl.textContent = warningText;
            } else if (hasBrandMismatch) {
                originWarningEl.style.display = 'block';
                originWarningEl.style.backgroundColor = 'var(--warning-bg)';
                originWarningEl.style.color = 'var(--warning-color)';
                originWarningEl.style.border = '1px solid rgba(221, 107, 32, 0.2)';
                originWarningEl.textContent = '⚠️ SUSPICIOUS: Brand spoofing domain mismatch';
            } else if (result.origin.is_google_relay) {
                originWarningEl.style.display = 'block';
                originWarningEl.style.backgroundColor = 'rgba(66, 153, 225, 0.15)';
                originWarningEl.style.color = '#2b6cb0';
                originWarningEl.style.border = '1px solid rgba(66, 153, 225, 0.3)';
                originWarningEl.textContent = 'ℹ️ Note: Gmail hides client IPs to protect privacy. Location represents a Google relay server, not the sender.';
            } else {
                originWarningEl.style.display = 'none';
            }
    }

    // Populate defanged links with interactive live preview buttons
    const iocLinksList = document.getElementById('iocLinksList');
    iocLinksList.innerHTML = '';
    const defangedUrls = result.heuristics.defanged_links || [];
    if (defangedUrls.length === 0) {
        iocLinksList.innerHTML = '<span style="color: var(--text-muted); font-style: italic;">No links detected.</span>';
    } else {
        defangedUrls.forEach(l => {
            const div = document.createElement('div');
            div.style.padding = '0.5rem 0';
            div.style.borderBottom = '1px solid var(--border-light)';
            div.style.display = 'flex';
            div.style.flexDirection = 'column';
            div.style.gap = '0.35rem';
            
            const linkSpan = document.createElement('span');
            linkSpan.textContent = l.defanged;
            linkSpan.style.wordBreak = 'break-all';
            linkSpan.style.fontSize = '0.75rem';
            linkSpan.style.fontFamily = 'monospace';
            linkSpan.style.color = 'var(--text-main)';
            div.appendChild(linkSpan);
            
            const btnContainer = document.createElement('div');
            btnContainer.style.display = 'flex';
            btnContainer.style.justifyContent = 'flex-start';
            btnContainer.style.gap = '0.5rem';
            
            const previewBtn = document.createElement('button');
            previewBtn.className = 'btn-preview-link';
            previewBtn.style.margin = '0';
            previewBtn.style.padding = '0.3rem 0.6rem';
            previewBtn.style.fontSize = '0.7rem';
            previewBtn.innerHTML = `
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 0.2rem;">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                    <circle cx="9" cy="9" r="2"/>
                    <path d="M21 15l-3.08-3.08a2 2 0 0 0-2.83 0L12 15l-4-4-5 5"/>
                </svg>
                Preview URL Sandbox
            `;
            previewBtn.addEventListener('click', () => {
                openScreenshotSandbox(l.original);
            });
            btnContainer.appendChild(previewBtn);

            const traceBtn = document.createElement('button');
            traceBtn.className = 'btn-preview-link';
            traceBtn.style.margin = '0';
            traceBtn.style.padding = '0.3rem 0.6rem';
            traceBtn.style.fontSize = '0.7rem';
            traceBtn.innerHTML = `
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 0.2rem;">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                </svg>
                Trace redirects
            `;
            traceBtn.addEventListener('click', () => {
                openLinkTraceSandbox(l.original);
            });
            btnContainer.appendChild(traceBtn);

            div.appendChild(btnContainer);
            iocLinksList.appendChild(div);
        });
    }

    // Populate attachment hashes
    const iocHashesList = document.getElementById('iocHashesList');
    const iocAttachmentsGroup = document.getElementById('iocAttachmentsGroup');
    iocHashesList.innerHTML = '';
    const attachments = result.metadata.attachments || [];
    if (attachments.length === 0) {
        iocAttachmentsGroup.style.display = 'none';
    } else {
        iocAttachmentsGroup.style.display = 'flex';
        attachments.forEach(att => {
            const div = document.createElement('div');
            div.style.padding = '0.2rem 0';
            div.textContent = `${att.filename} (SHA-256: ${att.sha256})`;
            iocHashesList.appendChild(div);
        });
    }

    iocBox.style.display = 'flex';

    // Populate Similarity Box (Cross-Log Threat Referencer Correlation Warnings)
    const similarityBox = document.getElementById('similarityBox');
    const similarityList = document.getElementById('similarityList');
    
    const similarities = result.similarities || [];
    similarityList.innerHTML = '';
    if (similarities.length === 0) {
        similarityBox.style.display = 'none';
    } else {
        similarityBox.classList.add('has-matches');
        similarities.forEach(sim => {
            const item = document.createElement('div');
            item.className = 'similarity-item';
            item.innerHTML = `
                <span style="color: var(--threat-color); font-weight: bold; margin-top: 0.1rem;">⚠️</span>
                <div>
                    <span style="font-weight: 600; font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); display: block;">${escapeHtml(sim.type)} MATCH</span>
                    <span style="font-size: 0.78rem; line-height: 1.4; color: var(--text-main); display: block; margin-top: 0.05rem;">${escapeHtml(sim.message)}</span>
                </div>
            `;
            similarityList.appendChild(item);
        });
        similarityBox.style.display = 'flex';
    }

    // Populate Email Headers Display Panel (with lag-prevention for massive recipient/sender lists)
    document.getElementById('headerSubject').textContent = result.metadata.subject || '(No Subject)';
    document.getElementById('headerDate').textContent = result.metadata.date || '(No Date)';

    const formatHeaderCollapsible = (elemId, rawText) => {
        const elem = document.getElementById(elemId);
        elem.innerHTML = ''; // Clear previous content
        if (!rawText) {
            elem.textContent = '(None)';
            return;
        }

        // Clean any double escapes or parsing anomalies
        const cleanedText = rawText.replace(/\s+/g, ' ').trim();

        if (cleanedText.length <= 160) {
            elem.textContent = cleanedText;
            return;
        }

        // Create collapsed state
        const visibleSpan = document.createElement('span');
        visibleSpan.textContent = cleanedText.slice(0, 150) + '... ';
        
        const fullSpan = document.createElement('span');
        fullSpan.textContent = cleanedText;
        fullSpan.style.display = 'none';

        const toggleBtn = document.createElement('a');
        toggleBtn.href = '#';
        toggleBtn.textContent = `[Expand list: ${cleanedText.split(',').length} addresses]`;
        toggleBtn.style.fontSize = '0.72rem';
        toggleBtn.style.color = 'var(--primary)';
        toggleBtn.style.marginLeft = '0.5rem';
        toggleBtn.style.textDecoration = 'none';
        toggleBtn.style.fontWeight = '600';
        toggleBtn.style.cursor = 'pointer';

        toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (fullSpan.style.display === 'none') {
                fullSpan.style.display = 'inline';
                visibleSpan.style.display = 'none';
                toggleBtn.textContent = '[Collapse list]';
            } else {
                fullSpan.style.display = 'none';
                visibleSpan.style.display = 'inline';
                toggleBtn.textContent = `[Expand list: ${cleanedText.split(',').length} addresses]`;
            }
        });

        elem.appendChild(visibleSpan);
        elem.appendChild(fullSpan);
        elem.appendChild(toggleBtn);
    };

    formatHeaderCollapsible('headerFrom', result.metadata.from);
    formatHeaderCollapsible('headerTo', result.metadata.to);

    // Highlight and Annotate Email Body
    const fullBody = result.metadata.body_text || result.metadata.body_html || '';
    forensicBody.innerHTML = annotateText(fullBody, result);
    
    setupTooltipListeners();
}

// JS Text Highlighter and Annotator
function annotateText(text, result) {
    let escaped = escapeHtml(text);
    
    const links = result.heuristics.defanged_links || [];
    links.forEach(l => {
        const originalUrl = l.original;
        const defangedUrl = l.defanged;
        let annotation = `Defanged URL: ${defangedUrl}`;
        if (l.anchor) {
            annotation += ` | Display text: "${l.anchor}"`;
        }
        
        const escapedRegexUrl = originalUrl.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(escapedRegexUrl, 'g');
        
        escaped = escaped.replace(regex, (match) => {
            return `<span class="suspicious-highlight high-risk" data-annotation="${escapeHtml(annotation)}">${match}</span>`;
        });
    });

    const urgencyPhrases = [
        "urgent", "action required", "immediate", "suspended", "suspicious activity",
        "security alert", "verify your account", "unauthorized login", "reset your password",
        "password reset", "account verification", "update billing", "immediate action",
        "verify credentials", "confirm identity", "failure to verify", "final notice"
    ];
    
    urgencyPhrases.forEach(kw => {
        const regex = new RegExp(`\\b(${kw})\\b`, 'gi');
        escaped = escaped.replace(regex, (match) => {
            return `<span class="suspicious-highlight" data-annotation="Urgency indicator: '${match}'">${match}</span>`;
        });
    });

    return escaped || "(Empty Body)";
}

// Absolute global tooltip mouse tracking logic
function setupTooltipListeners() {
    const highlights = forensicBody.querySelectorAll('.suspicious-highlight');
    
    highlights.forEach(el => {
        el.addEventListener('mouseenter', (e) => {
            globalTooltip.textContent = el.getAttribute('data-annotation');
            globalTooltip.style.display = 'block';
        });
        
        el.addEventListener('mousemove', (e) => {
            const tooltipHeight = globalTooltip.offsetHeight;
            const tooltipWidth = globalTooltip.offsetWidth;
            globalTooltip.style.top = (e.pageY - tooltipHeight - 12) + 'px';
            globalTooltip.style.left = (e.pageX - tooltipWidth / 2) + 'px';
        });
        
        el.addEventListener('mouseleave', () => {
            globalTooltip.style.display = 'none';
        });
    });
}

// Approve / Reject / Spam Verdict Actions
approveBtn.addEventListener('click', () => submitVerdict('Safe'));
spamBtn.addEventListener('click', () => submitVerdict('Spam'));
rejectBtn.addEventListener('click', () => submitVerdict('Malicious'));

async function submitVerdict(verdict) {
    if (!currentResult) return;

    // Show feedback status banner immediately
    const reviewInteractive = document.getElementById('reviewInteractive');
    const reviewStatus = document.getElementById('reviewStatus');
    if (reviewInteractive && reviewStatus) {
        reviewInteractive.style.display = 'none';
        reviewStatus.style.display = 'block';
        if (verdict === 'Safe') {
            reviewStatus.style.backgroundColor = 'var(--safe-bg)';
            reviewStatus.style.color = 'var(--safe-color)';
            reviewStatus.style.border = '1px solid var(--safe-color)';
            reviewStatus.textContent = '✅ Email Approved (Safe)';
        } else if (verdict === 'Spam') {
            reviewStatus.style.backgroundColor = 'var(--warning-bg)';
            reviewStatus.style.color = 'var(--warning-color)';
            reviewStatus.style.border = '1px solid var(--warning-color)';
            reviewStatus.textContent = '⚠️ Email Flagged as Spam';
        } else {
            reviewStatus.style.backgroundColor = 'var(--threat-bg)';
            reviewStatus.style.color = 'var(--threat-color)';
            reviewStatus.style.border = '1px solid var(--threat-color)';
            reviewStatus.textContent = '❌ Email Rejected (Malicious)';
        }
    }

    const payload = {
        metadata: {
            ...currentResult.metadata,
            defanged_links: currentResult.heuristics.defanged_links,
            attachments: currentResult.attachments
        },
        prediction: currentResult.ml.prediction,
        confidence: currentResult.ml.confidence,
        verdict: verdict
    };

    try {
        const response = await fetch('/api/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error("Feedback submission failed");
        const res = await response.json();

        if (res.logged) {
            if (res.retrained) {
                showToast("Mismatch logged. Classifier retrained successfully!");
            } else {
                showToast("Discrepancy logged to feedback_log.csv");
            }
        } else {
            showToast("Verdict logged. Model predictions match!");
        }

        setTimeout(() => {
            emailInput.value = '';
            resultsCard.style.display = 'none';
            document.getElementById('techIndicatorsCard').style.display = 'none';
            document.getElementById('forensicCard').style.display = 'none';
            scanPlaceholder.style.display = 'flex';
            currentResult = null;
            
            // Restore interactive buttons
            if (reviewInteractive && reviewStatus) {
                reviewInteractive.style.display = 'block';
                reviewStatus.style.display = 'none';
            }
        }, 2200);

    } catch (err) {
        showToast(err.message);
        // Re-enable interactive layout on error
        if (reviewInteractive && reviewStatus) {
            reviewInteractive.style.display = 'block';
            reviewStatus.style.display = 'none';
        }
    }
}

// Settings actions
retrainBtn.addEventListener('click', async () => {
    retrainBtn.disabled = true;
    retrainBtn.textContent = "Retraining Model...";
    try {
        await fetch('/api/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ metadata: {}, prediction: '', confidence: 0.0, verdict: '' })
        });
        showToast("Classifier weights successfully updated from local log.");
    } catch (e) {
        showToast("Retraining failed.");
    } finally {
        retrainBtn.disabled = false;
        retrainBtn.textContent = "Retrain Model Now";
    }
});

resetStatsBtn.addEventListener('click', async () => {
    emailsScanned = 0;
    blockedThreats = 0;
    localStorage.setItem('emailsScanned', 0);
    localStorage.setItem('blockedThreats', 0);
    updateStatsUI();
    
    try {
        await fetch('/api/clear_history', { method: 'POST' });
        showToast("Scanned stats and local history log cleared.");
    } catch (e) {
        showToast("Stats cleared locally, backend reset failed.");
    }
});

// Clear All Logs link handler
clearAllLogsBtn.addEventListener('click', async () => {
    if (confirm("Are you sure you want to clear all history logs?")) {
        try {
            const response = await fetch('/api/clear_history', { method: 'POST' });
            if (!response.ok) throw new Error();
            showToast("All analyst logs cleared successfully.");
            loadHistoryTable();
        } catch (e) {
            showToast("Clear logs failed.");
        }
    }
});

// Load History Table
async function loadHistoryTable() {
    historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading logs...</td></tr>';
    try {
        const response = await fetch('/api/history');
        if (!response.ok) throw new Error();
        const logs = await response.json();
        
        historyTableBody.innerHTML = '';
        if (logs.length === 0) {
            historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No mismatch logs found.</td></tr>';
            return;
        }
        
        logs.forEach(log => {
            const tr = document.createElement('tr');
            
            // Format timestamp
            let dateStr = "N/A";
            if (log.timestamp) {
                try {
                    const d = new Date(log.timestamp);
                    dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + 
                              d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                } catch (e) {
                    dateStr = log.timestamp;
                }
            }

            const tdDate = document.createElement('td');
            tdDate.textContent = dateStr;
            tdDate.title = log.timestamp;
            tdDate.style.whiteSpace = 'nowrap';
            tdDate.style.fontSize = '0.75rem';
            tdDate.style.color = 'var(--text-muted)';

            const tdSender = document.createElement('td');
            tdSender.textContent = log.from || "(No Sender)";
            tdSender.style.fontSize = '0.8rem';
            tdSender.style.maxWidth = '250px';
            tdSender.style.wordBreak = 'break-word';
            tdSender.style.whiteSpace = 'normal';
            tdSender.title = log.from;

            const tdSubj = document.createElement('td');
            tdSubj.textContent = log.subject || "(No Subject)";
            tdSubj.style.maxWidth = '300px';
            tdSubj.style.wordBreak = 'break-word';
            tdSubj.style.whiteSpace = 'normal';
            tdSubj.title = log.subject;

            // Indicators summary
            const tdIndicators = document.createElement('td');
            const linksCount = log.defanged_links ? log.defanged_links.length : 0;
            const attsCount = log.attachments ? log.attachments.length : 0;
            
            let indicatorsHtml = "";
            if (linksCount > 0) {
                indicatorsHtml += `<span class="indicator-chip" style="background: rgba(66, 153, 225, 0.15); color: #3182ce; padding: 0.15rem 0.4rem; border-radius: 4px; font-weight: 600; font-size: 0.7rem; margin-right: 0.25rem; white-space: nowrap;">🔗 ${linksCount} link${linksCount > 1 ? 's' : ''}</span>`;
            }
            if (attsCount > 0) {
                indicatorsHtml += `<span class="indicator-chip" style="background: rgba(236, 201, 75, 0.15); color: #d69e2e; padding: 0.15rem 0.4rem; border-radius: 4px; font-weight: 600; font-size: 0.7rem; white-space: nowrap;">📎 ${attsCount} file${attsCount > 1 ? 's' : ''}</span>`;
            }
            if (indicatorsHtml === "") {
                indicatorsHtml = '<span style="color: var(--text-muted); font-size: 0.75rem;">None</span>';
            }
            
            tdIndicators.innerHTML = indicatorsHtml;
            tdIndicators.style.fontSize = '0.75rem';
            
            let iocTooltip = "";
            if (linksCount > 0) {
                iocTooltip += "URLs:\n" + log.defanged_links.map(l => "- " + l.defanged).join("\n");
            }
            if (attsCount > 0) {
                if (iocTooltip) iocTooltip += "\n\n";
                iocTooltip += "Attachments:\n" + log.attachments.map(a => "- " + a.filename + " (SHA-256: " + a.sha256.substring(0, 12) + "...)").join("\n");
            }
            if (iocTooltip) {
                tdIndicators.title = iocTooltip;
                tdIndicators.style.cursor = 'help';
                tdIndicators.style.textDecoration = 'underline dotted var(--border-light)';
            }
            
            const tdVerdict = document.createElement('td');
            tdVerdict.textContent = log.human_verdict;
            tdVerdict.style.fontWeight = '600';
            tdVerdict.style.color = log.human_verdict === 'Malicious' ? 'var(--threat-color)' : 'var(--safe-color)';
            
            const tdAction = document.createElement('td');
            tdAction.style.textAlign = 'center';
            
            const btnDelete = document.createElement('button');
            btnDelete.className = 'btn-delete-row';
            btnDelete.title = 'Delete this entry';
            btnDelete.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="3 6 5 6 21 6"/>
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                    <line x1="10" y1="11" x2="10" y2="17"/>
                    <line x1="14" y1="11" x2="14" y2="17"/>
                </svg>
            `;
            
            btnDelete.addEventListener('click', async (e) => {
                e.stopPropagation();
                if (confirm(`Delete log entry "${log.subject}"?`)) {
                    try {
                        const delResponse = await fetch('/api/delete_log', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ timestamp: log.timestamp })
                        });
                        if (!delResponse.ok) throw new Error();
                        showToast("Log entry deleted successfully.");
                        loadHistoryTable();
                    } catch (err) {
                        showToast("Failed to delete log entry.");
                    }
                }
            });
            
            tdAction.appendChild(btnDelete);
            
            tr.appendChild(tdDate);
            tr.appendChild(tdSender);
            tr.appendChild(tdSubj);
            tr.appendChild(tdIndicators);
            tr.appendChild(tdVerdict);
            tr.appendChild(tdAction);
            
            // Add safe tabindex and keyboard listeners to log table rows so keyboard users can navigate table logs
            tr.tabIndex = 0;
            tr.setAttribute('role', 'link');
            tr.setAttribute('aria-label', `Log entry for subject: ${log.subject}`);
            tr.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    tr.click();
                }
            });
            
            // Clicking log row reloads and switches tab to Assess
            tr.addEventListener('click', () => {
                const rawEmail = `From: ${log.from}\nSubject: ${log.subject}\n\n${log.body_text}`;
                emailInput.value = rawEmail;
                switchTab('assess');
                analyzeEmailText(rawEmail, false);
                showToast("Loaded email from history log");
            });
            
            historyTableBody.appendChild(tr);
        });
        
        // Re-initialize custom triggers inside history table
        initSafeFocus();
    } catch (err) {
        historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: color; var(--threat-color);">Failed to load feedback log file.</td></tr>';
    }
}

// Safe Focus and Keyboard Accessibility Initializer
function initSafeFocus() {
    // Select elements that represent custom interactive triggers (removal actions, modal triggers, close controls)
    const customInteractive = document.querySelectorAll('.whitelist-tag-remove, .modal-close');
    
    customInteractive.forEach((element) => {
        // Safe Assignment: only apply to elements lacking native focus capabilities
        if (!element.hasAttribute('tabindex')) {
            element.tabIndex = 0;
        }
        if (!element.hasAttribute('role')) {
            element.setAttribute('role', 'button');
        }
        if (!element.hasAttribute('aria-label')) {
            const domain = element.getAttribute('data-domain');
            if (domain) {
                element.setAttribute('aria-label', `Remove ${domain} from whitelist`);
            } else {
                element.setAttribute('aria-label', 'Close dialog');
            }
        }
        
        // Bind standard activation keys (Space, Enter) securely to prevent trigger gaps
        if (!element.dataset.keyboardBound) {
            element.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    element.click();
                }
            });
            element.dataset.keyboardBound = "true";
        }
    });
}

// Whitelist Manager Functions
async function loadWhitelist() {
    try {
        const res = await fetch('/api/whitelist');
        if (!res.ok) throw new Error("Failed to load whitelist");
        const list = await res.json();
        
        whitelistList.innerHTML = '';
        if (list.length === 0) {
            whitelistList.innerHTML = '<span style="color: var(--text-muted); font-size: 0.75rem; font-style: italic;">No whitelisted domains.</span>';
            return;
        }
        
        list.sort().forEach(domain => {
            const tag = document.createElement('div');
            tag.className = 'whitelist-tag';
            tag.innerHTML = `
                <span>${escapeHtml(domain)}</span>
                <span class="whitelist-tag-remove" data-domain="${escapeHtml(domain)}">×</span>
            `;
            whitelistList.appendChild(tag);
        });
        
        // Re-initialize dynamic custom triggers inside settings view
        initSafeFocus();
    } catch (err) {
        console.error("Whitelist error:", err);
    }
}

async function addWhitelistDomain(domain) {
    domain = domain.trim().toLowerCase();
    if (!domain) return;
    
    // Validate domain name format
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,10}$/;
    if (!domainRegex.test(domain)) {
        showToast("Invalid domain format (e.g. outlook.com)");
        return;
    }
    
    try {
        const res = await fetch('/api/whitelist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(`Whitelisted ${domain}`);
            whitelistInput.value = '';
            loadWhitelist();
        } else {
            showToast("Failed to whitelist domain");
        }
    } catch (err) {
        showToast(err.message);
    }
}

async function deleteWhitelistDomain(domain) {
    try {
        const res = await fetch('/api/whitelist/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(`Removed ${domain} from whitelist`);
            loadWhitelist();
        } else {
            showToast("Failed to remove domain");
        }
    } catch (err) {
        showToast(err.message);
    }
}

// Add whitelist event listeners
addWhitelistBtn.addEventListener('click', () => {
    addWhitelistDomain(whitelistInput.value);
});

whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        addWhitelistDomain(whitelistInput.value);
    }
});

// Visual Tab vs Annotated Tab email sandboxing logic
const btnViewAnnotated = document.getElementById('btnViewAnnotated');
const btnViewVisual = document.getElementById('btnViewVisual');
const forensicBodyEl = document.getElementById('forensicBody');
const visualSandboxContainer = document.getElementById('visualSandboxContainer');
const visualSandboxIframe = document.getElementById('visualSandboxIframe');

btnViewAnnotated.addEventListener('click', () => {
    btnViewAnnotated.style.backgroundColor = 'var(--card-bg)';
    btnViewAnnotated.style.fontWeight = '600';
    btnViewAnnotated.style.color = 'var(--text-main)';
    
    btnViewVisual.style.backgroundColor = 'transparent';
    btnViewVisual.style.fontWeight = '500';
    btnViewVisual.style.color = 'var(--text-muted)';
    
    forensicBodyEl.style.display = 'block';
    visualSandboxContainer.style.display = 'none';
});

btnViewVisual.addEventListener('click', () => {
    btnViewVisual.style.backgroundColor = 'var(--card-bg)';
    btnViewVisual.style.fontWeight = '600';
    btnViewVisual.style.color = 'var(--text-main)';
    
    btnViewAnnotated.style.backgroundColor = 'transparent';
    btnViewAnnotated.style.fontWeight = '500';
    btnViewAnnotated.style.color = 'var(--text-muted)';
    
    forensicBodyEl.style.display = 'none';
    visualSandboxContainer.style.display = 'block';
});

// Update displayForensics to load Iframe content and run background link redirects tracing
const originalDisplayForensics = displayForensics;
displayForensics = function(result) {
    originalDisplayForensics(result);
    
    // Reset back to Annotated Tab initially on fresh load
    btnViewAnnotated.click();
    
    // Populate iframe
    const bodyHtml = result.metadata.body_html || '';
    const bodyText = result.metadata.body_text || '';
    if (bodyHtml) {
        visualSandboxIframe.srcdoc = bodyHtml;
    } else {
        const escaped = escapeHtml(bodyText).replace(/\n/g, '<br>');
        visualSandboxIframe.srcdoc = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        font-size: 13px;
                        line-height: 1.5;
                        color: #333333;
                        margin: 16px;
                        padding: 0;
                        background: #ffffff;
                        word-wrap: break-word;
                        white-space: pre-wrap;
                    }
                </style>
            </head>
            <body>${escaped}</body>
            </html>
        `;
    }

    // Trigger background link tracing and render traced screenshots
    const tracedLinksGrid = document.getElementById('tracedLinksGrid');
    
    if (tracedLinksGrid) {
        tracedLinksGrid.innerHTML = '';
        
        const links = result.heuristics.defanged_links || [];
        if (links.length === 0) {
            tracedLinksGrid.innerHTML = `
                <div style="text-align: center; padding: 1.5rem; color: var(--text-muted); font-size: 0.8rem; font-style: italic; grid-column: span 2;">
                    No links detected in this email.
                </div>`;
        } else {
            links.forEach((l, idx) => {
                const card = document.createElement('div');
                card.className = 'traced-link-preview-card';
                card.innerHTML = `
                    <div class="traced-link-info-col">
                        <div class="traced-link-label">Link #${idx + 1}</div>
                        <div class="traced-link-source-url" title="${escapeHtml(l.defanged)}">
                            Source: <span>${escapeHtml(l.defanged)}</span>
                        </div>
                        <div class="traced-link-loading-status" id="trace-status-${idx}">
                            <div class="sandbox-spinner" style="width: 10px; height: 10px; border-width: 1.5px; display: inline-block; vertical-align: middle; margin-right: 0.35rem;"></div>
                            <span style="font-size: 0.72rem; color: var(--text-muted);">Launching sandbox to trace redirects...</span>
                        </div>
                    </div>
                    <div class="traced-link-image-col" id="trace-thumb-container-${idx}">
                        <div class="traced-link-thumb-placeholder">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--text-muted); opacity: 0.4;">
                                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                                <circle cx="9" cy="9" r="2"/>
                                <path d="M21 15l-3.08-3.08a2 2 0 0 0-2.83 0L12 15l-4-4-5 5"/>
                            </svg>
                        </div>
                    </div>
                `;
                tracedLinksGrid.appendChild(card);
                
                // Dispatch asynchronous redirect tracer request
                fetch('/api/analyze-link', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: l.original })
                })
                .then(res => res.json())
                .then(data => {
                    const statusEl = document.getElementById(`trace-status-${idx}`);
                    const thumbEl = document.getElementById(`trace-thumb-container-${idx}`);
                    
                    if (data.status === 'success') {
                        // Render concise redirect path steps
                        let pathSteps = [];
                        data.redirect_chain.forEach((step, sIdx) => {
                            try {
                                const urlObj = new URL(step.replace(/\[\.\]/g, '.').replace('hxxps', 'https').replace('hxxp', 'http'));
                                pathSteps.push(urlObj.hostname);
                            } catch (_) {
                                pathSteps.push('Redirect Destination');
                            }
                        });
                        
                        const pathString = pathSteps.map(p => `<code>${escapeHtml(p)}</code>`).join(' ➔ ');
                        
                        statusEl.innerHTML = `
                            <div style="margin-top: 0.25rem;">
                                <strong style="font-size: 0.75rem; color: var(--text-main);">Final Title:</strong> 
                                <span style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(data.title || 'No Title')}</span>
                            </div>
                            <div style="margin-top: 0.25rem; font-size: 0.7rem; color: var(--text-muted); word-break: break-all;">
                                <strong style="color: var(--text-main);">Chain:</strong> ${pathString}
                            </div>
                        `;
                        
                        // Render thumbnail
                        thumbEl.innerHTML = `
                            <img class="traced-link-thumbnail-img" src="${data.screenshot}" alt="Webpage Preview" title="Click to view full size">
                        `;
                        thumbEl.querySelector('img').addEventListener('click', () => {
                            openScreenshotLightbox(data.screenshot, data.final_url, data.title);
                        });
                    } else {
                        // Error tracing link
                        statusEl.innerHTML = `
                            <span style="color: var(--threat-color); font-size: 0.72rem; font-weight: 500;">
                                ⚠️ Trace Failed: ${escapeHtml(data.message)}
                            </span>
                        `;
                    }
                })
                .catch(err => {
                    const statusEl = document.getElementById(`trace-status-${idx}`);
                    if (statusEl) {
                        statusEl.innerHTML = `
                            <span style="color: var(--threat-color); font-size: 0.72rem; font-weight: 500;">
                                ⚠️ Error: ${escapeHtml(err.message)}
                            </span>
                        `;
                    }
                });
            });
        }
    }
};

// ================================================================
// Playwright Screenshot Sandbox Modal — dual-mode (static + live)
// ================================================================
const screenshotModal = document.getElementById('screenshotModal');
const modalCloseBtn   = document.getElementById('modalCloseBtn');
const modalBody       = document.getElementById('modalBody');

let sandboxLiveMode    = false;
let sandboxCurrentUrl  = '';

async function closeSandboxModal() {
    screenshotModal.classList.remove('active');
    if (sandboxLiveMode) {
        sandboxLiveMode = false;
        try {
            await fetch('/api/sandbox/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            });
        } catch (_) {}
    }
}

modalCloseBtn.addEventListener('click', closeSandboxModal);

screenshotModal.addEventListener('click', (e) => {
    if (e.target === screenshotModal) closeSandboxModal();
});

// ── Static screenshot (safe read-only preview) ──
async function openScreenshotSandbox(rawUrl) {
    sandboxCurrentUrl = rawUrl;
    sandboxLiveMode   = false;
    screenshotModal.classList.add('active');

    modalBody.innerHTML = `
        <div class="sandbox-loading">
            <div class="sandbox-spinner"></div>
            <span>Capturing safe static snapshot…</span>
            <span style="font-size:0.7rem;color:var(--text-muted);text-align:center;max-width:400px;word-break:break-all;">${escapeHtml(rawUrl)}</span>
        </div>`;

    try {
        const res = await fetch('/api/screenshot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        }).then(r => r.json());

        if (res.status === 'success') {
            renderStaticScreenshot(rawUrl, res.image);
        } else {
            renderSandboxError(res.message);
        }
    } catch (err) {
        renderSandboxError(err.message);
    }
}

function renderStaticScreenshot(url, imageData) {
    modalBody.innerHTML = `
        <img src="${imageData}" class="screenshot-img" id="sandboxImg" alt="Safe Web Preview">
        <div class="sandbox-static-footer">
            <span style="font-size:0.75rem;color:var(--text-muted);">
                Static snapshot — scripting &amp; active controls fully isolated
            </span>
            <button class="sandbox-golive-btn" id="goLiveBtn">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>
                </svg>
                Go Live
            </button>
        </div>`;
    document.getElementById('goLiveBtn').addEventListener('click', () => openLiveSandbox(url));
}

// ── Live interactive sandbox ──
async function openLiveSandbox(rawUrl) {
    sandboxLiveMode   = true;
    sandboxCurrentUrl = rawUrl;

    modalBody.innerHTML = `
        <div class="sandbox-loading">
            <div class="sandbox-spinner"></div>
            <span>Starting live browser session…</span>
            <span style="font-size:0.7rem;color:var(--text-muted);">⚠️ Interactive mode — all navigation stays inside this isolated sandbox</span>
        </div>`;

    try {
        const res = await fetch('/api/sandbox/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        }).then(r => r.json());

        if (res.status === 'success') {
            sandboxCurrentUrl = res.current_url || rawUrl;
            renderLiveSandbox(res.image, sandboxCurrentUrl);
        } else {
            sandboxLiveMode = false;
            renderSandboxError(res.message);
        }
    } catch (err) {
        sandboxLiveMode = false;
        renderSandboxError(err.message);
    }
}

function renderLiveSandbox(imageData, currentUrl) {
    modalBody.innerHTML = `
        <div class="sandbox-toolbar">
            <div class="sandbox-nav-row">
                <button class="sandbox-nav-btn" id="sbBack" title="Back">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"/></svg>
                </button>
                <button class="sandbox-nav-btn" id="sbForward" title="Forward">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
                <input type="text" class="sandbox-url-bar" id="sandboxUrlBar"
                       value="${escapeHtml(currentUrl)}" placeholder="Enter URL…">
                <button class="sandbox-go-btn" id="sbGo">Go</button>
            </div>
        </div>
        <div class="sandbox-img-wrapper" id="sandboxImgWrapper">
            <img src="${imageData}" class="screenshot-img sandbox-img-interactive" id="sandboxImg" alt="Live Browser">
            <div class="sandbox-img-overlay" id="sandboxImgOverlay">
                <div class="sandbox-spinner"></div>
            </div>
        </div>
        <div class="sandbox-keyboard-row">
            <input type="text" class="sandbox-type-input" id="sandboxTypeInput" placeholder="⌨️ Type text here…">
            <button class="sandbox-key-btn" id="sbSendText" title="Send text">Send</button>
            <button class="sandbox-key-btn" id="sbEnter" title="Enter key">↵</button>
            <button class="sandbox-key-btn" id="sbBackspace" title="Backspace">⌫</button>
            <button class="sandbox-key-btn" id="sbTab" title="Tab key">Tab</button>
            <button class="sandbox-key-btn" id="sbEsc" title="Escape key">Esc</button>
        </div>
        <div class="sandbox-live-footer">
            <span class="sandbox-live-badge">● LIVE</span>
            <span style="font-size:0.7rem;color:var(--text-muted);">
                Click the image to interact · Type below · All traffic is sandboxed
            </span>
        </div>`;

    attachLiveSandboxListeners();
}

function attachLiveSandboxListeners() {
    const img     = document.getElementById('sandboxImg');
    const overlay = document.getElementById('sandboxImgOverlay');

    // ── Image click → sandbox click ──
    img.addEventListener('click', async (e) => {
        const rect = img.getBoundingClientRect();
        const xPct = (e.clientX - rect.left) / rect.width;
        const yPct = (e.clientY - rect.top)  / rect.height;
        await sandboxAction('/api/sandbox/click', { x_pct: xPct, y_pct: yPct }, overlay, img);
    });

    // ── Navigation buttons ──
    document.getElementById('sbBack').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Alt+ArrowLeft' }, overlay, img));
    document.getElementById('sbForward').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Alt+ArrowRight' }, overlay, img));

    // ── URL bar ──
    const urlBar = document.getElementById('sandboxUrlBar');
    const goBtn  = document.getElementById('sbGo');
    const doNav  = async () => {
        const url = urlBar.value.trim();
        if (url) await sandboxAction('/api/sandbox/navigate', { url }, overlay, img);
    };
    goBtn.addEventListener('click', doNav);
    urlBar.addEventListener('keydown', (e) => { if (e.key === 'Enter') doNav(); });

    // ── Virtual keyboard ──
    const typeInput = document.getElementById('sandboxTypeInput');
    const sendType  = async () => {
        const text = typeInput.value;
        if (!text) return;
        typeInput.value = '';
        await sandboxAction('/api/sandbox/type', { text }, overlay, img);
    };
    document.getElementById('sbSendText').addEventListener('click', sendType);
    typeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendType(); });

    document.getElementById('sbEnter').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Enter' }, overlay, img));
    document.getElementById('sbBackspace').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Backspace' }, overlay, img));
    document.getElementById('sbTab').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Tab' }, overlay, img));
    document.getElementById('sbEsc').addEventListener('click',
        () => sandboxAction('/api/sandbox/key', { key: 'Escape' }, overlay, img));
}

// ── Generic sandbox action helper ──
async function sandboxAction(endpoint, payload, overlay, img) {
    overlay.classList.add('active');
    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).then(r => r.json());

        if (res.status === 'success') {
            img.src = res.image;
            sandboxCurrentUrl = res.current_url || sandboxCurrentUrl;
            const bar = document.getElementById('sandboxUrlBar');
            if (bar) bar.value = sandboxCurrentUrl;
        } else {
            showToast(res.message || 'Sandbox error');
        }
    } catch (err) {
        showToast('Sandbox: ' + err.message);
    } finally {
        overlay.classList.remove('active');
    }
}

function renderSandboxError(message) {
    modalBody.innerHTML = `
        <div style="text-align:center;padding:2rem;color:var(--threat-color);">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom:0.5rem;display:inline-block;">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <h4 style="font-weight:600;font-size:0.85rem;margin-bottom:0.5rem;">Sandbox Error</h4>
            <p style="font-size:0.75rem;color:var(--text-muted);line-height:1.45;max-width:450px;margin:0 auto;">${escapeHtml(message)}</p>
        </div>`;
}

// Keyboard navigation for sidebar and navigation menu elements
document.addEventListener('DOMContentLoaded', function () {
    // Configured to support both legacy "nav a" elements and current ".nav-bar .nav-item" buttons
    const navLinks = document.querySelectorAll('nav a, .nav-bar .nav-item');
    let currentIndex = 0;

    navLinks.forEach((link, index) => {
        link.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                const direction = e.key === 'ArrowDown' ? 1 : -1;
                currentIndex = (currentIndex + direction + navLinks.length) % navLinks.length;
                navLinks[currentIndex].focus();
            }
        });

        // Track focus on click/manual select to keep active focus index accurate
        link.addEventListener('focus', function () {
            currentIndex = index;
        });
    });

    // Run safe focus initializer on initial page load
    initSafeFocus();
});

// ================================================================
// Deep Link Trace Sandbox Modal
// ================================================================
const linkTraceModal = document.getElementById('linkTraceModal');
const linkTraceCloseBtn = document.getElementById('linkTraceCloseBtn');
const linkTraceBody = document.getElementById('linkTraceBody');

function closeLinkTraceModal() {
    linkTraceModal.classList.remove('active');
}

linkTraceCloseBtn.addEventListener('click', closeLinkTraceModal);
linkTraceModal.addEventListener('click', (e) => {
    if (e.target === linkTraceModal) closeLinkTraceModal();
});

// Close modal on Escape key press
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeLinkTraceModal();
    }
});

async function openLinkTraceSandbox(rawUrl) {
    linkTraceModal.classList.add('active');
    
    linkTraceBody.innerHTML = `
        <div class="sandbox-loading">
            <div class="sandbox-spinner"></div>
            <span>Spinning up isolated sandbox...</span>
            <span style="font-size:0.7rem;color:var(--text-muted);text-align:center;max-width:400px;word-break:break-all;">Following redirect path for: ${escapeHtml(rawUrl)}</span>
        </div>`;
        
    try {
        const res = await fetch('/api/analyze-link', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: rawUrl })
        }).then(r => r.json());
        
        if (res.status === 'success') {
            renderLinkTraceResult(res);
        } else {
            renderLinkTraceError(res.message);
        }
    } catch (err) {
        renderLinkTraceError(err.message);
    }
}

function renderLinkTraceResult(data) {
    // Generate HTML for the redirect chain
    let chainHtml = '';
    data.redirect_chain.forEach((step, idx) => {
        const isLast = idx === data.redirect_chain.length - 1;
        chainHtml += `
            <div class="trace-step-item">
                <div class="trace-step-num">${idx + 1}</div>
                <div class="trace-step-content">
                    <span class="trace-step-url">${escapeHtml(step)}</span>
                    ${isLast ? `<span class="trace-step-final-tag">Final Destination</span>` : ''}
                </div>
            </div>
        `;
        if (!isLast) {
            chainHtml += `
                <div class="trace-step-connector">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/>
                    </svg>
                </div>
            `;
        }
    });

    // Generate HTML for secondary links
    let linksHtml = '';
    if (data.secondary_links.length === 0) {
        linksHtml = `<span style="color: var(--text-muted); font-style: italic; font-size: 0.75rem;">No secondary links detected on page.</span>`;
    } else {
        linksHtml = `
            <div class="secondary-links-grid">
                ${data.secondary_links.map(l => `
                    <div class="secondary-link-card">
                        <span class="secondary-link-anchor">${escapeHtml(l.anchor || 'Link')}</span>
                        <span class="secondary-link-url" title="${escapeHtml(l.defanged)}">${escapeHtml(l.defanged)}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }

    linkTraceBody.innerHTML = `
        <div class="trace-result-layout">
            <div class="trace-left-col">
                <div class="trace-section">
                    <div class="trace-section-header">
                        <span class="trace-section-title">Redirect Path</span>
                    </div>
                    <div class="trace-chain-container">
                        ${chainHtml}
                    </div>
                </div>
                
                <div class="trace-section" style="margin-top: 1.5rem;">
                    <div class="trace-section-header">
                        <span class="trace-section-title">Secondary Links (${data.secondary_links.length})</span>
                    </div>
                    <div class="trace-links-container">
                        ${linksHtml}
                    </div>
                </div>
            </div>
            
            <div class="trace-right-col">
                <div class="trace-section">
                    <div class="trace-section-header">
                        <span class="trace-section-title">Page Snapshot</span>
                    </div>
                    <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main); margin-bottom: 0.5rem; word-break: break-all;">
                        Title: <span style="font-weight: 500; color: var(--text-muted);">${escapeHtml(data.title)}</span>
                    </div>
                    <div class="trace-screenshot-container">
                        <img src="${data.screenshot}" class="trace-screenshot-img" alt="Final Destination Web Page Preview">
                    </div>
                    <div style="margin-top: 0.5rem; text-align: center;">
                        <span style="font-size:0.7rem;color:var(--text-muted);">
                            Headless browser snapshot - scripts, forms, and trackers disabled
                        </span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderLinkTraceError(message) {
    linkTraceBody.innerHTML = `
        <div style="text-align:center;padding:2rem;color:var(--threat-color);">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom:0.5rem;display:inline-block;">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <h4 style="font-weight:600;font-size:0.85rem;margin-bottom:0.5rem;">Tracer Error</h4>
            <p style="font-size:0.75rem;color:var(--text-muted);line-height:1.45;max-width:450px;margin:0 auto;">${escapeHtml(message)}</p>
        </div>`;
}

// ================================================================
// Screenshot Lightbox Modal Logic
// ================================================================
const screenshotLightboxModal = document.getElementById('screenshotLightboxModal');
const lightboxCloseBtn = document.getElementById('lightboxCloseBtn');
const lightboxImg = document.getElementById('lightboxImg');
const lightboxCaption = document.getElementById('lightboxCaption');

function openScreenshotLightbox(src, defangedUrl, title) {
    lightboxImg.src = src;
    lightboxCaption.innerHTML = `
        <div style="font-weight:600; color:#ffffff; font-size:0.88rem;">${escapeHtml(title || 'Page Preview')}</div>
        <div style="font-family:'JetBrains Mono', monospace; color:#cbd5e0; font-size:0.72rem; margin-top:0.25rem; word-break:break-all;">Destination: ${escapeHtml(defangedUrl)}</div>
    `;
    screenshotLightboxModal.classList.add('active');
}

function closeScreenshotLightbox() {
    screenshotLightboxModal.classList.remove('active');
    setTimeout(() => {
        lightboxImg.src = '';
    }, 200);
}

lightboxCloseBtn.addEventListener('click', closeScreenshotLightbox);
screenshotLightboxModal.addEventListener('click', (e) => {
    if (e.target === screenshotLightboxModal) closeScreenshotLightbox();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeScreenshotLightbox();
});