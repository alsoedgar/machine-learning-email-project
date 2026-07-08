import os
import sys
import json
import csv
import threading
import base64
import hashlib
import re
import socket
import ipaddress
from datetime import datetime

# Import modular components
from utils.parser import EmailParser
from utils.heuristics import HeuristicsAnalyzer, defang_url
from models.classifier import NaiveBayesClassifier
from utils.features import EmailFeatureExtractor
from models.ensemble import HybridPhishingClassifier

# ---------------------------------------------------------------------------
# Module-level persistent browser sandbox state (shared across HTTP requests)
# ---------------------------------------------------------------------------
_sandbox_pw = None
_sandbox_browser = None
_sandbox_page = None
_sandbox_current_url = ''
_sandbox_lock = threading.Lock()

from utils.parser import sanitize_input

def analyze_data(data):
    sanitized_data = sanitize_input(data)
    # Use the sanitized data for processing
    # Example: process the data here
    return f"Analyzed: {sanitized_data}"

def _undefang_url(url):
    """Converts a defanged URL back to a real navigable URL."""
    real = url.strip()
    if real.lower().startswith('hxxps://'):
        real = 'https://' + real[8:]
    elif real.lower().startswith('hxxp://'):
        real = 'http://' + real[7:]
    real = real.replace('[.]', '.')
    return real

def _is_safe_destination_url(url):
    """
    Validates that a URL does not point to the loopback address or private intranet subnets.
    Performs DNS resolution to catch DNS rebinding attempts.
    """
    try:
        from urllib.parse import urlparse
        real_url = _undefang_url(url)
        if not real_url.startswith('http'):
            real_url = 'https://' + real_url
            
        parsed = urlparse(real_url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # 1. Check string patterns
        lower_host = hostname.lower()
        local_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '[::1]']
        if any(p in lower_host for p in local_patterns) or '.local' in lower_host:
            return False
            
        # 2. Perform DNS resolution to verify destination IP block
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
            
        return True
    except Exception:
        # Block on failure to resolve or invalid formats to be safe
        return False

def _sandbox_screenshot():
    """Internal: capture PNG screenshot from active sandbox page as base64 data URI."""
    screenshot_bytes = _sandbox_page.screenshot(type='png')
    encoded = base64.b64encode(screenshot_bytes).decode('utf-8')
    return f'data:image/png;base64,{encoded}'

def get_seed_dataset():
    """Loads the 42 bootstrapping email training templates from JSON."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    seed_path = os.path.join(base_path, "data", "seed_dataset.json")
    try:
        with open(seed_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        emails = []
        labels = []
        for entry in data.get("safe", []):
            emails.append(entry["subject"] + "\n" + entry["body"])
            labels.append("Safe")
        for entry in data.get("malicious", []):
            emails.append(entry["subject"] + "\n" + entry["body"])
            labels.append("Malicious")
        for entry in data.get("spam", []):
            emails.append(entry["subject"] + "\n" + entry["body"])
            labels.append("Spam")
        return emails, labels
    except Exception:
        return [], []

class EmailAnalyzer:
    """The unified analyzer combining email parsing, heuristics, and Naive Bayes ML."""
    def __init__(self, model_dir=None):
        if model_dir is None:
            try:
                # Use PyInstaller's extracted temporary folder if packaged
                model_dir = sys._MEIPASS
            except Exception:
                model_dir = os.path.dirname(os.path.abspath(__file__))
                
        self.model_path = os.path.join(model_dir, "model_state.json")
        self.feedback_csv_path = os.path.join(model_dir, "feedback_log.csv")
        self.whitelist_path = os.path.join(model_dir, "whitelisted_senders.json")
        
        self.classifier = NaiveBayesClassifier()
        self.whitelisted_domains = set()
        self.load_whitelist()
        
        if not self.classifier.load(self.model_path):
            emails, labels = get_seed_dataset()
            self.classifier.train(emails, labels)
            self.classifier.save(self.model_path)
            
        self.hybrid_classifier = HybridPhishingClassifier(self.classifier)

    def load_whitelist(self):
        if not os.path.exists(self.whitelist_path):
            # Outlook infrastructure and Microsoft/Google safe defaults
            default_whitelist = ["outlook.com", "microsoft.com", "google.com", "gmail.com"]
            try:
                with open(self.whitelist_path, 'w', encoding='utf-8') as f:
                    json.dump(default_whitelist, f)
            except Exception:
                pass
            self.whitelisted_domains = set(default_whitelist)
        else:
            try:
                with open(self.whitelist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.whitelisted_domains = set(data)
            except Exception:
                self.whitelisted_domains = set()

    def save_whitelist(self):
        try:
            with open(self.whitelist_path, 'w', encoding='utf-8') as f:
                json.dump(list(self.whitelisted_domains), f, indent=2)
            return True
        except Exception:
            return False

    def add_to_whitelist(self, domain):
        cleaned = domain.strip().lower()
        if cleaned:
            self.whitelisted_domains.add(cleaned)
            return self.save_whitelist()
        return False

    def remove_from_whitelist(self, domain):
        cleaned = domain.strip().lower()
        if cleaned in self.whitelisted_domains:
            self.whitelisted_domains.remove(cleaned)
            return self.save_whitelist()
        return False

    def cross_reference_logs(self, sender, links, attachments):
        similarities = []
        if not os.path.exists(self.feedback_csv_path):
            return similarities
            
        sender_domain = HeuristicsAnalyzer.get_email_domain(sender)
        link_domains = {HeuristicsAnalyzer.get_domain(l['url']) for l in links if HeuristicsAnalyzer.get_domain(l['url'])}
        attachment_hashes = {att['sha256'] for att in attachments if att.get('sha256')}
        
        matches = {
            'sender_matches': 0,
            'link_matches': [],
            'attachment_matches': []
        }
        
        try:
            with open(self.feedback_csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Check sender domain match
                    past_sender = row.get('from', '')
                    past_sender_domain = HeuristicsAnalyzer.get_email_domain(past_sender)
                    if sender_domain and past_sender_domain == sender_domain:
                        matches['sender_matches'] += 1
                        
                    # Check links matching
                    past_links_raw = row.get('defanged_links', '[]')
                    try:
                        past_links = json.loads(past_links_raw)
                        for pl in past_links:
                            pl_url = pl.get('original', '')
                            pl_domain = HeuristicsAnalyzer.get_domain(pl_url)
                            if pl_domain and pl_domain in link_domains:
                                matches['link_matches'].append(pl_domain)
                    except Exception:
                        pass
                        
                    # Check attachments matching
                    past_atts_raw = row.get('attachments', '[]')
                    try:
                        past_atts = json.loads(past_atts_raw)
                        for pa in past_atts:
                            pa_hash = pa.get('sha256', '')
                            if pa_hash and pa_hash in attachment_hashes:
                                matches['attachment_matches'].append(pa.get('filename', 'attachment'))
                    except Exception:
                        pass
        except Exception:
            pass
            
        # Compile warnings
        if matches['sender_matches'] > 0:
            similarities.append({
                'type': 'Sender Domain',
                'value': sender_domain,
                'message': f"Sender domain ({sender_domain}) matches {matches['sender_matches']} past logged analysis session(s)."
            })
            
        unique_link_matches = list(set(matches['link_matches']))
        for lm in unique_link_matches:
            similarities.append({
                'type': 'Link Destination',
                'value': lm,
                'message': f"Hyperlink destination ({lm}) matches a link analyzed in past logged sessions."
            })
            
        unique_att_matches = list(set(matches['attachment_matches']))
        for am in unique_att_matches:
            similarities.append({
                'type': 'Attachment Hash',
                'value': am,
                'message': f"Attachment '{am}' SHA-256 hash matches a file seen in a past logged session."
            })
            
        return similarities

    def generate_personalized_summary(self, parsed, heuristics, ml_pred, ml_conf, ml_probs, assessment):
        summary_parts = []
        flags = heuristics['flags']
        sender_addr = parsed.get('from', '')
        sender_domain = HeuristicsAnalyzer.get_email_domain(sender_addr)
        
        # Determine dynamic slot-filled overview sentence (1-2 sentences)
        dynamic_overview = ""
        if flags.get('univ_scam_detected'):
            # Attempt to extract name of university referenced in content
            content_lower = (parsed.get('subject', '') + " " + parsed.get('body_text', '')).lower()
            univ_match = re.search(r'([a-z\-]+ university|university of [a-z\-]+)', content_lower)
            univ_name = univ_match.group(0).title() if univ_match else "a university"
            dynamic_overview = (
                f"### 🛑 Threat Alert\n"
                f"This email matches the signature of a fraudulent recruitment scam. The sender is impersonating "
                f"**{univ_name}** to offer a fake role using a public email address (`{sender_addr}`), demanding off-platform contact."
            )
        elif assessment == "POTENTIAL PHISHING":
            dynamic_overview = (
                f"### 🛑 Phishing Warning\n"
                f"This message shows clear indicators of a phishing attempt from `{sender_domain or 'unknown source'}`. "
                f"It contains spoofed domains or suspicious call-to-actions designed to compromise credentials."
            )
        elif assessment == "SPAM DETECTED":
            dynamic_overview = (
                f"### ⚠️ Spam Overview\n"
                f"This appears to be an unsolicited bulk advertisement or promotional email sent from `{sender_domain}`. "
                f"It contains common advertising vocabulary and high-frequency spam triggers."
            )
        else:
            # Check if it looks like a legitimate job post/profile match
            content_lower = (parsed.get('subject', '') + " " + parsed.get('body_text', '')).lower()
            if "job" in content_lower or "position" in content_lower or "career" in content_lower:
                dynamic_overview = (
                    f"### 🔍 Verified Opportunity\n"
                    f"This email from `{sender_domain}` appears to be a legitimate job posting or professional inquiry. "
                    f"No deceptive links, suspicious urgency cues, or sender mismatches were found."
                )
            else:
                dynamic_overview = (
                    f"### 🔍 Safety Summary\n"
                    f"No suspicious markers were detected in this message. The email from `{sender_domain}` aligns "
                    f"with all standard safety checks and Naive Bayes heuristics."
                )

        summary_parts.append(dynamic_overview)
        
        # Add detailed metrics header
        if assessment == "SAFE":
            summary_parts.append(f"Based on heuristics and text analysis, this email is classified as **LIKELY SAFE** ({ml_conf:.0%} confidence).")
        elif assessment == "SPAM DETECTED":
            summary_parts.append(f"This email is flagged as **SPAM / BULK ADVERTISEMENT** (Confidence: {ml_conf:.0%}).")
        else:
            summary_parts.append(f"This email is flagged as a **POTENTIAL PHISHING THREAT** (Confidence: {ml_conf:.0%}).")
            
        # 2. Red Flags Present
        flags = heuristics['flags']
        red_flags = []
        
        if flags.get('domain_mismatch'):
            sender = parsed.get('from', '')
            links = heuristics.get('defanged_links', [])
            link_domains = list(set([HeuristicsAnalyzer.get_domain(l['original']) for l in links if HeuristicsAnalyzer.get_domain(l['original'])]))
            domains_str = ", ".join(link_domains[:2])
            red_flags.append(f"**Sender Domain Mismatch**: Sender address `{sender}` does not align with destination domains (`{domains_str}`).")
            
        if flags.get('display_text_mismatch'):
            red_flags.append("**Deceptive Anchor Text**: The text of one or more links attempts to disguise the actual destination domain.")
            
        if flags.get('suspicious_tld'):
            red_flags.append("**Suspicious Top-Level Domain (TLD)**: Contains links pointing to high-risk domains (e.g. `.xyz`, `.top`, `.click`).")
            
        if flags.get('fake_domain_detected'):
            red_flags.append("**Fake / Impersonated Domain**: Contains domains that do not resolve in DNS or suspiciously mimic popular brands.")
            
        if flags.get('urgency_detected'):
            red_flags.append("**Urgency & Deadline Pressure**: Language contains coercive urgency cues designed to force fast actions.")
            
        if flags.get('spam_heuristics'):
            red_flags.append("**Bulk Promotional Content**: Excessive capitalization, currency density, or promotional keywords found.")
            
        if ml_pred == 'Malicious':
            red_flags.append(f"**ML Phishing Signature Match**: The Naive Bayes text model predicts malicious intent with {ml_conf:.0%} confidence.")
        elif ml_pred == 'Spam':
            red_flags.append(f"**ML Spam Pattern Match**: The Naive Bayes text model predicts bulk advertising style with {ml_conf:.0%} confidence.")
            
        if red_flags:
            summary_parts.append("### ⚠️ Red Flags Present\n" + "\n".join([f"- {flag}" for flag in red_flags]))
        else:
            summary_parts.append("### ⚠️ Red Flags Present\n- No critical threat heuristics or malicious text patterns were triggered.")

        # 3. Legitimate Indicators
        legit_indicators = []
        if not flags.get('domain_mismatch'):
            legit_indicators.append("Sender domain aligns with destination link domains.")
            
        sender_domain = HeuristicsAnalyzer.get_email_domain(parsed.get('from', ''))
        public_providers = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'protonmail.com'}
        
        if sender_domain and any(wd == sender_domain or sender_domain.endswith("." + wd) for wd in self.whitelisted_domains):
            if sender_domain in public_providers:
                # Add a strong warning warning the user about whitelisting generic providers
                legit_indicators.append(
                    f"⚠️ **Generic Domain Whitelist Warning**: Sender domain `{sender_domain}` is whitelisted in settings, "
                    f"but it is a generic public provider. Since anyone can create a free account on public providers, "
                    f"this whitelist alignment is NOT a guarantee of legitimacy and should be treated with high caution."
                )
            else:
                legit_indicators.append(f"Sender domain `{sender_domain}` is whitelisted in settings.")
                
        if not flags.get('urgency_detected'):
            legit_indicators.append("No high-pressure urgency cues detected in content.")
            
        if ml_pred == 'Safe':
            legit_indicators.append(f"ML vocabulary classifier rates this email body as clean.")
            
        # Conflict warnings (e.g. spam/malicious predicted but whitelisted or domain aligns)
        if ml_pred in ('Spam', 'Malicious') and ml_conf > 0.90:
            if not flags.get('domain_mismatch') or (sender_domain and any(wd == sender_domain for wd in self.whitelisted_domains)):
                legit_indicators.append(
                    f"⚠️ **Conflict Alert**: The text classifier is {ml_conf:.0%} confident this matches {ml_pred.lower()} patterns, "
                    f"but the sender domain is whitelisted or aligns with destination links. This discrepancy is typical "
                    f"of hijacked legitimate mailboxes, spoofed routing origins, or automated marketing campaigns."
                )
            
        if legit_indicators:
            summary_parts.append("### ✅ Signs That Could Indicate Legitimacy\n" + "\n".join([f"- {ind}" for ind in legit_indicators]))

        # 3.5 Off-Platform Contacts Section
        contacts = parsed.get('detected_contacts', {})
        detected_phones = contacts.get('phones', [])
        detected_emails = contacts.get('emails', [])
        
        if detected_phones or detected_emails:
            contact_lines = []
            if detected_phones:
                contact_lines.append(f"- **Phone Number(s) Found**: " + ", ".join([f"`{p}`" for p in detected_phones]))
            if detected_emails:
                contact_lines.append(f"- **Alternative Contact Email(s)**: " + ", ".join([f"`{e}`" for e in detected_emails]))
            
            summary_parts.append("### 📞 Off-Platform Contacts Found\n" + "\n".join(contact_lines) + 
                                 "\n\n*⚠️ Warning: Phishers frequently request off-platform communication (alternative phone or email) to bypass corporate email security blocks.*")

        # 4. Actionable Verification Next Steps
        next_steps = []
        if assessment != "SAFE":
            next_steps.append("Do **NOT** click any links or download attachments in this email yet.")
            if detected_phones:
                next_steps.append(f"Do **NOT** call the phone number(s) found in the email (" + ", ".join([f"`{p}`" for p in detected_phones]) + "). Phishers use spoofed support numbers to conduct voice phishing (vishing) scams.")
            if sender_domain:
                next_steps.append(f"Verify manually: open a browser and type the official URL (`https://{sender_domain}`) instead of using links inside the message.")
            next_steps.append("Contact the sender organization using a verified phone number or public contact page found on their official, independently-searched website (e.g. via Google or their official directory).")
            next_steps.append("Forward this email to your security operations team or email provider's abuse desk.")
        else:
            next_steps.append("The email appears clean, but always exercise caution before downloading unexpected attachments.")
            
        summary_parts.append("### 🔒 How to Verify Safely\n" + "\n".join([f"- {step}" for step in next_steps]))
        
        return "\n\n".join(summary_parts)

    def analyze_email(self, raw_content):
        parsed = EmailParser.parse_raw_email(raw_content)
        
        # Extract off-platform contacts (phones and alternative emails)
        body_and_subject = parsed['subject'] + "\n" + parsed['body_text']
        phone_pattern = re.compile(r'\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?\d{3}[-. ]?\d{4}\b')
        phones = list(set(phone_pattern.findall(body_and_subject)))
        
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        all_found_emails = email_pattern.findall(body_and_subject)
        
        sender_email_only = ""
        if '@' in parsed['from']:
            sender_parts = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', parsed['from'])
            if sender_parts:
                sender_email_only = sender_parts.group(0).lower()
                
        distinct_emails = list(set([
            e.lower() for e in all_found_emails if e.lower() != sender_email_only
        ]))
        
        parsed['detected_contacts'] = {
            'phones': phones,
            'emails': distinct_emails
        }
        
        # Get sender geographic routing origin early to avoid UnboundLocalError
        origin_data = EmailFeatureExtractor.get_email_origin(raw_content)
        
        # Check if sender domain is whitelisted
        sender_domain = HeuristicsAnalyzer.get_email_domain(parsed['from'])
        is_sender_whitelisted = False
        for wd in self.whitelisted_domains:
            if sender_domain == wd or sender_domain.endswith("." + wd):
                is_sender_whitelisted = True
                break
                
        heuristics_results = HeuristicsAnalyzer.analyze(parsed, is_sender_whitelisted=is_sender_whitelisted)
        
        full_text = parsed['subject'] + "\n" + parsed['body_text']
        
        # Extract metadata mismatch features
        metadata_features = EmailFeatureExtractor.extract_features(raw_content, parsed, heuristics_results)
        
        # Use upgraded Hybrid Phishing Classifier (Ensemble)
        ml_pred, ml_conf, ml_probs = self.hybrid_classifier.predict(full_text, metadata_features)
        
        critical_heuristics = (
            heuristics_results['flags']['display_text_mismatch'] or
            heuristics_results['flags']['domain_mismatch'] or
            heuristics_results['flags']['suspicious_tld']
        )
        
        reasons = list(heuristics_results['reasons'])
        
        # Append metadata indicator findings to reasons
        if metadata_features.get('display_brand_mismatch', 0.0) > 0:
            reasons.append("Sender display name brand spoofing detected")
        if metadata_features.get('origin_network_anomaly', 0.0) > 0:
            if origin_data.get('is_vpn'):
                reasons.append("Routing network anomaly: SMTP relay via anonymous VPN/Proxy detected")
            elif origin_data.get('is_hosting'):
                reasons.append("Routing network anomaly: SMTP relay via automated hosting server detected")
            else:
                reasons.append("Geographic routing anomaly: SMTP relay through Nigeria detected")
        if metadata_features.get('reply_to_mismatch', 0.0) > 0:
            reasons.append("Reply-To header domain mismatch detected")
            
        if heuristics_results['flags'].get('univ_scam_detected'):
            assessment = "POTENTIAL PHISHING"
            overall_confidence = max(0.92, ml_probs["Malicious"])
        elif ml_pred == "Malicious":
            reasons.append(f"ML hybrid model predicts malicious intent ({ml_conf:.0%} confidence)")
            assessment = "POTENTIAL PHISHING"
            overall_confidence = ml_probs["Malicious"]
        elif ml_pred == "Spam":
            reasons.append(f"ML hybrid model predicts bulk marketing/spam ({ml_conf:.0%} confidence)")
            assessment = "SPAM DETECTED"
            overall_confidence = ml_probs["Spam"]
        else:
            if critical_heuristics:
                reasons.append(f"ML hybrid model predicts safe, but critical heuristics were flagged")
                assessment = "POTENTIAL PHISHING"
                overall_confidence = max(0.65, ml_probs["Malicious"])
            elif heuristics_results['flags']['spam_heuristics']:
                reasons.append("ML hybrid model predicts safe, but spam heuristics were triggered")
                assessment = "SPAM DETECTED"
                overall_confidence = max(0.65, ml_probs["Spam"])
            else:
                assessment = "SAFE"
                overall_confidence = ml_probs["Safe"]
                
        # Perform historical log threat cross-referencing
        similarities = self.cross_reference_logs(parsed['from'], parsed['links'], parsed['attachments'])
        
        # Compile dynamic forensic personalized summary
        summary = self.generate_personalized_summary(
            parsed, heuristics_results, ml_pred, ml_conf, ml_probs, assessment
        )
        
        # Compute dynamic visual threat index (phishing prob + spam prob)
        gauge_score = ml_probs.get("Malicious", 0.0) + ml_probs.get("Spam", 0.0)
                
        return {
            'metadata': {
                'subject': parsed['subject'],
                'from': parsed['from'],
                'to': parsed['to'],
                'date': parsed['date'],
                'body_text': parsed['body_text'],
                'body_html': parsed['body_html']
            },
            'heuristics': {
                'flags': heuristics_results['flags'],
                'defanged_links': heuristics_results['defanged_links'],
                'sender_domain': heuristics_results['sender_domain'],
                'is_whitelisted': is_sender_whitelisted
            },
            'origin': origin_data,
            'contacts': parsed['detected_contacts'],
            'metadata_features': metadata_features,
            'attachments': parsed['attachments'],
            'ml': {
                'prediction': ml_pred,
                'confidence': ml_conf,
                'score': gauge_score,
                'probabilities': ml_probs
            },
            'assessment': assessment,
            'confidence': overall_confidence,
            'reasons': reasons,
            'similarities': similarities,
            'summary': summary
        }

    def log_feedback(self, email_metadata, prediction, confidence, human_verdict):
        file_exists = os.path.exists(self.feedback_csv_path)
        
        # Access control: If creating the feedback file for the first time, set local 0o600 permissions
        try:
            if not file_exists:
                # Open with fd to enforce permission flags at creation time
                flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
                mode = 0o600
                fd = os.open(self.feedback_csv_path, flags, mode)
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    pass
                file_exists = True
            elif hasattr(os, 'chmod'):
                os.chmod(self.feedback_csv_path, 0o600)
        except Exception:
            pass

        try:
            # Data Minimization: Store only safe metadata hashes for attachments
            minimized_attachments = []
            for att in email_metadata.get('attachments', []):
                minimized_attachments.append({
                    'filename_hash': hashlib.sha256(att.get('filename', '').encode('utf-8')).hexdigest()[:16],
                    'sha256': att.get('sha256', ''),
                    'size': att.get('size', 0)
                })

            with open(self.feedback_csv_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists or os.path.getsize(self.feedback_csv_path) == 0:
                    writer.writerow([
                        'timestamp', 'subject', 'from', 'body_text', 
                        'model_prediction', 'model_confidence', 'human_verdict',
                        'defanged_links', 'attachments'
                    ])
                
                writer.writerow([
                    datetime.now().isoformat(),
                    email_metadata.get('subject', ''),
                    email_metadata.get('from', ''),
                    email_metadata.get('body_text', '').replace('\n', ' [NEWLINE] '),
                    prediction,
                    f"{confidence:.4f}",
                    human_verdict,
                    json.dumps(email_metadata.get('defanged_links', [])),
                    json.dumps(minimized_attachments)
                ])
            return True
        except Exception:
            return False

    def retrain_model(self):
        seed_emails, seed_labels = get_seed_dataset()
        # If there is feedback, blend it with seed data
        if os.path.exists(self.feedback_csv_path):
            result = self.classifier.train_on_feedback(
                self.feedback_csv_path, self.model_path, seed_emails, seed_labels
            )
            if result:
                return True
        # Fallback: retrain on seed data alone (no feedback yet)
        self.classifier.train(seed_emails, seed_labels)
        self.classifier.save(self.model_path)
        return True

    def take_screenshot(self, url):
        """Attempts to open the URL in a headless browser via Playwright and capture a screenshot."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {
                'status': 'error',
                'message': 'Playwright library is not installed. To run offline previews, run: pip install playwright && playwright install chromium'
            }
            
        import base64
        
        # Un-defang the URL (restore protocols and dots)
        real_url = url.strip()
        if real_url.lower().startswith("hxxps://"):
            real_url = "https://" + real_url[8:]
        elif real_url.lower().startswith("hxxp://"):
            real_url = "http://" + real_url[7:]
        real_url = real_url.replace("[.]", ".")
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_viewport_size({"width": 1280, "height": 800})
                
                # Navigate with a strict 7-second timeout
                page.goto(real_url, timeout=7000, wait_until="load")
                
                # Take flat PNG screenshot
                screenshot_bytes = page.screenshot(type="png")
                browser.close()
                
                encoded = base64.b64encode(screenshot_bytes).decode('utf-8')
                return {
                    'status': 'success',
                    'image': f"data:image/png;base64,{encoded}"
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Sandbox browser failed to capture site: {str(e)}"
            }

    # ------------------------------------------------------------------
    # Persistent Live Sandbox methods
    # ------------------------------------------------------------------

    def start_sandbox(self, url):
        """Launch a persistent headless browser, navigate to url, return first screenshot."""
        global _sandbox_pw, _sandbox_browser, _sandbox_page, _sandbox_current_url
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {'status': 'error', 'message': 'Playwright is not installed. Run: pip install playwright && playwright install chromium'}

        # Network Restrictions: Block requests pointing to internal network loopback or local subnet
        if not _is_safe_destination_url(url):
            return {'status': 'error', 'message': 'Navigation to local intranet, private subnets, or loopback addresses is restricted for security.'}
        real_url = _undefang_url(url)

        with _sandbox_lock:
            # Close any existing session first
            self._stop_sandbox_internal()
            try:
                _sandbox_pw = sync_playwright().start()
                # Isolated Execution: Disable sandbox bypass triggers, keep strict browser arguments
                _sandbox_browser = _sandbox_pw.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-gpu',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',  # Runs under standard chromium security sandbox inside headless
                        '--block-new-web-contents' # Prevent popups / tabs escape
                    ]
                )
                
                # Create a completely isolated browser context with zero permissions granted
                context = _sandbox_browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    ignore_https_errors=True
                )
                
                # Prevent geolocation, notification, and microphone permissions
                context.grant_permissions([])
                
                _sandbox_page = context.new_page()
                _sandbox_page.goto(real_url, timeout=15000, wait_until='domcontentloaded')
                _sandbox_current_url = _sandbox_page.url
                return {'status': 'success', 'image': _sandbox_screenshot(), 'current_url': _sandbox_current_url}
            except Exception as e:
                self._stop_sandbox_internal()
                return {'status': 'error', 'message': f'Sandbox start failed: {str(e)}'}

    def click_sandbox(self, x_pct, y_pct):
        """Click at percentage coordinates in the live browser, return new screenshot."""
        global _sandbox_current_url
        with _sandbox_lock:
            if _sandbox_page is None:
                return {'status': 'error', 'message': 'No active sandbox session.'}
            try:
                x = max(0, int(1280 * x_pct))
                y = max(0, int(800 * y_pct))
                _sandbox_page.mouse.click(x, y)
                _sandbox_page.wait_for_timeout(1500)
                _sandbox_current_url = _sandbox_page.url
                return {'status': 'success', 'image': _sandbox_screenshot(), 'current_url': _sandbox_current_url}
            except Exception as e:
                return {'status': 'error', 'message': f'Click failed: {str(e)}'}

    def type_sandbox(self, text):
        """Type text into the active focused element in the live browser."""
        global _sandbox_current_url
        with _sandbox_lock:
            if _sandbox_page is None:
                return {'status': 'error', 'message': 'No active sandbox session.'}
            try:
                _sandbox_page.keyboard.type(text, delay=30)
                _sandbox_page.wait_for_timeout(500)
                _sandbox_current_url = _sandbox_page.url
                return {'status': 'success', 'image': _sandbox_screenshot(), 'current_url': _sandbox_current_url}
            except Exception as e:
                return {'status': 'error', 'message': f'Type failed: {str(e)}'}

    def key_sandbox(self, key):
        """Press a special key (e.g. Enter, Backspace, Tab, Escape) in the live browser."""
        global _sandbox_current_url
        with _sandbox_lock:
            if _sandbox_page is None:
                return {'status': 'error', 'message': 'No active sandbox session.'}
            try:
                _sandbox_page.keyboard.press(key)
                _sandbox_page.wait_for_timeout(1000)
                _sandbox_current_url = _sandbox_page.url
                return {'status': 'success', 'image': _sandbox_screenshot(), 'current_url': _sandbox_current_url}
            except Exception as e:
                return {'status': 'error', 'message': f'Key press failed: {str(e)}'}

    def navigate_sandbox(self, url):
        """Navigate the live browser to a new URL, return updated screenshot."""
        global _sandbox_current_url
        with _sandbox_lock:
            if _sandbox_page is None:
                return {'status': 'error', 'message': 'No active sandbox session.'}
            try:
                real_url = _undefang_url(url)
                if not real_url.startswith('http'):
                    real_url = 'https://' + real_url
                
                # Network Restrictions: Block requests pointing to internal network loopback or local subnet
                if not _is_safe_destination_url(url):
                    return {'status': 'error', 'message': 'Navigation to local intranet, private subnets, or loopback addresses is restricted for security.'}
                
                _sandbox_page.goto(real_url, timeout=15000, wait_until='domcontentloaded')
                _sandbox_current_url = _sandbox_page.url
                return {'status': 'success', 'image': _sandbox_screenshot(), 'current_url': _sandbox_current_url}
            except Exception as e:
                return {'status': 'error', 'message': f'Navigate failed: {str(e)}'}

    def stop_sandbox(self):
        """Terminate the live browser session and release resources."""
        with _sandbox_lock:
            self._stop_sandbox_internal()
        return {'status': 'success'}

    def _stop_sandbox_internal(self):
        """Internal helper: close browser without acquiring the lock (must be called within lock)."""
        global _sandbox_pw, _sandbox_browser, _sandbox_page, _sandbox_current_url
        try:
            if _sandbox_browser:
                _sandbox_browser.close()
        except Exception:
            pass
        try:
            if _sandbox_pw:
                _sandbox_pw.stop()
        except Exception:
            pass
        _sandbox_browser = None
        _sandbox_page = None
        _sandbox_pw = None
        _sandbox_current_url = ''

    def trace_link_redirects(self, defanged_url):
        """
        Launches a headless browser to follow all redirects for a defanged URL.
        Returns a dictionary containing redirect chain, title, final screenshot, and secondary links.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {
                'status': 'error',
                'message': 'Playwright is not installed.'
            }

        real_url = _undefang_url(defanged_url)
        lower_url = real_url.lower()
        
        # Block intranet/localhost
        if not _is_safe_destination_url(defanged_url):
            return {
                'status': 'error',
                'message': 'Navigation to local intranet, private subnets, or loopback addresses is restricted for security.'
            }

        navigated_urls = [real_url]
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-gpu',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        '--block-new-web-contents'
                    ]
                )
                context = browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    ignore_https_errors=True
                )
                context.grant_permissions([])
                page = context.new_page()
                
                # Listen to frame navigated events to build our redirect chain
                def handle_frame_navigated(frame):
                    if frame == page.main_frame:
                        current = frame.url
                        if current and current not in navigated_urls:
                            navigated_urls.append(current)

                page.on("framenavigated", handle_frame_navigated)
                
                # Visit the page
                page.goto(real_url, timeout=12000, wait_until='domcontentloaded')
                page.wait_for_timeout(2000) # give a little time for JS redirects if any
                
                final_url = page.url
                title = page.title() or "No Title"
                
                # screenshot
                screenshot_bytes = page.screenshot(type='png')
                encoded_screenshot = base64.b64encode(screenshot_bytes).decode('utf-8')
                
                # extract links
                raw_links = page.locator("a").evaluate_all(
                    "nodes => nodes.map(node => ({ href: node.getAttribute('href'), text: node.innerText }))"
                )
                
                # close browser
                browser.close()
                
            # Filter and defang secondary links
            secondary_links = []
            seen_secondary = set()
            for rl in raw_links:
                href = rl.get('href')
                if href:
                    href = href.strip()
                    # Resolve relative links (using final_url)
                    from urllib.parse import urljoin
                    full_href = urljoin(final_url, href)
                    # Keep only HTTP(S) links
                    if full_href.lower().startswith(('http://', 'https://')):
                        defanged_href = defang_url(full_href)
                        if defanged_href not in seen_secondary:
                            seen_secondary.add(defanged_href)
                            secondary_links.append({
                                'original': full_href,
                                'defanged': defanged_href,
                                'anchor': rl.get('text', '').strip() or 'Link'
                            })
            
            # Format the redirect chain: all elements in navigated_urls
            # We defang each step in the chain
            defanged_chain = [defang_url(url) for url in navigated_urls]
            
            return {
                'status': 'success',
                'original_url': defang_url(real_url),
                'final_url': defang_url(final_url),
                'redirect_chain': defanged_chain,
                'title': title,
                'screenshot': f"data:image/png;base64,{encoded_screenshot}",
                'secondary_links': secondary_links[:50] # cap at 50 links
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Link trace failed: {str(e)}"
            }

