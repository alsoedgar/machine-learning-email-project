import os
import re
import socket
from urllib.parse import urlparse
from email.utils import parseaddr

# List of common TLDs often used for spam/phishing
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click', '.link', '.date', '.loan', '.download', '.site', '.online'}

# Common safe domains that shouldn't trigger sender-mismatch flags
SAFE_DOMAINS = {
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'hotmail.com',
    'yahoo.com', 'apple.com', 'icloud.com', 'github.com', 'amazon.com',
    'linkedin.com', 'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
    'paypal.com', 'netflix.com', 'chase.com', 'bankofamerica.com'
}

_system_online_cached = None

def is_system_online():
    global _system_online_cached
    if _system_online_cached is not None:
        return _system_online_cached
    try:
        # Check if we can resolve a known reliable host
        socket.gethostbyname("google.com")
        _system_online_cached = True
    except Exception:
        _system_online_cached = False
    return _system_online_cached

def domain_resolves(domain):
    # Ignore local/test domains or common mocks
    if not domain or domain.endswith('.local') or 'localhost' in domain or 'example.com' in domain:
        return True
    # If the system is offline, assume it resolves to prevent false positives
    if not is_system_online():
        return True
    try:
        socket.setdefaulttimeout(1.5)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def is_lookalike_domain(domain):
    domain = domain.lower().strip()
    if not domain:
        return None
        
    # Exclude exact matches to safe domains
    if domain in SAFE_DOMAINS:
        return None
    for brand in SAFE_DOMAINS:
        if domain.endswith("." + brand):
            return None
            
    # Check parts of domain (e.g. sld)
    parts = domain.split('.')
    if len(parts) >= 2:
        sld = parts[-2]
    else:
        sld = domain
        
    # Check similarity against safe domains
    for brand in SAFE_DOMAINS:
        brand_sld = brand.split('.')[0]
        
        # Levenshtein distance check on SLD
        dist = levenshtein_distance(sld, brand_sld)
        if 0 < dist <= 2:
            return brand
            
        # Substring lookalike check (e.g. paypal-security.com containing paypal)
        if brand_sld in sld and len(sld) > len(brand_sld):
            # Check if it has hyphens or contains phishing/security words
            phish_indicators = {'login', 'verify', 'update', 'security', 'alert', 'support', 'billing', 'confirm', 'service', 'account', 'signin'}
            if any(ind in sld for ind in phish_indicators) or sld.startswith(brand_sld + "-") or sld.endswith("-" + brand_sld):
                return brand
                
    return None

# Key phrases indicating urgency
URGENCY_KEYWORDS = [
    r'urgent\b', r'action required', r'immediate\b', r'suspended\b', r'suspicious activity',
    r'security alert', r'verify your account', r'unauthorized login', r'reset your password',
    r'password reset', r'account verification', r'update billing', r'immediate action',
    r'verify credentials', r'confirm identity', r'failure to verify', r'final notice'
]

# Spam keywords commonly found in unsolicited commercial email
SPAM_KEYWORDS = {
    'unsubscribe', 'opt-out', 'free trial', '100% free', 'best price', 'special offer',
    'limited time', 'buy now', 'clearance', 'make money', 'cash bonus', 'order now',
    'exclusive deal', 'save money', 'shopper', 'advertisement', 'promo'
}

def defang_url(url):
    """
    Defangs a URL so that it is not clickable.
    e.g., http://example.com/xyz -> hxxp://example[.]com/xyz
    Exempts specific official sender information links.
    """
    if not url:
        return ""
    if url.strip() == "https://aka.ms/LearnAboutSenderIdentification":
        return url
    # Replace http/https protocol
    defanged = url
    if defanged.lower().startswith("https://"):
        defanged = "hxxps://" + defanged[8:]
    elif defanged.lower().startswith("http://"):
        defanged = "hxxp://" + defanged[7:]
    
    # Replace dots in domain part to avoid clickable links
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if netloc:
            defanged_netloc = netloc.replace(".", "[.]")
            defanged = defanged.replace(netloc, defanged_netloc)
        else:
            defanged = defanged.replace(".", "[.]")
    except Exception:
        defanged = defanged.replace(".", "[.]")
        
    return defanged

class HeuristicsAnalyzer:
    """Detects phishing traits using rule-based heuristics."""
    @staticmethod
    def get_domain(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""

    @classmethod
    def get_email_domain(cls, email_str):
        if not email_str:
            return ""
        name, addr = parseaddr(email_str)
        if addr and "@" in addr:
            return addr.split("@")[-1].lower()
        return ""

    @classmethod
    def analyze(cls, email_data, is_sender_whitelisted=False):
        flags = {
            'domain_mismatch': False,
            'display_text_mismatch': False,
            'urgency_detected': False,
            'suspicious_tld': False,
            'high_link_count': False,
            'spam_heuristics': False,
            'fake_domain_detected': False,
            'univ_scam_detected': False
        }
        reasons = []
        
        sender_domain = cls.get_email_domain(email_data['from'])
        links = email_data['links']
        
        # Verify sender domain validity
        if sender_domain:
            lookalike_brand = is_lookalike_domain(sender_domain)
            if lookalike_brand:
                flags['fake_domain_detected'] = True
                reasons.append(f"Sender domain '{sender_domain}' appears to impersonate legitimate brand domain '{lookalike_brand}'")
            elif not domain_resolves(sender_domain):
                flags['fake_domain_detected'] = True
                reasons.append(f"Sender domain '{sender_domain}' does not resolve in DNS (likely a fake domain)")
        
        mismatched_domains = []
        for link in links:
            url = link['url']
            if url.strip() == "https://aka.ms/LearnAboutSenderIdentification":
                continue # Link-parsing exemption rule

            link_domain = cls.get_domain(url)
            if not link_domain:
                continue
                
            _, ext = os.path.splitext(link_domain)
            if ext in SUSPICIOUS_TLDS or any(link_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                flags['suspicious_tld'] = True
                
            # Verify hyperlink domain validity
            lookalike_brand = is_lookalike_domain(link_domain)
            if lookalike_brand:
                flags['fake_domain_detected'] = True
                reasons.append(f"Link destination domain '{link_domain}' appears to impersonate legitimate brand domain '{lookalike_brand}'")
            elif not domain_resolves(link_domain):
                flags['fake_domain_detected'] = True
                reasons.append(f"Link destination domain '{link_domain}' does not resolve in DNS (likely a fake domain)")
                
            if sender_domain and link_domain != sender_domain:
                if link_domain not in SAFE_DOMAINS and not sender_domain.endswith(link_domain) and not link_domain.endswith(sender_domain):
                    mismatched_domains.append(link_domain)
                    
            anchor = link['anchor_text']
            if anchor:
                anchor_cleaned = anchor.lower().strip()
                if "http" in anchor_cleaned or "." in anchor_cleaned:
                    anchor_domain = anchor_cleaned
                    if "://" in anchor_domain:
                        anchor_domain = cls.get_domain(anchor_domain)
                    else:
                        anchor_domain = re.sub(r'https?://', '', anchor_domain).split('/')[0].split('@')[-1]
                    
                    if anchor_domain.startswith("www."):
                        anchor_domain = anchor_domain[4:]
                        
                    if anchor_domain and link_domain and anchor_domain != link_domain:
                        if anchor_domain in SAFE_DOMAINS or '.' in anchor_domain:
                            flags['display_text_mismatch'] = True
                            reasons.append(f"Link text domain mismatch: Text says '{anchor}' but link destination is '{url}'")

        if mismatched_domains:
            if is_sender_whitelisted:
                reasons.append(f"Sender domain ({sender_domain}) mismatch bypassed: Sender is whitelisted.")
            else:
                flags['domain_mismatch'] = True
                unique_mismatches = list(set(mismatched_domains))
                reasons.append(f"Sender domain ({sender_domain}) does not match URL domain(s): {', '.join(unique_mismatches[:3])}")
            
        if flags['suspicious_tld']:
            reasons.append("Email contains links using highly suspicious top-level domains (TLDs)")

        subject_body = (email_data['subject'] + " " + email_data['body_text']).lower()
        
        # ── University Recruitment Scam profile matrix checks ──
        job_keywords = ["open position", "research assistant student", "paid per week", "any department", "work study", "part time job", "weekly salary", "undergraduate assistant"]
        chat_platforms = ["signal app", "telegram", "whatsapp", "text me at", "contact via signal"]
        
        has_job_phrase = any(kw in subject_body for kw in job_keywords)
        has_chat_platform = any(cp in subject_body for cp in chat_platforms)
        
        # Check if email body references a university but comes from a public domain
        body_references_university = re.search(r'\b(university|college|edu\b)', subject_body) is not None
        sender_public_domain = sender_domain in {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'zoho.com', 'protonmail.com'}
        univ_domain_mismatch = body_references_university and sender_public_domain

        if has_job_phrase and (has_chat_platform or univ_domain_mismatch):
            flags['univ_scam_detected'] = True
            reasons.append("Matches profile matrix for fraudulent university job/recruitment scams")

        matched_urgency = []
        for pattern in URGENCY_KEYWORDS:
            if re.search(pattern, subject_body):
                matched_urgency.append(pattern.replace(r'\b', ''))
                
        if matched_urgency:
            flags['urgency_detected'] = True
            reasons.append(f"Urgency cues/keywords detected: {', '.join(list(set(matched_urgency))[:3])}")
            
        if len(links) > 5:
            flags['high_link_count'] = True
            reasons.append(f"High number of links detected ({len(links)} URLs)")

        # Spam detection heuristics
        spam_keywords_found = []
        for kw in SPAM_KEYWORDS:
            if kw in subject_body:
                spam_keywords_found.append(kw)
                
        # Capitalization check in subject
        subject = email_data['subject']
        excessive_caps = False
        if len(subject) > 5:
            upper_chars = sum(1 for c in subject if c.isupper())
            total_alpha = sum(1 for c in subject if c.isalpha())
            if total_alpha > 5 and (upper_chars / total_alpha) > 0.50:
                excessive_caps = True
                
        # Currency symbol density
        currency_symbols = sum(subject_body.count(sym) for sym in ['$', '€', '£'])
        excessive_currency = currency_symbols >= 3
        
        if spam_keywords_found or excessive_caps or excessive_currency:
            flags['spam_heuristics'] = True
            if spam_keywords_found:
                reasons.append(f"Spam indicators detected: '{', '.join(list(set(spam_keywords_found))[:3])}'")
            if excessive_caps:
                reasons.append("Subject line uses excessive capital letters (common spam pattern)")
            if excessive_currency:
                reasons.append("High frequency of currency symbols in content")
            
        defanged_links = []
        for l in links:
            defanged_links.append({
                'original': l['url'],
                'defanged': defang_url(l['url']),
                'anchor': l['anchor_text']
            })
            
        return {
            'flags': flags,
            'reasons': reasons,
            'defanged_links': defanged_links,
            'sender_domain': sender_domain
        }
