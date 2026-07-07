import re
import ipaddress
import urllib.request
import json
from email.utils import parseaddr
from urllib.parse import urlparse

# Representative Nigerian IP subnets for testing and demo purposes
NIGERIA_CIDRS = [
    "197.210.0.0/16",
    "105.112.0.0/16",
    "102.88.0.0/15",  # 102.88.0.0 - 102.89.255.255
    "41.203.64.0/19",
    "41.58.0.0/16",
    "154.113.0.0/16",
    "105.113.0.0/16",
    "197.156.0.0/16",
    "102.90.0.0/16",
    "102.91.0.0/16"
]

def is_nigerian_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return False
        for cidr in NIGERIA_CIDRS:
            if ip in ipaddress.ip_network(cidr):
                return True
    except Exception:
        pass
    return False

def get_ip_location(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return "Local Private Network"
    except Exception:
        return "Unknown Location"
        
    if is_nigerian_ip(ip_str):
        return "Nigeria (Detected offline)"
        
    # Online check with 1-second timeout
    try:
        url = f"http://ip-api.com/json/{ip_str}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.0) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                country = data.get('country', '')
                city = data.get('city', '')
                if city and country:
                    return f"{country} ({city})"
                return country or "Unknown Country"
    except Exception:
        pass
        
    return "Unknown (Offline)"

def get_ip_details(ip_str):
    details = {
        "ip": ip_str,
        "location": "Unknown Location",
        "is_vpn": False,
        "is_hosting": False,
        "isp": "Unknown ISP",
        "is_google_relay": False
    }
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            details["location"] = "Local Private Network"
            details["isp"] = "Loopback/Private"
            return details
    except Exception:
        return details
        
    if is_nigerian_ip(ip_str):
        details["location"] = "Nigeria (Detected offline)"
        details["isp"] = "Nigerian ISP (Offline)"
        return details
        
    try:
        # Request country, city, proxy (VPN), hosting, and ISP name
        url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,city,proxy,hosting,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.2) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                country = data.get('country', '')
                city = data.get('city', '')
                isp_name = data.get('isp', 'Unknown ISP')
                details["isp"] = isp_name
                details["is_vpn"] = bool(data.get('proxy', False))
                details["is_hosting"] = bool(data.get('hosting', False))
                
                if "google" in isp_name.lower():
                    details["is_google_relay"] = True
                    details["location"] = f"{country} ({city}) [Google Mail Relay]"
                else:
                    details["is_google_relay"] = False
                    details["location"] = f"{country} ({city})" if city and country else (country or "Unknown Country")
    except Exception:
        pass
        
    return details

class EmailFeatureExtractor:
    """Extracts structured numerical security features from raw email headers and metadata."""
    
    @staticmethod
    def extract_ips_from_headers(raw_content):
        """Extracts all IPv4 addresses found in the email header block."""
        # Find the header/body separator (double newline)
        parts = re.split(r'\n\s*\n', raw_content, maxsplit=1)
        headers = parts[0] if parts else raw_content
        
        # Regex for IPv4
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        return list(set(ip_pattern.findall(headers)))

    @staticmethod
    def extract_features(raw_content, parsed_email, heuristics_result):
        """
        Extracts a dictionary of key-value features for classification.
        Returns a dict of feature names to float values (0.0 or 1.0).
        """
        features = {
            'display_brand_mismatch': 0.0,
            'reply_to_mismatch': 0.0,
            'origin_network_anomaly': 0.0,
            'suspicious_subject_urgency': 0.0
        }
        
        # 1. Display Name / Brand Spoofing Mismatch
        from_header = parsed_email.get('from', '')
        display_name, addr = parseaddr(from_header)
        display_name_lower = display_name.lower()
        addr_lower = addr.lower()
        
        brand_keywords = ['uic', 'university of illinois', 'payroll', 'helpdesk', 'admin', 'billing', 'support', 'secure']
        contains_brand_kw = any(kw in display_name_lower for kw in brand_keywords)
        
        if contains_brand_kw:
            # Check if domain matches the expected university or brand domain
            # For UIC: display contains uic but domain is not uic.edu
            sender_domain = addr_lower.split('@')[-1] if '@' in addr_lower else ''
            if 'uic' in display_name_lower and sender_domain != 'uic.edu':
                features['display_brand_mismatch'] = 1.0
            # General public domain check for other brands
            elif sender_domain in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'protonmail.com']:
                features['display_brand_mismatch'] = 1.0
                
        # 2. Reply-To Mismatch
        # Parse Reply-To header manually if present
        reply_to = ''
        for line in raw_content.split('\n'):
            if line.lower().startswith('reply-to:'):
                reply_to = line.split(':', 1)[1].strip()
                break
                
        if reply_to:
            _, reply_addr = parseaddr(reply_to)
            from_domain = addr_lower.split('@')[-1] if '@' in addr_lower else ''
            reply_domain = reply_addr.lower().split('@')[-1] if '@' in reply_addr else ''
            if from_domain and reply_domain and from_domain != reply_domain:
                # Exclude standard public email providers from mismatch if they both use them
                public_providers = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'}
                if not (from_domain in public_providers and reply_domain in public_providers):
                    features['reply_to_mismatch'] = 1.0
                    
        # 3. Origin Network Anomaly (Nigeria / VPN / Hosting checks)
        origin_data = EmailFeatureExtractor.get_email_origin(raw_content)
        if origin_data:
            ip = origin_data.get('ip')
            is_vpn = origin_data.get('is_vpn', False)
            is_hosting = origin_data.get('is_hosting', False)
            if is_vpn or is_hosting or (ip and is_nigerian_ip(ip)):
                features['origin_network_anomaly'] = 1.0
                
        # 4. Subject Urgency Keyphrase Check
        subject = parsed_email.get('subject', '').lower()
        urgency_regex = re.compile(
            r'\b(urgent|action required|immediate|suspended|suspicious activity|security alert|verify your account|final notice)\b'
        )
        if urgency_regex.search(subject):
            features['suspicious_subject_urgency'] = 1.0
            
        return features

    @staticmethod
    def get_email_origin(raw_content):
        """
        Parses Received headers from bottom to top to identify the originating client IP.
        Resolves its location using offline/online lookup.
        """
        # Find the header block
        parts = re.split(r'\n\s*\n', raw_content, maxsplit=1)
        headers = parts[0] if parts else raw_content
        
        # Unfold multiline headers
        unfolded_headers = re.sub(r'\r?\n\s+', ' ', headers)
        lines = unfolded_headers.split('\n')
        
        received_headers = []
        for line in lines:
            if line.lower().startswith('received:'):
                received_headers.append(line)
                
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        origin_ip = None
        
        # Traverse oldest hop to newest
        for header in reversed(received_headers):
            found_ips = ip_pattern.findall(header)
            for ip_str in found_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if not (ip.is_private or ip.is_loopback):
                        origin_ip = ip_str
                        break
                except Exception:
                    pass
            if origin_ip:
                break
                
        # Fall back to any public IP found in headers if none in Received
        if not origin_ip:
            all_ips = EmailFeatureExtractor.extract_ips_from_headers(raw_content)
            for ip_str in all_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if not (ip.is_private or ip.is_loopback):
                        origin_ip = ip_str
                        break
                except Exception:
                    pass
                    
        if not origin_ip:
            return {
                "ip": "Unknown / Internal Origin",
                "location": "Local Private Network",
                "is_vpn": False,
                "is_hosting": False,
                "isp": "Local Relay"
            }
            
        return get_ip_details(origin_ip)
