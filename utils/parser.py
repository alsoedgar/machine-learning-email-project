import re
import email
import email.header
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

def sanitize_input(input_text):
    # Remove any HTML tags
    sanitized_text = re.sub(r'<[^>]+>', '', input_text)
    # Remove special characters
    sanitized_text = re.sub(r'[^\w\s]', '', sanitized_text)
    return sanitized_text

class EmailParser:
    """Parses raw email headers, text/HTML content, attachments, and links."""
    @staticmethod
    def parse_raw_email(raw_content):
        """
        Parses a raw email string or .eml content.
        Returns a dictionary with parsed elements.
        """
        msg = email.message_from_string(raw_content)
        
        subject = msg.get('Subject', '')
        # Decode subject if needed
        decoded_subject = ""
        for part, encoding in email.header.decode_header(subject):
            if isinstance(part, bytes):
                decoded_subject += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                decoded_subject += part
        
        sender = msg.get('From', '')
        recipient = msg.get('To', '')
        date = msg.get('Date', '')
        
        body_text = ""
        body_html = ""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get_content_disposition()
                
                # Attachment
                if content_disposition == 'attachment' or part.get_filename():
                    filename = part.get_filename()
                    if filename:
                        # Decode filename
                        decoded_filename = ""
                        for fn_part, encoding in email.header.decode_header(filename):
                            if isinstance(fn_part, bytes):
                                decoded_filename += fn_part.decode(encoding or 'utf-8', errors='ignore')
                            else:
                                decoded_filename += fn_part
                    else:
                        decoded_filename = f"attachment_{len(attachments) + 1}"
                    
                    payload = part.get_payload(decode=True)
                    if payload:
                        sha256 = hashlib.sha256(payload).hexdigest()
                        size = len(payload)
                        attachments.append({
                            'filename': decoded_filename,
                            'sha256': sha256,
                            'size': size
                        })
                # Inline / Embedded Images
                elif content_type.startswith('image/'):
                    payload = part.get_payload(decode=True)
                    if payload:
                        cid = part.get('Content-ID')
                        if cid:
                            # Strip brackets: <image_cid> -> image_cid
                            cid = cid.strip('<>')
                        filename = part.get_filename() or f"inline_image_{len(attachments) + 1}"
                        sha256 = hashlib.sha256(payload).hexdigest()
                        size = len(payload)
                        
                        # Store base64 data URI to inline load the image safely in the preview
                        b64_content = base64.b64encode(payload).decode('utf-8')
                        data_uri = f"data:{content_type};base64,{b64_content}"
                        
                        attachments.append({
                            'filename': filename,
                            'sha256': sha256,
                            'size': size,
                            'cid': cid,
                            'data_uri': data_uri
                        })
                # Body texts
                elif content_type == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                elif content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html += payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            if payload:
                if content_type == 'text/html':
                    body_html = payload.decode(charset, errors='ignore')
                elif content_type.startswith('image/'):
                    # Single-part inline image
                    cid = msg.get('Content-ID', '').strip('<>')
                    filename = msg.get_filename() or "inline_image_1"
                    sha256 = hashlib.sha256(payload).hexdigest()
                    b64_content = base64.b64encode(payload).decode('utf-8')
                    data_uri = f"data:{content_type};base64,{b64_content}"
                    attachments.append({
                        'filename': filename,
                        'sha256': sha256,
                        'size': len(payload),
                        'cid': cid,
                        'data_uri': data_uri
                    })
                else:
                    body_text = payload.decode(charset, errors='ignore')
                    
        # Replace Content-ID (cid:...) references in HTML with local base64 Data URIs
        if body_html:
            for att in attachments:
                if 'cid' in att and att['cid'] and 'data_uri' in att:
                    # Match both cid:name and cid:<name>
                    body_html = body_html.replace(f"cid:{att['cid']}", att['data_uri'])
                    body_html = body_html.replace(f"cid:<{att['cid']}>", att['data_uri'])
                    
        # Extract links from text and html
        links = EmailParser.extract_links(body_text, body_html)
        
        return {
            'subject': decoded_subject,
            'from': sender,
            'to': recipient,
            'date': date,
            'body_text': body_text,
            'body_html': body_html,
            'links': links,
            'attachments': attachments
        }
        
    @staticmethod
    def extract_links(body_text, body_html):
        """Extracts URLs and their anchor text if HTML is present."""
        links = []
        seen_urls = set()
        
        # 1. Parse HTML links
        if body_html:
            try:
                soup = BeautifulSoup(body_html, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    url = a_tag['href'].strip()
                    if not url or url.startswith(('javascript:', 'mailto:', '#')):
                        continue
                    if url == "https://aka.ms/LearnAboutSenderIdentification":
                        continue  # Completely ignore automated Microsoft link
                    text = a_tag.get_text().strip()
                    
                    if url not in seen_urls:
                        seen_urls.add(url)
                        links.append({
                            'url': url,
                            'anchor_text': text,
                            'source': 'html'
                        })
            except Exception:
                pass
                
        # 2. Extract plain text URLs using regex (fallback / supplementary)
        text_to_scan = body_text + "\n" + (body_html if not body_html else "")
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        for match in url_pattern.finditer(text_to_scan):
            url = match.group(0).strip()
            if url[-1] in ('.', ',', ';', ')'):
                url = url[:-1]
            if url == "https://aka.ms/LearnAboutSenderIdentification":
                continue  # Completely ignore automated Microsoft link
            if url not in seen_urls:
                seen_urls.add(url)
                links.append({
                    'url': url,
                    'anchor_text': "",
                    'source': 'text'
                })
                
        return links
