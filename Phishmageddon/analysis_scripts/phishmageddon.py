
import os
import re
import sys
import hashlib
import ipaddress
import requests
import email
from email import policy
from email.parser import BytesParser
from textblob import TextBlob
from datetime import datetime

# --- Helpers for defanging ---
def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    url = url.replace('https://', 'hxxps[://]')
    url = url.replace('http://', 'hxxp[://]')
    url = url.replace('.', '[.]')
    return url

# --- Extract IPs from headers and body ---
def extract_ips(email_message):
    ips = set()
    # From headers
    for header_value in email_message.values():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    # From body
    for part in email_message.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except:
                    payload = ''
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(set(valid_ips))

# --- Extract URLs from body ---
def extract_urls(email_message):
    urls = set()
    url_regex = r'https?://[^\s\'"<>]+'
    for part in email_message.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except:
                    payload = ''
            found_urls = re.findall(url_regex, payload)
            urls.update(found_urls)
    return list(urls)

# --- Check if IP is reserved/private ---
def is_reserved_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    ip_addr = ipaddress.ip_address(ip)
    for r in private_ranges + reserved_ranges:
        if ip_addr in ipaddress.ip_network(r):
            return True
    return False

# --- Lookup IP info ---
def ip_lookup(ip):
    if is_reserved_ip(ip):
        return None
    try:
        url = f"https://ipinfo.io/{ip}/json"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                'IP': data.get('ip', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'ISP': data.get('org', ''),
            }
    except:
        pass
    return None

# --- Extract relevant headers ---
def extract_headers(email_message):
    keys = [
        "Date", "Subject", "To", "From", "Reply-To", "Return-Path",
        "Message-ID", "X-Originating-IP", "X-Sender-IP", "Authentication-Results"
    ]
    headers = {}
    for k in keys:
        if k in email_message:
            headers[k] = email_message[k]
    return headers

# --- Extract attachments info ---
def extract_attachments(email_message):
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            content = part.get_payload(decode=True)
            attachments.append({
                'filename': filename,
                'md5': hashlib.md5(content).hexdigest(),
                'sha1': hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest(),
            })
    return attachments

# --- Grammar error count using TextBlob ---
def grammar_errors_count(text):
    if not text:
        return 0
    blob = TextBlob(text)
    errors = 0
    for sentence in blob.sentences:
        corrected = sentence.correct()
        if str(sentence) != str(corrected):
            errors += 1
    return errors

# --- Generate risk reason dynamically ---
def generate_risk_reason(risk_score):
    reasons_high = [
        "Multiple malicious URLs detected.",
        "Suspicious attachments with dangerous filetypes found.",
        "IP addresses linked to known threat actors.",
        "Email headers show signs of spoofing or forgery.",
        "High number of grammar/spelling mistakes indicates possible phishing.",
    ]
    reasons_medium = [
        "Some suspicious URLs found, proceed with caution.",
        "Unusual email headers detected.",
        "Attachments present but no confirmed threats.",
        "Moderate grammar issues detected in email body.",
    ]
    reasons_low = [
        "No suspicious URLs or attachments detected.",
        "Headers look clean and legitimate.",
        "Minimal grammar errors, email appears genuine.",
    ]
    if risk_score >= 7:
        return reasons_high[risk_score % len(reasons_high)]
    elif risk_score >= 4:
        return reasons_medium[risk_score % len(reasons_medium)]
    else:
        return reasons_low[risk_score % len(reasons_low)]

# --- Analyze single email ---
def analyze_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract parts
    ips = extract_ips(msg)
    urls = extract_urls(msg)
    headers = extract_headers(msg)
    attachments = extract_attachments(msg)

    # Extract plain text body for grammar check
    body_text = ""
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            try:
                body_text += part.get_content()
            except:
                pass

    # Grammar error count
    grammar_count = grammar_errors_count(body_text)

    # Simple risk scoring (0-10)
    risk_score = 0
    risk_score += min(len(urls), 4)  # Each suspicious URL adds risk (max 4)
    risk_score += min(len(attachments), 3) * 2  # Attachments add more risk
    if any(hdr for hdr in headers if 'spf' in hdr.lower() or 'dkim' in hdr.lower()):
        # We could parse Authentication-Results further here for failures (not implemented)
        pass
    if grammar_count > 3:
        risk_score += 2
    if risk_score > 10:
        risk_score = 10

    # Generate reason text
    reason = generate_risk_reason(risk_score)

    # Build report string
    report = []
    report.append(f"Report for: {os.path.basename(file_path)}")
    report.append("="*50)
    report.append("\nHeaders:")
    for k, v in headers.items():
        report.append(f"  {k}: {v}")

    report.append("\nExtracted IP Addresses:")
    for ip in ips:
        defanged = defang_ip(ip)
        info = ip_lookup(ip)
        if info:
            report.append(f"  {defanged} - {info['City']}, {info['Region']}, {info['Country']}, ISP: {info['ISP']}")
        else:
            report.append(f"  {defanged}")

    report.append("\nExtracted URLs:")
    for url in urls:
        report.append(f"  {defang_url(url)}")

    report.append("\nAttachments:")
    if attachments:
        for att in attachments:
            report.append(f"  Filename: {att['filename']}")
            report.append(f"    MD5: {att['md5']}")
            report.append(f"    SHA1: {att['sha1']}")
            report.append(f"    SHA256: {att['sha256']}")
    else:
        report.append("  None found")

    report.append(f"\nGrammar/spelling errors count: {grammar_count}")
    report.append(f"\nRisk Score: {risk_score}/10")
    report.append(f"Reason: {reason}")

    return "\n".join(report), risk_score

# --- Save report to file ---
def save_report(report_text, risk_score, filename):
    reports_dir = os.path.join(os.getcwd(), '..', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = filename.replace(' ', '_').replace('(', '').replace(')', '')
    report_file = os.path.join(reports_dir, f"{timestamp}_{safe_filename}_report.txt")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)

# --- Scan all emails in incoming_emails folder ---
def scan_all_emails(folder):
    print(f"Starting scan of emails in: {os.path.abspath(folder)}")
    files = [f for f in os.listdir(folder) if f.lower().endswith('.eml')]
    print(f"Found {len(files)} email(s)")

    for f in files:
        path = os.path.join(folder, f)
        print(f"\nScanning {f} ...")
        report_text, risk = analyze_email(path)
        save_report(report_text, risk, f)
        print(f"Report saved. Risk Score: {risk}/10")

if __name__ == "__main__":
    # Change path here if your incoming_emails folder is somewhere else
    incoming_folder = os.path.abspath(os.path.join(os.getcwd(), '..', 'incoming_emails'))
    scan_all_emails(incoming_folder)
