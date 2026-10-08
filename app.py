import re
from urllib.parse import urlparse
from flask import Flask, render_template, request

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking', 
    'password', 'credential', 'signin', 'support', 'wallet', 
    'auth', 'token', 'confirm', 'security', 'billing', 'admin'
]

STANDARD_PORTS = {'80', '443', '8080', ''}

def analyze_url(url_string):
    if not url_string:
        return None
        
    url_cleaned = url_string.strip()
    
    # Auto-prepend http if scheme is missing
    if not re.match(r'^[a-zA-Z]+://', url_cleaned):
        url_cleaned = 'http://' + url_cleaned

    try:
        parsed = urlparse(url_cleaned)
    except Exception:
        return {'error': 'Invalid URL format.', 'url': url_string}

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ''
    port = str(parsed.port) if parsed.port else ''
    path = parsed.path.lower()

    # --- NEW: VALIDATION CHECK ---
    # Ensure it's either a valid IPv4 address or has a valid domain/TLD structure
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = bool(re.match(ip_pattern, hostname))
    
    valid_domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    is_domain = bool(re.match(valid_domain_pattern, hostname))

    if not is_ip and not is_domain:
        return {
            'error': f'"{url_string}" is not a valid domain name or IP address.',
            'url': url_string
        }
    # -----------------------------

    checks = []
    indicators = []
    risk_points = 0

    # 1. HTTPS Encryption
    if scheme == 'https':
        checks.append({
            'title': 'HTTPS Encryption',
            'status': 'Good',
            'detail': 'URL uses secure HTTPS encryption.'
        })
    else:
        risk_points += 25
        indicators.append('URL does not use HTTPS')
        checks.append({
            'title': 'HTTPS Encryption',
            'status': 'Warning',
            'detail': 'URL does not use HTTPS.'
        })

    # 2. IP Address as Hostname
    if is_ip:
        risk_points += 25
        indicators.append('Hostname is an IP address instead of a domain name')
        checks.append({
            'title': 'IP Address',
            'status': 'Warning',
            'detail': f'Uses raw IP address ({hostname}).'
        })
    else:
        checks.append({
            'title': 'IP Address',
            'status': 'Good',
            'detail': 'URL uses a domain name.'
        })

    # 3. @ Symbol check
    if '@' in url_cleaned:
        risk_points += 15
        indicators.append('URL contains "@" symbol (potential spoofing)')
        checks.append({
            'title': '@ Symbol',
            'status': 'Warning',
            'detail': 'Found @ symbol, which can mask the true destination.'
        })
    else:
        checks.append({
            'title': '@ Symbol',
            'status': 'Good',
            'detail': 'No @ symbol detected.'
        })

    # 4. URL Length
    if len(url_cleaned) > 75:
        risk_points += 10
        indicators.append('URL is abnormally long (>75 characters)')
        checks.append({
            'title': 'URL Length',
            'status': 'Warning',
            'detail': f'URL length ({len(url_cleaned)}) is unusually long.'
        })
    else:
        checks.append({
            'title': 'URL Length',
            'status': 'Good',
            'detail': 'URL length appears normal.'
        })

    # 5. Suspicious Keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (path + ' ' + hostname)]
    if found_keywords:
        risk_points += 20
        indicators.append(f'Contains suspicious keywords: {", ".join(found_keywords)}')
        checks.append({
            'title': 'Suspicious Keywords',
            'status': 'Warning',
            'detail': f'Found: {", ".join(found_keywords)}'
        })
    else:
        checks.append({
            'title': 'Suspicious Keywords',
            'status': 'Good',
            'detail': 'No suspicious keywords detected.'
        })

    # 6. Subdomain Count
    subdomains = hostname.split('.')
    if len(subdomains) > 3 and not is_ip:
        risk_points += 10
        indicators.append('URL contains excessive subdomains')
        checks.append({
            'title': 'Subdomains',
            'status': 'Warning',
            'detail': 'High number of subdomains detected.'
        })
    else:
        checks.append({
            'title': 'Subdomains',
            'status': 'Good',
            'detail': 'Normal number of subdomains.'
        })

    # 7. Domain Hyphens
    if hostname.count('-') > 1:
        risk_points += 10
        indicators.append('Domain contains multiple hyphens')
        checks.append({
            'title': 'Domain Hyphens',
            'status': 'Warning',
            'detail': 'High count of hyphens detected in domain.'
        })
    else:
        checks.append({
            'title': 'Domain Hyphens',
            'status': 'Good',
            'detail': 'No unusual number of hyphens.'
        })

    # 8. Encoded Characters
    encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url_cleaned))
    if encoded_count > 2:
        risk_points += 10
        indicators.append('URL contains multiple hex-encoded characters')
        checks.append({
            'title': 'Encoded Characters',
            'status': 'Warning',
            'detail': f'Detected {encoded_count} encoded character sequences.'
        })
    else:
        checks.append({
            'title': 'Encoded Characters',
            'status': 'Good',
            'detail': 'No encoded characters detected.'
        })

    # 9. Network Port
    if port and port not in STANDARD_PORTS:
        risk_points += 15
        indicators.append(f'URL uses an uncommon port: {port}')
        checks.append({
            'title': 'Network Port',
            'status': 'Warning',
            'detail': f'Uncommon port detected: {port}.'
        })
    else:
        checks.append({
            'title': 'Network Port',
            'status': 'Good',
            'detail': 'Standard network port.'
        })

    # 10. Domain Format
    # (Since we validated earlier, this will mostly act as a secondary sanity check)
    if not is_ip and not is_domain:
        risk_points += 10
        indicators.append('Non-standard domain structure')
        checks.append({
            'title': 'Domain Format',
            'status': 'Warning',
            'detail': 'Domain does not follow standard format.'
        })
    else:
        checks.append({
            'title': 'Domain Format',
            'status': 'Good',
            'detail': 'Domain has a standard format.'
        })

    # Risk score calculation
    risk_score = min(100, int((risk_points / 140) * 100))

    if risk_score >= 60:
        verdict = 'Phishing Threat'
        verdict_class = 'danger'
    elif risk_score >= 20:
        verdict = 'Suspicious'
        verdict_class = 'warning'
    else:
        verdict = 'Likely Safe'
        verdict_class = 'safe'

    return {
        'url': url_string,
        'risk_score': risk_score,
        'verdict': verdict,
        'verdict_class': verdict_class,
        'indicators': indicators,
        'checks': checks
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url_input = ''
    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        if url_input:
            result = analyze_url(url_input)
    return render_template('index.html', result=result, url_input=url_input)

if __name__ == '__main__':
    app.run(debug=True, port=5000)