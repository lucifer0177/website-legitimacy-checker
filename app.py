from flask import Flask, render_template, request, redirect, url_for, flash
import validators
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session and flash messages

# Home route - URL input form
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Analyze route - process URL and show results
@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '').strip()
    if not url:
        flash('Please enter a URL.', 'error')
        return redirect(url_for('index'))
    if not validators.url(url):
        flash('Invalid URL format. Please enter a valid URL.', 'error')
        return redirect(url_for('index'))

    # For demonstration, simple AI analysis placeholder
    # In real app, integrate reputable APIs here
    analysis_result = perform_analysis(url)

    return render_template('result.html', url=url, analysis=analysis_result)

import os
import requests
from urllib.parse import urlparse

def perform_analysis(url):
    """
    Perform real analysis of website legitimacy and risk using external APIs.
    Requires environment variables:
    - GOOGLE_SAFE_BROWSING_API_KEY
    - VIRUSTOTAL_API_KEY
    """
    google_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    analysis = {
        'legitimacy': 'Unknown',
        'risk_score': None,
        'details': {},
        'recommendation': ''
    }

    # Google Safe Browsing API check
    if google_api_key:
        safe_browsing_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}'
        payload = {
            "client": {
                "clientId": "website-legitimacy-checker",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        try:
            response = requests.post(safe_browsing_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if 'matches' in data:
                    analysis['details']['google_safe_browsing'] = 'Unsafe - Threats found'
                    analysis['risk_score'] = 90
                    analysis['legitimacy'] = 'Unsafe'
                    analysis['recommendation'] = 'The website is flagged as unsafe by Google Safe Browsing.'
                else:
                    analysis['details']['google_safe_browsing'] = 'No threats found'
            else:
                analysis['details']['google_safe_browsing'] = f'API error: {response.status_code}'
        except Exception as e:
            analysis['details']['google_safe_browsing'] = f'Error: {str(e)}'
    else:
        analysis['details']['google_safe_browsing'] = 'API key not configured'

    # VirusTotal URL scan
    if virustotal_api_key:
        vt_url = 'https://www.virustotal.com/api/v3/urls'
        headers = {
            'x-apikey': virustotal_api_key
        }
        try:
            # VirusTotal requires URL to be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            vt_report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            vt_response = requests.get(vt_report_url, headers=headers)
            if vt_response.status_code == 200:
                vt_data = vt_response.json()
                stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                total = sum(stats.values()) if stats else 0

                analysis['details']['virustotal'] = {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'harmless': harmless,
                    'total_scans': total
                }

                if malicious > 0 or suspicious > 0:
                    analysis['risk_score'] = max(analysis.get('risk_score', 0), 80)
                    analysis['legitimacy'] = 'Unsafe'
                    analysis['recommendation'] = 'The website is flagged as malicious or suspicious by VirusTotal.'
                else:
                    if analysis['legitimacy'] != 'Unsafe':
                        analysis['legitimacy'] = 'Likely Legitimate'
                        analysis['recommendation'] = 'No malicious or suspicious activity detected by VirusTotal.'
            else:
                analysis['details']['virustotal'] = f'API error: {vt_response.status_code}'
        except Exception as e:
            analysis['details']['virustotal'] = f'Error: {str(e)}'
    else:
        analysis['details']['virustotal'] = 'API key not configured'

    # Additional checks (e.g., SSL certificate, domain age) can be added here
    # For SSL check, we can try to connect via HTTPS and verify certificate
    import ssl
    import socket
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                analysis['details']['ssl_certificate'] = True
    except Exception:
        analysis['details']['ssl_certificate'] = False

    # Domain age check using whois (optional, requires python-whois package)
    try:
        import whois
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        from datetime import datetime
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            analysis['details']['domain_age_days'] = age_days
            if age_days < 180:
                analysis['risk_score'] = max(analysis.get('risk_score', 0), 70)
                analysis['legitimacy'] = 'Suspicious'
                analysis['recommendation'] += ' The domain is relatively new, which can be a risk factor.'
        else:
            analysis['details']['domain_age_days'] = 'Unknown'
    except ImportError:
        analysis['details']['domain_age_days'] = 'whois package not installed'
    except Exception as e:
        analysis['details']['domain_age_days'] = f'Error: {str(e)}'

    # Set default risk score if not set
    if analysis['risk_score'] is None:
        analysis['risk_score'] = 10
        if analysis['legitimacy'] == 'Unknown':
            analysis['legitimacy'] = 'Likely Legitimate'
            analysis['recommendation'] = 'No significant risks detected.'

    return analysis

if __name__ == '__main__':
    app.run(debug=True, port=8080)
