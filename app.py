from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

HEADER_CHECKS = {
    'Content-Security-Policy': {
        'recommended': "default-src 'self'",
        'severity': 'high'
    },
    'Strict-Transport-Security': {
        'recommended': "max-age=31536000; includeSubDomains",
        'severity': 'high'
    },
    'X-Content-Type-Options': {
        'recommended': "nosniff",
        'severity': 'medium'
    },
    'X-Frame-Options': {
        'recommended': "DENY",
        'severity': 'medium'
    },
    'X-XSS-Protection': {
        'recommended': "1; mode=block",
        'severity': 'medium'
    },
    'Referrer-Policy': {
        'recommended': "no-referrer-when-downgrade",
        'severity': 'low'
    }
}

def validate_url(url):
    """Ensure URL has a valid scheme and format"""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    if not parsed.netloc:
        raise ValueError("Invalid URL format")
    return url

def analyze_headers(url):
    """Fetch headers and analyze security"""
    try:
        # Use HEAD first for efficiency, fallback to GET if needed
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)
        except requests.exceptions.ConnectionError:
            response = requests.get(url, timeout=10, allow_redirects=True)

        # Convert headers to lowercase for case-insensitive comparison
        headers = {k.lower(): v for k, v in response.headers.items()}
        print(f"\n[DEBUG] Headers received ({url}):")
        for k, v in headers.items():
            print(f"{k}: {v}")

        results = []
        
        for header, config in HEADER_CHECKS.items():
            header_lower = header.lower()
            header_value = headers.get(header_lower, '')
            status = '✅' if header_value else '❌'

            # Special validations
            if header_value:
                if header == 'Strict-Transport-Security':
                    if 'max-age=0' in header_value:
                        status = '⚠️ (HSTS Disabled)'
                    elif 'max-age' not in header_value:
                        status = '⚠️ (Missing max-age)'
                        
                if header == 'Content-Security-Policy' and "'unsafe-inline'" in header_value:
                    status = '⚠️ (Unsafe CSP)'

            results.append({
                'header': header,
                'status': status,
                'value': header_value or 'Not found',
                'recommended': config['recommended'],
                'severity': config['severity']
            })

        return {'success': True, 'results': results}
    
    except Exception as e:
        print(f"\n[ERROR] Analysis failed: {str(e)}")
        return {'success': False, 'error': f"Failed to analyze headers: {str(e)}"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return render_template('error.html', error="No URL provided")
    
    try:
        validated_url = validate_url(url)
        analysis = analyze_headers(validated_url)
        
        if analysis['success']:
            return render_template('results.html', 
                                url=validated_url,
                                results=analysis['results'])
        else:
            return render_template('error.html', error=analysis.get('error', 'Unknown error'))
            
    except Exception as e:
        return render_template('error.html', error=str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
