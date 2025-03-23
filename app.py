# app.py (updated)
from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

HEADER_CHECKS = { 
    # ... [keep existing HEADER_CHECKS configuration] ...
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
        response = requests.get(url, timeout=10, allow_redirects=True)
        results = []
        
        for header, config in HEADER_CHECKS.items():
            # Case-insensitive header check
            header_value = response.headers.get(header, '') or response.headers.get(header.lower(), '')
            status = '✅' if header_value else '❌'
            
            # Special case checks
            if header_value:
                if header == 'Strict-Transport-Security':
                    if 'max-age=0' in header_value:
                        status = '⚠️ (HSTS Disabled)'
                    elif 'max-age' not in header_value:
                        status = '⚠️ (Missing max-age)'
                        
                if header == 'Content-Security-Policy' and "'unsafe-inline'" in header_value:
                    status = '⚠️ (Contains unsafe-inline)'
            
            results.append({
                'header': header,
                'status': status,
                'value': header_value if header_value else 'Not found',
                'recommended': config['recommended'],
                'severity': config['severity']
            })
            
        return {'success': True, 'results': results}
    
    except Exception as e:
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
