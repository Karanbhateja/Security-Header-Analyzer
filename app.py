# app.py
from flask import Flask, render_template, request, jsonify
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# Security headers to check with their recommended values
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
    return url

def analyze_headers(url):
    """Fetch headers and analyze security"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        results = []
        
        for header, config in HEADER_CHECKS.items():
            header_value = response.headers.get(header, '')
            status = '✅' if header_value else '❌'
            
            if header_value:
                if header == 'Strict-Transport-Security' and 'max-age=0' in header_value:
                    status = '⚠️'
                    
            results.append({
                'header': header,
                'status': status,
                'value': header_value or 'Not found',
                'recommended': config['recommended'],
                'severity': config['severity']
            })
            
        return {'success': True, 'results': results}
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        validated_url = validate_url(url)
        analysis = analyze_headers(validated_url)
        return render_template('results.html', 
                             url=validated_url,
                             results=analysis['results'])
    except Exception as e:
        return render_template('error.html', error=str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
