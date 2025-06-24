from flask import Flask, render_template, request, jsonify
from scanner import VulnerabilityScanner
import threading
import os

app = Flask(__name__)

# Ensure templates directory exists
os.makedirs('templates', exist_ok=True)
# Ensure static directory exists
os.makedirs(os.path.join('static', 'css'), exist_ok=True)
os.makedirs(os.path.join('static', 'js'), exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    scanner = VulnerabilityScanner(url)
    results = scanner.scan()
    
    return jsonify({
        'results': results,
        'url': url
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)