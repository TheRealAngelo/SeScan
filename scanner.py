import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import warnings

# Suppress InsecureRequestWarning
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = {
            'xss': [],
            'sqli': [],
            'header_issues': [],
            'open_redirects': []
        }

    def scan(self):
        """Main scanning method that calls other specialized scan methods"""
        try:
            print(f"[*] Starting scan on {self.url}")
            response = self.session.get(self.url, headers=self.headers, verify=False, timeout=10)
            
            # Check security headers
            self.check_security_headers(response)
            
            # Get all forms for XSS and SQLi testing
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                self.check_xss_vulnerability(form)
                self.check_sqli_vulnerability(form)
            
            # Check for open redirects
            self.check_open_redirects()
            
            return self.results
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Error scanning {self.url}: {e}")
            return self.results

    def check_security_headers(self, response):
        """Check for missing or misconfigured security headers"""
        headers = response.headers
        
        # List of important security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-XSS-Protection': 'Missing XSS Protection header'
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                self.results['header_issues'].append(message)
        
        # Check for insecure cookies
        if 'Set-Cookie' in headers:
            if 'secure' not in headers['Set-Cookie'].lower() or 'httponly' not in headers['Set-Cookie'].lower():
                self.results['header_issues'].append('Insecure cookie configuration')

    def check_xss_vulnerability(self, form):
        """Basic XSS check for forms"""
        action = form.get('action', '')
        if not action:
            action = self.url
        else:
            action = urljoin(self.url, action)
            
        method = form.get('method', 'get').lower()
        
        # Get all input fields
        inputs = form.find_all('input')
        data = {}
        
        # XSS test payloads
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>'
        ]
        
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', '').lower()
            
            if input_name and input_type != 'submit':
                # Test each input field with XSS payloads
                for payload in xss_payloads:
                    data[input_name] = payload
                    
                    try:
                        if method == 'post':
                            response = self.session.post(action, data=data, headers=self.headers, timeout=10)
                        else:
                            response = self.session.get(action, params=data, headers=self.headers, timeout=10)
                        
                        # Check if payload is reflected in the response
                        if payload in response.text:
                            self.results['xss'].append(f"Possible XSS in {input_name} parameter via {method.upper()} to {action}")
                            break
                    except:
                        continue

    def check_sqli_vulnerability(self, form):
        """Basic SQLi check for forms"""
        action = form.get('action', '')
        if not action:
            action = self.url
        else:
            action = urljoin(self.url, action)
            
        method = form.get('method', 'get').lower()
        
        # Get all input fields
        inputs = form.find_all('input')
        data = {}
        
        # SQLi test payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin'--"
        ]
        
        sqli_errors = [
            "SQL syntax",
            "mysql_fetch_array",
            "sqlite_query",
            "ORA-01756",
            "error in your SQL syntax"
        ]
        
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', '').lower()
            
            if input_name and input_type != 'submit':
                # Test each input field with SQLi payloads
                for payload in sqli_payloads:
                    data[input_name] = payload
                    
                    try:
                        if method == 'post':
                            response = self.session.post(action, data=data, headers=self.headers, timeout=10)
                        else:
                            response = self.session.get(action, params=data, headers=self.headers, timeout=10)
                        
                        # Check for SQL error messages
                        for error in sqli_errors:
                            if error.lower() in response.text.lower():
                                self.results['sqli'].append(f"Possible SQLi in {input_name} parameter via {method.upper()} to {action}")
                                break
                    except:
                        continue

    def check_open_redirects(self):
        """Check for open redirect vulnerabilities"""
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        redirect_params = ['redirect', 'url', 'next', 'redir', 'return', 'target', 'destination', 'go']
        test_payload = 'https://example.com'
        
        for param in redirect_params:
            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{param}={test_payload}"
            
            try:
                response = self.session.get(test_url, headers=self.headers, allow_redirects=False, timeout=10)
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if test_payload in location or (location.startswith('/') is False and base_url not in location):
                        self.results['open_redirects'].append(f"Possible open redirect via {param} parameter")
            except:
                continue