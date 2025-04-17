import requests
import re
import sqlite3
import os
import logging
import json
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_tests')

class SecurityTester:
    """Class for performing security tests on the application"""
    
    def __init__(self, base_url, admin_username, admin_password):
        """
        Initialize the security tester.
        
        Args:
            base_url: Base URL of the application
            admin_username: Admin username for authentication
            admin_password: Admin password for authentication
        """
        self.base_url = base_url
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.session = requests.Session()
        self.csrf_token = None
        self.api_key = None
        self.test_results = {
            "xss": [],
            "csrf": [],
            "sql_injection": [],
            "authentication": [],
            "authorization": [],
            "password_security": [],
            "totp_security": [],
            "api_security": [],
            "summary": {
                "passed": 0,
                "failed": 0,
                "warnings": 0
            }
        }
    
    def _login(self):
        """
        Log in to the application.
        
        Returns:
            bool: True if login successful, False otherwise
        """
        try:
            # Get login page to extract CSRF token
            response = self.session.get(urljoin(self.base_url, '/auth/login'))
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find CSRF token
            csrf_input = soup.find('input', {'name': 'csrf_token'})
            if not csrf_input:
                logger.error("CSRF token not found on login page")
                self._add_result("csrf", "CSRF token missing from login form", "failed")
                return False
            
            csrf_token = csrf_input.get('value')
            self.csrf_token = csrf_token
            
            # Perform login
            login_data = {
                'csrf_token': csrf_token,
                'username': self.admin_username,
                'password': self.admin_password,
                'remember': 'y'
            }
            
            response = self.session.post(
                urljoin(self.base_url, '/auth/login'),
                data=login_data,
                allow_redirects=True
            )
            
            # Check if login was successful
            if 'Dashboard' in response.text:
                logger.info("Login successful")
                return True
            else:
                logger.error("Login failed")
                return False
        
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def _create_api_key(self):
        """
        Create an API key for testing.
        
        Returns:
            str: API key or None if failed
        """
        try:
            # Ensure we're logged in
            if not self._login():
                return None
            
            # Create a random API key name
            key_name = f"security_test_{int(time.time())}"
            
            # Create API key
            response = self.session.post(
                urljoin(self.base_url, '/api/keys'),
                json={
                    'name': key_name,
                    'description': 'Automatically created for security testing'
                }
            )
            
            if response.status_code == 201:
                data = response.json()
                self.api_key = data.get('key')
                logger.info(f"Created API key: {key_name}")
                return self.api_key
            else:
                logger.error(f"Failed to create API key: {response.text}")
                return None
        
        except Exception as e:
            logger.error(f"API key creation error: {e}")
            return None
    
    def _delete_api_key(self):
        """Delete the API key created for testing"""
        if not self.api_key:
            return
        
        try:
            # Get all API keys to find the ID of our key
            response = self.session.get(urljoin(self.base_url, '/api/keys'))
            
            if response.status_code == 200:
                keys = response.json()
                for key in keys:
                    if key.get('key') == self.api_key:
                        key_id = key.get('id')
                        
                        # Delete the key
                        delete_response = self.session.delete(
                            urljoin(self.base_url, f'/api/keys/{key_id}')
                        )
                        
                        if delete_response.status_code == 200:
                            logger.info(f"Deleted API key ID: {key_id}")
                        else:
                            logger.error(f"Failed to delete API key: {delete_response.text}")
                        
                        break
        except Exception as e:
            logger.error(f"API key deletion error: {e}")
    
    def _add_result(self, category, message, status, details=None):
        """
        Add a test result.
        
        Args:
            category: Test category
            message: Test message
            status: Test status (passed, failed, warning)
            details: Additional details
        """
        result = {
            "message": message,
            "status": status,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": details or {}
        }
        
        self.test_results[category].append(result)
        
        # Update summary
        if status == "passed":
            self.test_results["summary"]["passed"] += 1
        elif status == "failed":
            self.test_results["summary"]["failed"] += 1
        elif status == "warning":
            self.test_results["summary"]["warnings"] += 1
    
    def test_xss_vulnerabilities(self):
        """Test for XSS vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("xss", "Login failed, cannot test XSS", "failed")
            return
        
        # XSS payloads to test
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<body onload="alert(\'XSS\')">',
            '"><img src=x onerror=alert("XSS")>'
        ]
        
        # Test user creation form
        try:
            for payload in xss_payloads:
                # Create a user with XSS payload in username
                username = f"test_user_{int(time.time())}_{random.randint(1000, 9999)}"
                
                # Get the user creation form to extract CSRF token
                response = self.session.get(urljoin(self.base_url, '/users/create'))
                soup = BeautifulSoup(response.text, 'html.parser')
                csrf_token = soup.find('input', {'name': 'csrf_token'}).get('value')
                
                # Create user with XSS payload in various fields
                user_data = {
                    'csrf_token': csrf_token,
                    'username': username,
                    'password': 'Password123!',
                    'confirm_password': 'Password123!',
                    'groups': f"users,{payload}"
                }
                
                response = self.session.post(
                    urljoin(self.base_url, '/users/create'),
                    data=user_data,
                    allow_redirects=True
                )
                
                # Check if the XSS payload was reflected without encoding
                if payload in response.text and not re.search(r'&lt;script&gt;', response.text):
                    self._add_result(
                        "xss",
                        f"Potential XSS vulnerability found in user creation form",
                        "failed",
                        {"payload": payload, "field": "groups"}
                    )
                else:
                    self._add_result(
                        "xss",
                        f"XSS payload properly handled in user creation form",
                        "passed",
                        {"payload": payload, "field": "groups"}
                    )
                
                # Clean up - delete the test user
                if "User created successfully" in response.text:
                    delete_response = self.session.post(
                        urljoin(self.base_url, f'/users/delete/{username}'),
                        data={'csrf_token': csrf_token}
                    )
        
        except Exception as e:
            logger.error(f"XSS testing error: {e}")
            self._add_result("xss", f"Error during XSS testing: {str(e)}", "failed")
    
    def test_csrf_protection(self):
        """Test for CSRF vulnerabilities"""
        logger.info("Testing for CSRF vulnerabilities")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("csrf", "Login failed, cannot test CSRF", "failed")
            return
        
        # Test forms for CSRF tokens
        forms_to_test = [
            '/users/create',
            '/clients/create',
            '/admins/create',
            '/profile'
        ]
        
        for form_url in forms_to_test:
            try:
                response = self.session.get(urljoin(self.base_url, form_url))
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check if form has CSRF token
                csrf_input = soup.find('input', {'name': 'csrf_token'})
                
                if not csrf_input:
                    self._add_result(
                        "csrf",
                        f"CSRF token missing from {form_url}",
                        "failed"
                    )
                else:
                    self._add_result(
                        "csrf",
                        f"CSRF token present in {form_url}",
                        "passed"
                    )
                    
                    # Test if form submission without CSRF token is rejected
                    if form_url == '/users/create':
                        # Try to create a user without CSRF token
                        username = f"csrf_test_{int(time.time())}"
                        user_data = {
                            'username': username,
                            'password': 'Password123!',
                            'confirm_password': 'Password123!'
                        }
                        
                        response = self.session.post(
                            urljoin(self.base_url, form_url),
                            data=user_data,
                            allow_redirects=True
                        )
                        
                        # Check if submission was rejected
                        if "CSRF token is missing" in response.text or response.status_code == 400:
                            self._add_result(
                                "csrf",
                                "Form correctly rejected submission without CSRF token",
                                "passed"
                            )
                        else:
                            self._add_result(
                                "csrf",
                                "Form accepted submission without CSRF token",
                                "failed"
                            )
            
            except Exception as e:
                logger.error(f"CSRF testing error for {form_url}: {e}")
                self._add_result("csrf", f"Error during CSRF testing for {form_url}: {str(e)}", "failed")
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        logger.info("Testing for SQL injection vulnerabilities")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("sql_injection", "Login failed, cannot test SQL injection", "failed")
            return
        
        # SQL injection payloads to test
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM admin_users; --",
            "' OR '1'='1' --",
            "admin' --"
        ]
        
        # Test user search functionality
        for payload in sql_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, f'/users/?search={payload}')
                )
                
                # Check for SQL error messages
                sql_error_patterns = [
                    "SQL syntax",
                    "sqlite3.OperationalError",
                    "ORA-",
                    "MySQL",
                    "SQL error",
                    "syntax error"
                ]
                
                has_sql_error = any(pattern.lower() in response.text.lower() for pattern in sql_error_patterns)
                
                if has_sql_error:
                    self._add_result(
                        "sql_injection",
                        "Potential SQL injection vulnerability found in user search",
                        "failed",
                        {"payload": payload}
                    )
                else:
                    self._add_result(
                        "sql_injection",
                        "SQL injection payload properly handled in user search",
                        "passed",
                        {"payload": payload}
                    )
            
            except Exception as e:
                logger.error(f"SQL injection testing error: {e}")
                self._add_result("sql_injection", f"Error during SQL injection testing: {str(e)}", "failed")
    
    def test_authentication(self):
        """Test authentication security"""
        logger.info("Testing authentication security")
        
        # Test login rate limiting
        try:
            # Try multiple rapid login attempts with incorrect password
            for i in range(10):
                response = self.session.post(
                    urljoin(self.base_url, '/auth/login'),
                    data={
                        'username': self.admin_username,
                        'password': 'wrong_password'
                    },
                    allow_redirects=True
                )
            
            # Check if rate limiting is in place
            if "Too many login attempts" in response.text or response.status_code == 429:
                self._add_result(
                    "authentication",
                    "Login rate limiting is properly implemented",
                    "passed"
                )
            else:
                self._add_result(
                    "authentication",
                    "No login rate limiting detected",
                    "warning"
                )
        
        except Exception as e:
            logger.error(f"Authentication testing error: {e}")
            self._add_result("authentication", f"Error during authentication testing: {str(e)}", "failed")
        
        # Test session timeout
        try:
            # Login
            if self._login():
                # Check if session cookie has secure and httponly flags
                cookies = self.session.cookies
                session_cookie = None
                
                for cookie in cookies:
                    if cookie.name.lower().startswith('session'):
                        session_cookie = cookie
                        break
                
                if session_cookie:
                    if not session_cookie.secure:
                        self._add_result(
                            "authentication",
                            "Session cookie does not have Secure flag",
                            "warning"
                        )
                    else:
                        self._add_result(
                            "authentication",
                            "Session cookie has Secure flag",
                            "passed"
                        )
                    
                    if not session_cookie.has_nonstandard_attr('HttpOnly'):
                        self._add_result(
                            "authentication",
                            "Session cookie does not have HttpOnly flag",
                            "warning"
                        )
                    else:
                        self._add_result(
                            "authentication",
                            "Session cookie has HttpOnly flag",
                            "passed"
                        )
                else:
                    self._add_result(
                        "authentication",
                        "Session cookie not found",
                        "warning"
                    )
        
        except Exception as e:
            logger.error(f"Session testing error: {e}")
            self._add_result("authentication", f"Error during session testing: {str(e)}", "failed")
    
    def test_authorization(self):
        """Test authorization controls"""
        logger.info("Testing authorization controls")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("authorization", "Login failed, cannot test authorization", "failed")
            return
        
        # Test access to admin-only pages
        admin_pages = [
            '/admins/',
            '/api-keys'
        ]
        
        for page in admin_pages:
            try:
                response = self.session.get(urljoin(self.base_url, page))
                
                # Admin should have access
                if response.status_code == 200:
                    self._add_result(
                        "authorization",
                        f"Admin user correctly has access to {page}",
                        "passed"
                    )
                else:
                    self._add_result(
                        "authorization",
                        f"Admin user incorrectly denied access to {page}",
                        "failed"
                    )
            
            except Exception as e:
                logger.error(f"Authorization testing error for {page}: {e}")
                self._add_result("authorization", f"Error during authorization testing for {page}: {str(e)}", "failed")
        
        # TODO: Test with non-admin user if available
    
    def test_password_security(self):
        """Test password security"""
        logger.info("Testing password security")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("password_security", "Login failed, cannot test password security", "failed")
            return
        
        # Test password strength requirements
        weak_passwords = [
            "password",
            "123456",
            "qwerty",
            "letmein",
            "admin"
        ]
        
        # Get the user creation form
        response = self.session.get(urljoin(self.base_url, '/users/create'))
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'}).get('value')
        
        for password in weak_passwords:
            try:
                # Try to create a user with weak password
                username = f"pwd_test_{int(time.time())}_{random.randint(1000, 9999)}"
                
                user_data = {
                    'csrf_token': csrf_token,
                    'username': username,
                    'password': password,
                    'confirm_password': password
                }
                
                response = self.session.post(
                    urljoin(self.base_url, '/users/create'),
                    data=user_data,
                    allow_redirects=True
                )
                
                # Check if weak password was rejected
                if "password must be at least" in response.text.lower() or "password is too weak" in response.text.lower():
                    self._add_result(
                        "password_security",
                        f"Weak password '{password}' correctly rejected",
                        "passed"
                    )
                else:
                    self._add_result(
                        "password_security",
                        f"Weak password '{password}' was accepted",
                        "warning"
                    )
                    
                    # Clean up - delete the test user if it was created
                    if "User created successfully" in response.text:
                        delete_response = self.session.post(
                            urljoin(self.base_url, f'/users/delete/{username}'),
                            data={'csrf_token': csrf_token}
                        )
            
            except Exception as e:
                logger.error(f"Password security testing error: {e}")
                self._add_result("password_security", f"Error during password security testing: {str(e)}", "failed")
    
    def test_totp_security(self):
        """Test TOTP security"""
        logger.info("Testing TOTP security")
        
        # Ensure we're logged in
        if not self._login():
            self._add_result("totp_security", "Login failed, cannot test TOTP security", "failed")
            return
        
        # Create a test user with TOTP
        try:
            # Get the user creation form
            response = self.session.get(urljoin(self.base_url, '/users/create'))
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrf_token'}).get('value')
            
            # Create user with TOTP enabled
            username = f"totp_test_{int(time.time())}_{random.randint(1000, 9999)}"
            
            user_data = {
                'csrf_token': csrf_token,
                'username': username,
                'password': 'Password123!',
                'confirm_password': 'Password123!',
                'enable_totp': 'y'
            }
            
            response = self.session.post(
                urljoin(self.base_url, '/users/create'),
                data=user_data,
                allow_redirects=True
            )
            
            # Check if TOTP setup page is displayed
            if '/totp/setup/' in response.url:
                # Extract TOTP secret
                soup = BeautifulSoup(response.text, 'html.parser')
                secret_elem = soup.find('code', {'id': 'totp-secret'})
                
                if secret_elem and secret_elem.text:
                    totp_secret = secret_elem.text.strip()
                    
                    # Check if TOTP secret is properly generated
                    if len(totp_secret) >= 16:
                        self._add_result(
                            "totp_security",
                            "TOTP secret is properly generated with sufficient length",
                            "passed",
                            {"secret_length": len(totp_secret)}
                        )
                    else:
                        self._add_result(
                            "totp_security",
                            "TOTP secret is too short",
                            "warning",
                            {"secret_length": len(totp_secret)}
                        )
                    
                    # Test TOTP verification with invalid token
                    invalid_token = '123456'
                    verify_data = {
                        'csrf_token': csrf_token,
                        'token': invalid_token
                    }
                    
                    verify_response = self.session.post(
                        urljoin(self.base_url, f'/totp/verify/{username}'),
                        data=verify_data,
                        allow_redirects=True
                    )
                    
                    if "Invalid TOTP token" in verify_response.text:
                        self._add_result(
                            "totp_security",
                            "TOTP verification correctly rejects invalid tokens",
                            "passed"
                        )
                    else:
                        self._add_result(
                            "totp_security",
                            "TOTP verification accepted invalid token",
                            "failed"
                        )
                else:
                    self._add_result(
                        "totp_security",
                        "Could not extract TOTP secret from setup page",
                        "failed"
                    )
            else:
                self._add_result(
                    "totp_security",
                    "TOTP setup page not displayed after creating user with TOTP",
                    "failed"
                )
            
            # Clean up - delete the test user
            delete_response = self.session.post(
                urljoin(self.base_url, f'/users/delete/{username}'),
                data={'csrf_token': csrf_token}
            )
        
        except Exception as e:
            logger.error(f"TOTP security testing error: {e}")
            self._add_result("totp_security", f"Error during TOTP security testing: {str(e)}", "failed")
    
    def test_api_security(self):
        """Test API security"""
        logger.info("Testing API security")
        
        # Create an API key for testing
        api_key = self._create_api_key()
        
        if not api_key:
            self._add_result("api_security", "Failed to create API key for testing", "failed")
            return
        
        # Test API endpoints without authentication
        api_endpoints = [
            '/api/users',
            '/api/clients',
            '/api/status',
            '/api/logs/auth'
        ]
        
        for endpoint in api_endpoints:
            try:
                # Test without API key
                response = requests.get(urljoin(self.base_url, endpoint))
                
                if response.status_code in (401, 403):
                    self._add_result(
                        "api_security",
                        f"API endpoint {endpoint} correctly requires authentication",
                        "passed"
                    )
                else:
                    self._add_result(
                        "api_security",
                        f"API endpoint {endpoint} does not require authentication",
                        "failed"
                    )
                
                # Test with API key
                response = requests.get(
                    urljoin(self.base_url, endpoint),
                    headers={'X-API-Key': api_key}
                )
                
                if response.status_code == 200:
                    self._add_result(
                        "api_security",
                        f"API endpoint {endpoint} correctly accepts valid API key",
                        "passed"
                    )
                else:
                    self._add_result(
                        "api_security",
                        f"API endpoint {endpoint} rejects valid API key",
                        "warning",
                        {"status_code": response.status_code}
                    )
            
            except Exception as e:
                logger.error(f"API security testing error for {endpoint}: {e}")
                self._add_result("api_security", f"Error during API security testing for {endpoint}: {str(e)}", "failed")
        
        # Test API rate limiting
        try:
            # Make multiple rapid requests to the API
            for i in range(20):
                response = requests.get(
                    urljoin(self.base_url, '/api/status'),
                    headers={'X-API-Key': api_key}
                )
            
            # Check if rate limiting is in place
            if response.status_code == 429:
                self._add_result(
                    "api_security",
                    "API rate limiting is properly implemented",
                    "passed"
                )
            else:
                self._add_result(
                    "api_security",
                    "No API rate limiting detected",
                    "warning"
                )
        
        except Exception as e:
            logger.error(f"API rate limiting testing error: {e}")
            self._add_result("api_security", f"Error during API rate limiting testing: {str(e)}", "failed")
        
        # Clean up - delete the API key
        self._delete_api_key()
    
    def run_all_tests(self):
        """Run all security tests"""
        logger.info("Starting security tests")
        
        self.test_xss_vulnerabilities()
        self.test_csrf_protection()
        self.test_sql_injection()
        self.test_authentication()
        self.test_authorization()
        self.test_password_security()
        self.test_totp_security()
        self.test_api_security()
        
        logger.info("Security tests completed")
        return self.test_results
    
    def generate_report(self, output_file=None):
        """
        Generate a security test report.
        
        Args:
            output_file: Path to save the report (default: None, returns the report)
        
        Returns:
            str: JSON report if output_file is None, otherwise None
        """
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "base_url": self.base_url,
            "summary": self.test_results["summary"],
            "results": {
                category: results
                for category, results in self.test_results.items()
                if category != "summary"
            }
        }
        
        # Calculate risk score (0-100, lower is better)
        failed_tests = self.test_results["summary"]["failed"]
        warning_tests = self.test_results["summary"]["warnings"]
        passed_tests = self.test_results["summary"]["passed"]
        total_tests = failed_tests + warning_tests + passed_tests
        
        if total_tests > 0:
            risk_score = int((failed_tests * 100 + warning_tests * 30) / total_tests)
        else:
            risk_score = 0
        
        report["risk_score"] = min(100, risk_score)
        
        # Add risk level
        if risk_score < 20:
            report["risk_level"] = "Low"
        elif risk_score < 50:
            report["risk_level"] = "Medium"
        else:
            report["risk_level"] = "High"
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            return None
        
        return json.dumps(report, indent=2)

def run_security_tests(base_url, admin_username, admin_password, output_file=None):
    """
    Run security tests on the application.
    
    Args:
        base_url: Base URL of the application
        admin_username: Admin username for authentication
        admin_password: Admin password for authentication
        output_file: Path to save the report (default: None)
    
    Returns:
        dict: Test results
    """
    tester = SecurityTester(base_url, admin_username, admin_password)
    results = tester.run_all_tests()
    
    if output_file:
        tester.generate_report(output_file)
    
    return results

if __name__ == "__main__":
    # Example usage
    base_url = "http://localhost:8080"
    admin_username = "admin"
    admin_password = "changeme"
    
    results = run_security_tests(base_url, admin_username, admin_password, "security_report.json")
    print(f"Tests completed: {results['summary']['passed']} passed, {results['summary']['failed']} failed, {results['summary']['warnings']} warnings")