#!/usr/bin/env python3
"""
Security Testing Script for FreeRADIUS TOTP Management System

This script runs a comprehensive set of security tests on the application
to identify potential vulnerabilities and security issues.
"""

import os
import sys
import argparse
import json
import logging
from datetime import datetime

# Add the parent directory to the path so we can import the app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.security_tests import SecurityTester

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_tests')

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Run security tests on the FreeRADIUS TOTP Management System')
    
    parser.add_argument('--base-url', default='http://localhost:8080',
                        help='Base URL of the application (default: http://localhost:8080)')
    
    parser.add_argument('--admin-username', default='admin',
                        help='Admin username for authentication (default: admin)')
    
    parser.add_argument('--admin-password', default='changeme',
                        help='Admin password for authentication (default: changeme)')
    
    parser.add_argument('--output', default=None,
                        help='Path to save the security report (default: security_report_TIMESTAMP.json)')
    
    parser.add_argument('--tests', default='all',
                        help='Comma-separated list of tests to run (default: all)')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Generate output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'security_report_{timestamp}.json'
    
    # Print test configuration
    logger.info('Starting security tests with the following configuration:')
    logger.info(f'Base URL: {args.base_url}')
    logger.info(f'Admin Username: {args.admin_username}')
    logger.info(f'Output File: {args.output}')
    
    # Create security tester
    tester = SecurityTester(args.base_url, args.admin_username, args.admin_password)
    
    # Determine which tests to run
    if args.tests.lower() == 'all':
        tests_to_run = [
            'xss',
            'csrf',
            'sql_injection',
            'authentication',
            'authorization',
            'password_security',
            'totp_security',
            'api_security'
        ]
    else:
        tests_to_run = [test.strip() for test in args.tests.split(',')]
    
    logger.info(f'Running the following tests: {", ".join(tests_to_run)}')
    
    # Run tests
    for test in tests_to_run:
        logger.info(f'Running {test} tests...')
        
        if test == 'xss':
            tester.test_xss_vulnerabilities()
        elif test == 'csrf':
            tester.test_csrf_protection()
        elif test == 'sql_injection':
            tester.test_sql_injection()
        elif test == 'authentication':
            tester.test_authentication()
        elif test == 'authorization':
            tester.test_authorization()
        elif test == 'password_security':
            tester.test_password_security()
        elif test == 'totp_security':
            tester.test_totp_security()
        elif test == 'api_security':
            tester.test_api_security()
        else:
            logger.warning(f'Unknown test: {test}')
    
    # Generate report
    logger.info('Generating security report...')
    tester.generate_report(args.output)
    
    # Print summary
    summary = tester.test_results['summary']
    logger.info('Security tests completed:')
    logger.info(f'Passed: {summary["passed"]}')
    logger.info(f'Failed: {summary["failed"]}')
    logger.info(f'Warnings: {summary["warnings"]}')
    logger.info(f'Report saved to: {args.output}')
    
    # Return non-zero exit code if any tests failed
    if summary['failed'] > 0:
        logger.error('Some security tests failed!')
        return 1
    
    logger.info('All security tests passed!')
    return 0

if __name__ == '__main__':
    sys.exit(main())