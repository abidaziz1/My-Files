"""
SQL Injection Scanner for WebSecScanner
Implements error-based, boolean-based, and time-based detection
"""
import re
import random
import time
from typing import List, Dict, Optional, Tuple
from html import unescape
from difflib import SequenceMatcher

from src.core.scanner_base import ScannerBase, Vulnerability
from src.core.http_client import HTTPClient
from src.payloads.payload_manager import PayloadManager
from src.utils.logger import get_logger

class SQLiScanner(ScannerBase):
    """SQL Injection vulnerability scanner"""
    
    # Database error patterns
    ERROR_PATTERNS = {
        'mysql': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions"
        ],
        'postgresql': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s\ssyntax error at or near"
        ],
        'mssql': [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
            r"Incorrect syntax near"
        ],
        'oracle': [
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"oracle\.jdbc\.driver"
        ],
        'sqlite': [
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]"
        ],
        'generic': [
            r"SQL (syntax|statement)",
            r"database error",
            r"syntax error",
            r"unclosed quotation mark",
            r"quoted string not properly terminated"
        ]
    }
    
    def __init__(self, http_client: HTTPClient):
        super().__init__(http_client)
        self.payload_manager = PayloadManager()
        self.logger = get_logger()
    
    def scan(self, url: str, parameters: Dict[str, str]) -> List[Vulnerability]:
        """
        Main scanning method for SQLi vulnerabilities
        
        Args:
            url: Target URL
            parameters: URL parameters to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info(f"Starting SQL injection scan on {url}")
        self.logger.info(f"Testing parameters: {list(parameters.keys())}")
        
        for param in parameters:
            self.logger.debug(f"Testing parameter: {param}")
            
            # Test 1: Error-based SQLi
            if self._test_error_based(url, param, parameters):
                continue  # Skip other tests if already found
            
            # Test 2: Boolean-based blind SQLi
            if self._test_boolean_based(url, param, parameters):
                continue
            
            # Test 3: Time-based blind SQLi
            self._test_time_based(url, param, parameters)
        
        return self.vulnerabilities
    
    def _test_error_based(self, url: str, param: str, parameters: Dict[str, str]) -> bool:
        """
        Test for error-based SQL injection
        
        Returns:
            True if vulnerability found
        """
        self.logger.debug(f"[{param}] Testing error-based SQLi...")
        
        # Get error-based payloads
        payloads = self.payload_manager.get_error_based_payloads()
        
        for payload in payloads[:15]:  # Test first 15 payloads
            self.scan_count += 1
            
            # Inject payload
            test_params = parameters.copy()
            test_params[param] = payload
            
            # Send request
            response = self.http_client.get(url, params=test_params)
            
            if not response:
                continue
            
            # Check for database errors
            db_type, error_match = self._check_error_patterns(response.text)
            
            if db_type:
                self.logger.info(f"[{param}] Error-based SQLi detected! Database: {db_type}")
                
                # Create vulnerability
                vuln = Vulnerability(
                    vuln_type='sqli',
                    severity='CRITICAL',
                    confidence=0.9,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=error_match[:200],  # First 200 chars of error
                    description=f"Error-based SQL injection vulnerability found in parameter '{param}'. "
                               f"Database type: {db_type}. The application returns database error messages, "
                               f"allowing an attacker to extract sensitive information.",
                    remediation="Use parameterized queries (prepared statements) instead of string concatenation. "
                               "Implement proper input validation and sanitization. Disable detailed error messages in production."
                )
                
                self.add_vulnerability(vuln)
                return True
        
        return False
    
    def _test_boolean_based(self, url: str, param: str, parameters: Dict[str, str]) -> bool:
        """
        Test for boolean-based blind SQL injection
        
        Returns:
            True if vulnerability found
        """
        self.logger.debug(f"[{param}] Testing boolean-based blind SQLi...")
        
        # Get baseline response
        baseline_response = self.http_client.get(url, params=parameters)
        if not baseline_response or baseline_response.status_code != 200:
            return False
        
        baseline_text = baseline_response.text
        baseline_length = len(baseline_text)
        
        # Get boolean payloads
        true_payloads, false_payloads = self.payload_manager.get_boolean_payloads()
        
        # Test payload pairs
        for i in range(min(5, len(true_payloads))):  # Test first 5 pairs
            true_payload = true_payloads[i]
            false_payload = false_payloads[i]
            
            # Test TRUE condition
            test_params_true = parameters.copy()
            test_params_true[param] = parameters[param] + true_payload
            response_true = self.http_client.get(url, params=test_params_true)
            
            if not response_true:
                continue
            
            self.scan_count += 1
            
            # Test FALSE condition
            test_params_false = parameters.copy()
            test_params_false[param] = parameters[param] + false_payload
            response_false = self.http_client.get(url, params=test_params_false)
            
            if not response_false:
                continue
            
            self.scan_count += 1
            
            # Compare responses
            true_similarity = self._calculate_similarity(baseline_text, response_true.text)
            false_similarity = self._calculate_similarity(baseline_text, response_false.text)
            
            # Check length differences
            true_len_diff = abs(len(response_true.text) - baseline_length)
            false_len_diff = abs(len(response_false.text) - baseline_length)
            
            # Vulnerability criteria:
            # TRUE response is similar to baseline
            # FALSE response is significantly different
            if true_similarity > 0.85 and false_similarity < 0.70:
                self.logger.info(f"[{param}] Boolean-based blind SQLi detected!")
                
                confidence = self.calculate_confidence({
                    'behavior_change': True,
                    'multiple_confirmations': True
                })
                
                vuln = Vulnerability(
                    vuln_type='sqli_blind',
                    severity=self.classify_severity(confidence, 'sqli_blind'),
                    confidence=confidence,
                    url=url,
                    parameter=param,
                    payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                    evidence=f"TRUE similarity: {true_similarity:.2f}, FALSE similarity: {false_similarity:.2f}",
                    description=f"Boolean-based blind SQL injection vulnerability found in parameter '{param}'. "
                               f"The application's behavior changes based on TRUE/FALSE SQL conditions, "
                               f"allowing an attacker to extract data character by character.",
                    remediation="Use parameterized queries (prepared statements). Implement proper input validation. "
                               "Ensure error messages don't reveal database structure."
                )
                
                self.add_vulnerability(vuln)
                return True
        
        return False
    
    def _test_time_based(self, url: str, param: str, parameters: Dict[str, str]) -> bool:
        """
        Test for time-based blind SQL injection
        
        Returns:
            True if vulnerability found
        """
        self.logger.debug(f"[{param}] Testing time-based blind SQLi...")
        
        # Measure baseline response time (3 requests average)
        baseline_times = []
        for _ in range(3):
            start = time.time()
            response = self.http_client.get(url, params=parameters)
            if response:
                baseline_times.append(time.time() - start)
        
        if not baseline_times:
            return False
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        self.logger.debug(f"[{param}] Baseline response time: {avg_baseline:.2f}s")
        
        # Get time-based payloads (5 second delay)
        time_payloads = self.payload_manager.get_all_time_payloads(delay=5)
        
        # Test payloads
        for payload in time_payloads[:8]:  # Test first 8 payloads
            self.scan_count += 1
            
            # Inject payload
            test_params = parameters.copy()
            test_params[param] = parameters[param] + payload
            
            # Measure response time
            start = time.time()
            response = self.http_client.get(url, params=test_params, timeout=15)
            elapsed = time.time() - start
            
            if not response:
                continue
            
            # Check if delay occurred
            expected_delay = 5.0
            delay_threshold = avg_baseline + expected_delay - 0.5  # Allow 0.5s margin
            
            if elapsed >= delay_threshold:
                self.logger.info(f"[{param}] Time-based blind SQLi detected! Delay: {elapsed:.2f}s")
                
                # Verify with second payload (different delay)
                verify_payloads = self.payload_manager.get_all_time_payloads(delay=7)
                if verify_payloads:
                    test_params[param] = parameters[param] + verify_payloads[0]
                    start = time.time()
                    response = self.http_client.get(url, params=test_params, timeout=15)
                    elapsed_verify = time.time() - start
                    
                    if elapsed_verify >= (avg_baseline + 6.5):  # 7s delay with margin
                        verified = True
                    else:
                        verified = False
                else:
                    verified = False
                
                confidence = self.calculate_confidence({
                    'timing_delay': True,
                    'verified_execution': verified
                })
                
                vuln = Vulnerability(
                    vuln_type='sqli_blind',
                    severity=self.classify_severity(confidence, 'sqli_blind'),
                    confidence=confidence,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response time: {elapsed:.2f}s (baseline: {avg_baseline:.2f}s, delay: {elapsed - avg_baseline:.2f}s)",
                    description=f"Time-based blind SQL injection vulnerability found in parameter '{param}'. "
                               f"The application delays its response based on injected SQL time delays, "
                               f"allowing an attacker to extract data through timing attacks.",
                    remediation="Use parameterized queries (prepared statements). Implement strict input validation. "
                               "Consider using a Web Application Firewall (WAF)."
                )
                
                self.add_vulnerability(vuln)
                return True
        
        return False
    
    def _check_error_patterns(self, response_text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Check response for database error patterns
        
        Returns:
            Tuple of (database_type, error_match) or (None, None)
        """
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        
        return None, None
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        return SequenceMatcher(None, text1, text2).ratio()
