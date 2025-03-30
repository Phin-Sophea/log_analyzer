import re
import os
import argparse
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import ipaddress
import requests
import json
from urllib.parse import unquote
import matplotlib

class SecurityLogAnalyzer:
    def __init__(self):
        self.log_data = []
        self.parsed_data = []
        self.suspicious_activity = []
        self.sqli_attempts = []
        self.ddos_attempts = []
        
    def load_log_file(self, file_path):
        """Load a log file into memory."""
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist.")
            return False
        
        try:
            with open(file_path, 'r') as file:
                self.log_data = file.readlines()
            print(f"Successfully loaded {len(self.log_data)} log entries.")
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def parse_ssh_log(self):
        """Parse Linux authentication log format."""
        parsed_entries = []
        
        pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)')
        
        for line in self.log_data:
            match = pattern.search(line)
            if match:
                timestamp_str, hostname, service, pid, message = match.groups()
                
                # Convert timestamp
                try:
                    current_year = datetime.datetime.now().year
                    timestamp = datetime.datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                except:
                    timestamp = None
                
                entry = {
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'service': service,
                    'pid': pid,
                    'message': message,
                    'raw_log': line.strip()
                }
                
                # Extract IP address
                ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
                ip_match = ip_pattern.search(message)
                entry['ip_address'] = ip_match.group(0) if ip_match else None
                
                # Improved username extraction
                username = None
                # Case 1: Failed password attempts
                failed_pw_match = re.search(r'Failed password for (?:invalid user )?(\S+)', message)
                if failed_pw_match:
                    username = failed_pw_match.group(1)
                
                # Case 2: Invalid user attempts
                invalid_user_match = re.search(r'Invalid user (\S+)', message, re.IGNORECASE)
                if invalid_user_match:
                    username = invalid_user_match.group(1)
                
                # Case 3: pam_unix authentication attempts
                pam_user_match = re.search(r'pam_unix\(.*?:auth\).*?user=(\S+)', message)
                if pam_user_match:
                    username = pam_user_match.group(1)
                
                # Validate username (shouldn't be an IP address or contain special chars)
                if username:
                    # Skip if username looks like an IP address
                    if re.match(r'\d+\.\d+\.\d+\.\d+', username):
                        username = None
                    # Skip if username contains invalid characters
                    elif not re.match(r'^[a-zA-Z0-9_-]+$', username):
                        username = None
                
                entry['username'] = username
                
                parsed_entries.append(entry)
        
        self.parsed_data = parsed_entries
        print(f"Successfully parsed {len(parsed_entries)} entries.")
        return parsed_entries
    
    def parse_apache_log(self):
        """Parse Apache access log format."""
        parsed_entries = []
        
        # Common Apache log format pattern
        # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        pattern = re.compile(r'(\S+) \S+ (\S+) \[([^]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\S+)')
        
        for line in self.log_data:
            match = pattern.search(line)
            if match:
                ip, username, timestamp_str, method, path, protocol, status, size = match.groups()
                
                # Try to convert the timestamp to a datetime object
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                except:
                    timestamp = None
                
                entry = {
                    'ip_address': ip,
                    'username': username if username != '-' else None,
                    'timestamp': timestamp,
                    'method': method,
                    'path': path,
                    'protocol': protocol,
                    'status': int(status),
                    'size': int(size) if size != '-' else 0,
                    'raw_log': line.strip()
                }
                
                # Decode URL for SQL injection detection
                entry['decoded_path'] = unquote(path)
                
                parsed_entries.append(entry)
        
        self.parsed_data = parsed_entries
        print(f"Successfully parsed {len(parsed_entries)} entries.")
        return parsed_entries
    
    def detect_brute_force_attempts(self, threshold=5, time_window_minutes=10):
        """Detect potential brute force attempts based on failed login patterns."""
        if not self.parsed_data:
            print("No parsed data available. Please parse logs first.")
            return []
        
        # Filter for failed login attempts
        failed_logins = []
        for entry in self.parsed_data:
            if 'message' in entry and 'Failed password' in entry.get('message', ''):
                failed_logins.append(entry)
        
        # Convert to DataFrame for easier analysis
        if failed_logins:
            df = pd.DataFrame(failed_logins)
            
            # Group by IP address and count
            if 'ip_address' in df.columns:
                ip_counts = df['ip_address'].value_counts()
                suspicious_ips = ip_counts[ip_counts >= threshold].index.tolist()
                
                # For each suspicious IP, check if attempts happened within the time window
                confirmed_threats = []
                for ip in suspicious_ips:
                    ip_attempts = df[df['ip_address'] == ip].sort_values('timestamp')
                    
                    if len(ip_attempts) >= threshold:
                        # Check if attempts are within the time window
                        for i in range(len(ip_attempts) - threshold + 1):
                            window = ip_attempts.iloc[i:i+threshold]
                            if window.empty:
                                continue
                                
                            start_time = min(window['timestamp'])
                            end_time = max(window['timestamp'])
                            
                            if start_time and end_time:
                                time_diff = end_time - start_time
                                if time_diff.total_seconds() <= time_window_minutes * 60:
                                    # Get geolocation for the IP address
                                    geo_info = self.get_ip_geolocation(ip)
                                    
                                    threat = {
                                        'ip_address': ip,
                                        'attempt_count': len(window),
                                        'first_attempt': start_time,
                                        'last_attempt': end_time,
                                        'usernames': window['username'].unique().tolist(),
                                        'raw_logs': window['raw_log'].tolist(),
                                        'geo_location': geo_info
                                    }
                                    confirmed_threats.append(threat)
                                    break
                
                self.suspicious_activity = confirmed_threats
                return confirmed_threats
        
        print("No brute force attempts detected.")
        return []
    
    def detect_sql_injection(self):
        """Detect potential SQL injection attempts in web server logs."""
        if not self.parsed_data:
            print("No parsed data available. Please parse logs first.")
            return []
        
        # Common SQL injection patterns
        sqli_patterns = [
            r'(\s|%20|;|/)(\s|%20)*union(\s|%20)+', 
            r'select.+from',
            r'insert(\s|%20)+into',
            r'delete(\s|%20)+from',
            r'drop(\s|%20)+table',
            r'update(\s|%20)+.*set(\s|%20)+',
            r'exec(\s|%20)+.*sp_',
            r'%27.*(%20|--|#|/\*)',
            r'\b(or|and)\b(\s|%20)*\d+=\d+',
            r'--.*$',
            r'\/\*.*\*\/',
            r';\s*$',
            r"['\"].*OR.*['\"=]",
        ]
        
        sqli_attempts = []
        
        for entry in self.parsed_data:
            if 'decoded_path' in entry:
                path = entry['decoded_path'].lower()
                for pattern in sqli_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        # Get geolocation for the IP address
                        geo_info = self.get_ip_geolocation(entry['ip_address'])
                        
                        attempt = {
                            'ip_address': entry['ip_address'],
                            'timestamp': entry['timestamp'],
                            'method': entry.get('method', 'N/A'),
                            'path': entry.get('path', 'N/A'),
                            'decoded_path': path,
                            'pattern_matched': pattern,
                            'raw_log': entry['raw_log'],
                            'geo_location': geo_info
                        }
                        sqli_attempts.append(attempt)
                        break
        
        self.sqli_attempts = sqli_attempts
        print(f"Detected {len(sqli_attempts)} potential SQL injection attempts.")
        return sqli_attempts
    
    def detect_ddos_attempts(self, request_threshold=100, time_window_minutes=1):
        """Detect potential DDoS attacks based on request frequency."""
        if not self.parsed_data:
            print("No parsed data available. Please parse logs first.")
            return []
        
        # Only relevant for web server logs
        if 'method' not in self.parsed_data[0]:
            print("DDoS detection is only available for web server logs.")
            return []
        
        # Convert to DataFrame for time-based analysis
        df = pd.DataFrame(self.parsed_data)
        
        # Ensure timestamp is present
        if 'timestamp' not in df.columns or df['timestamp'].isnull().all():
            print("Timestamp information is required for DDoS detection.")
            return []
        
        # Remove rows with None timestamps
        df = df[df['timestamp'].notna()]
        
        # Group by IP address and minute
        df['minute'] = df['timestamp'].dt.floor('min')
        request_counts = df.groupby(['ip_address', 'minute']).size().reset_index(name='count')
        
        # Find IPs with request counts above threshold
        high_frequency = request_counts[request_counts['count'] >= request_threshold]
        
        # Group results by IP
        ddos_attempts = []
        for ip, group in high_frequency.groupby('ip_address'):
            # Get geolocation for the IP address
            geo_info = self.get_ip_geolocation(ip)
            
            attempt = {
                'ip_address': ip,
                'max_requests_per_minute': group['count'].max(),
                'total_high_traffic_minutes': len(group),
                'first_detected': group['minute'].min(),
                'last_detected': group['minute'].max(),
                'geo_location': geo_info,
                'sample_logs': df[df['ip_address'] == ip].sample(min(5, len(df[df['ip_address'] == ip])))['raw_log'].tolist()
            }
            ddos_attempts.append(attempt)
        
        self.ddos_attempts = ddos_attempts
        print(f"Detected {len(ddos_attempts)} potential DDoS sources.")
        return ddos_attempts
    
    def get_ip_geolocation(self, ip_address):
        """Get geolocation information for an IP address."""
        # Skip private IP addresses
        try:
            if ip_address and ipaddress.ip_address(ip_address).is_private:
                return {
                    'country': 'Private IP',
                    'city': 'N/A',
                    'org': 'Private Network',
                    'region': 'N/A',
                    'loc': 'N/A'
                }
        except:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'org': 'Unknown',
                'region': 'Unknown',
                'loc': 'Unknown'
            }
        
        # Use ipinfo.io API for geolocation (free tier has limits)
        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json?token=fae19289e2bb5a')
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'country': 'API Error',
                    'city': 'API Error',
                    'org': 'API Error',
                    'region': 'API Error',
                    'loc': 'API Error'
                }
        except Exception as e:
            print(f"Error getting geolocation for IP {ip_address}: {e}")
            return {
                'country': 'Error',
                'city': 'Error',
                'org': 'Error',
                'region': 'Error',
                'loc': 'Error'
            }
    
    def generate_report(self, output_file=None, format='txt'):
        """Generate a report of the log analysis."""
        if not self.parsed_data:
            print("No parsed data available. Please parse logs first.")
            return
        
        # Ensure the directory exists if output_file is specified
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        if format == 'txt':
            return self._generate_txt_report(output_file)
        elif format == 'html':
            return self._generate_html_report(output_file)
        else:
            print(f"Unsupported format: {format}. Using text format instead.")
            return self._generate_txt_report(output_file)
    
    def _generate_txt_report(self, output_file=None):
        """Generate a text-based report."""
        report = []
        report.append("=== SECURITY LOG ANALYSIS REPORT ===")
        report.append(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total log entries analyzed: {len(self.parsed_data)}")
        
        # Basic statistics
        if self.parsed_data:
            df = pd.DataFrame(self.parsed_data)
            
            # IP statistics
            if 'ip_address' in df.columns:
                top_ips = df['ip_address'].value_counts().head(10)
                report.append("\n=== TOP 10 IP ADDRESSES ===")
                for ip, count in top_ips.items():
                    if ip:  # Skip None values
                        # Get geolocation
                        geo = self.get_ip_geolocation(ip)
                        location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                        report.append(f"{ip} ({location}): {count} entries")
            
            # User statistics
            if 'username' in df.columns:
                top_users = df['username'].value_counts().head(10)
                report.append("\n=== TOP 10 USERNAMES ===")
                for user, count in top_users.items():
                    if user:  # Skip None values
                        report.append(f"{user}: {count} entries")
            
            # Service statistics (for auth logs)
            if 'service' in df.columns:
                service_counts = df['service'].value_counts()
                report.append("\n=== SERVICES ===")
                for service, count in service_counts.items():
                    report.append(f"{service}: {count} entries")
            
            # HTTP status codes (for web server logs)
            if 'status' in df.columns:
                status_counts = df['status'].value_counts()
                report.append("\n=== HTTP STATUS CODES ===")
                for status, count in status_counts.items():
                    report.append(f"Status {status}: {count} entries")
        
        # Suspicious activity - Brute force
        if self.suspicious_activity:
            report.append("\n=== SUSPICIOUS ACTIVITY - BRUTE FORCE ATTEMPTS ===")
            for i, threat in enumerate(self.suspicious_activity, 1):
                report.append(f"\nThreat #{i}:")
                report.append(f"IP Address: {threat['ip_address']}")
                
                # Add geolocation info
                geo = threat.get('geo_location', {})
                if geo:
                    report.append(f"Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}")
                    report.append(f"Organization: {geo.get('org', 'Unknown')}")
                
                report.append(f"Attempt Count: {threat['attempt_count']}")
                report.append(f"Time Period: {threat['first_attempt']} to {threat['last_attempt']}")
                report.append(f"Targeted Usernames: {', '.join(threat['usernames'])}")
                report.append("Sample Log Entries:")
                for i, log in enumerate(threat['raw_logs'][:3], 1):  # Show just the first 3 logs
                    report.append(f"  {i}. {log}")
        else:
            report.append("\n=== NO BRUTE FORCE ATTEMPTS DETECTED ===")
        
        # SQL Injection attempts
        if self.sqli_attempts:
            report.append("\n=== SQL INJECTION ATTEMPTS ===")
            for i, attempt in enumerate(self.sqli_attempts, 1):
                report.append(f"\nAttempt #{i}:")
                report.append(f"IP Address: {attempt['ip_address']}")
                
                # Add geolocation info
                geo = attempt.get('geo_location', {})
                if geo:
                    report.append(f"Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}")
                    report.append(f"Organization: {geo.get('org', 'Unknown')}")
                
                report.append(f"Timestamp: {attempt['timestamp']}")
                report.append(f"Method: {attempt['method']}")
                report.append(f"Path: {attempt['path']}")
                report.append(f"Pattern Matched: {attempt['pattern_matched']}")
                report.append(f"Raw Log: {attempt['raw_log']}")
        else:
            report.append("\n=== NO SQL INJECTION ATTEMPTS DETECTED ===")
        
        # DDoS attempts
        if self.ddos_attempts:
            report.append("\n=== POTENTIAL DDoS SOURCES ===")
            for i, attempt in enumerate(self.ddos_attempts, 1):
                report.append(f"\nSource #{i}:")
                report.append(f"IP Address: {attempt['ip_address']}")
                
                # Add geolocation info
                geo = attempt.get('geo_location', {})
                if geo:
                    report.append(f"Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}")
                    report.append(f"Organization: {geo.get('org', 'Unknown')}")
                
                report.append(f"Max Requests per Minute: {attempt['max_requests_per_minute']}")
                report.append(f"High Traffic Minutes: {attempt['total_high_traffic_minutes']}")
                report.append(f"Time Period: {attempt['first_detected']} to {attempt['last_detected']}")
                report.append("Sample Log Entries:")
                for i, log in enumerate(attempt['sample_logs'][:3], 1):  # Show just the first 3 logs
                    report.append(f"  {i}. {log}")
        else:
            report.append("\n=== NO DDoS ATTEMPTS DETECTED ===")
        
        # Write to file if requested
        if output_file:
            try:
                with open(output_file, 'w', encoding="utf-8") as f:
                    f.write('\n'.join(report))
                print(f"Report saved to {output_file}")
            except Exception as e:
                print(f"Error saving report: {e}")
        
        # Print report to console
        print('\n'.join(report))
        return report
    
    def _generate_html_report(self, output_file=None):
        """Generate an HTML-based report."""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("  <meta charset='UTF-8'>")
        html.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("  <title>Security Log Analysis Report</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }")
        html.append("    h1, h2 { color: #2c3e50; }")
        html.append("    .container { max-width: 1200px; margin: 0 auto; }")
        html.append("    .card { background: #fff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; padding: 20px; }")
        html.append("    .threat { background-color: #fff8f8; border-left: 4px solid #e74c3c; padding: 10px; margin-bottom: 10px; }")
        html.append("    .stats-container { display: flex; flex-wrap: wrap; justify-content: space-between; }")
        html.append("    .stat-box { flex: 1; min-width: 200px; margin: 10px; }")
        html.append("    table { width: 100%; border-collapse: collapse; }")
        html.append("    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    th { background-color: #f2f2f2; }")
        html.append("    .sample-log { font-family: monospace; background-color: #f8f9fa; padding: 5px; margin: 5px 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }")
        html.append("    .map-container { height: 400px; margin-bottom: 20px; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("  <div class='container'>")
        
        # Header
        html.append("    <div class='card'>")
        html.append("      <h1>Security Log Analysis Report</h1>")
        html.append(f"      <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append(f"      <p>Total log entries analyzed: {len(self.parsed_data)}</p>")
        html.append("    </div>")
        
        # Summary section
        html.append("    <div class='card'>")
        html.append("      <h2>Summary</h2>")
        html.append("      <div class='stats-container'>")
        
        # Brute force summary
        html.append("        <div class='stat-box'>")
        html.append("          <h3>Brute Force Attempts</h3>")
        html.append(f"          <p><strong>{len(self.suspicious_activity)}</strong> detected</p>")
        if self.suspicious_activity:
            unique_ips = set(threat['ip_address'] for threat in self.suspicious_activity)
            html.append(f"          <p><strong>{len(unique_ips)}</strong> unique IPs</p>")
        html.append("        </div>")
        
        # SQL Injection summary
        html.append("        <div class='stat-box'>")
        html.append("          <h3>SQL Injection Attempts</h3>")
        html.append(f"          <p><strong>{len(self.sqli_attempts)}</strong> detected</p>")
        if self.sqli_attempts:
            unique_ips = set(attempt['ip_address'] for attempt in self.sqli_attempts)
            html.append(f"          <p><strong>{len(unique_ips)}</strong> unique IPs</p>")
        html.append("        </div>")
        
        # DDoS summary
        html.append("        <div class='stat-box'>")
        html.append("          <h3>DDoS Sources</h3>")
        html.append(f"          <p><strong>{len(self.ddos_attempts)}</strong> detected</p>")
        if self.ddos_attempts:
            max_rate = max([attempt['max_requests_per_minute'] for attempt in self.ddos_attempts])
            html.append(f"          <p>Highest rate: <strong>{max_rate}</strong> req/min</p>")
        html.append("        </div>")
        
        html.append("      </div>")
        html.append("    </div>")
        
        # Basic statistics section
        if self.parsed_data:
            df = pd.DataFrame(self.parsed_data)
            
            html.append("    <div class='card'>")
            html.append("      <h2>Top Statistics</h2>")
            
            # IP statistics
            if 'ip_address' in df.columns:
                top_ips = df['ip_address'].value_counts().head(10)
                html.append("      <h3>Top 10 IP Addresses</h3>")
                html.append("      <table>")
                html.append("        <tr><th>IP Address</th><th>Location</th><th>Count</th></tr>")
                for ip, count in top_ips.items():
                    if ip:
                        geo = self.get_ip_geolocation(ip)
                        location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                        html.append(f"        <tr><td>{ip}</td><td>{location}</td><td>{count}</td></tr>")
                html.append("      </table>")
            
            # Display only if we have web logs
            if 'status' in df.columns:
                html.append("      <h3>HTTP Status Codes</h3>")
                status_counts = df['status'].value_counts()
                html.append("      <table>")
                html.append("        <tr><th>Status Code</th><th>Count</th></tr>")
                for status, count in status_counts.items():
                    html.append(f"        <tr><td>{status}</td><td>{count}</td></tr>")
                html.append("      </table>")
            
            html.append("    </div>")
        
        # Threat details - Brute Force
        if self.suspicious_activity:
            html.append("    <div class='card'>")
            html.append("      <h2>Brute Force Attempts</h2>")
            
            for i, threat in enumerate(self.suspicious_activity, 1):
                html.append("      <div class='threat'>")
                html.append(f"        <h3>Threat #{i}: {threat['ip_address']}</h3>")
                
                # Add geolocation info
                geo = threat.get('geo_location', {})
                if geo:
                    html.append(f"        <p><strong>Location:</strong> {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}</p>")
                    html.append(f"        <p><strong>Organization:</strong> {geo.get('org', 'Unknown')}</p>")
                
                html.append(f"        <p><strong>Attempt Count:</strong> {threat['attempt_count']}</p>")
                html.append(f"        <p><strong>Time Period:</strong> {threat['first_attempt']} to {threat['last_attempt']}</p>")
                html.append(f"        <p><strong>Targeted Usernames:</strong> {', '.join(threat['usernames'])}</p>")
                
                html.append("        <p><strong>Sample Log Entries:</strong></p>")
                for log in threat['raw_logs'][:3]:
                    html.append(f"        <div class='sample-log'>{log}</div>")
                
                html.append("      </div>")
            
            html.append("    </div>")
        
        # SQL Injection attempts
        if self.sqli_attempts:
            html.append("    <div class='card'>")
            html.append("      <h2>SQL Injection Attempts</h2>")
            
            for i, attempt in enumerate(self.sqli_attempts, 1):
                html.append("      <div class='threat'>")
                html.append(f"        <h3>Attempt #{i}: {attempt['ip_address']}</h3>")
                
                # Add geolocation info
                geo = attempt.get('geo_location', {})
                if geo:
                    html.append(f"        <p><strong>Location:</strong> {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}</p>")
                    html.append(f"        <p><strong>Organization:</strong> {geo.get('org', 'Unknown')}</p>")
                
                html.append(f"        <p><strong>Timestamp:</strong> {attempt['timestamp']}</p>")
                html.append(f"        <p><strong>Method:</strong> {attempt['method']}</p>")
                html.append(f"        <p><strong>Path:</strong> {attempt['path']}</p>")
                html.append(f"        <p><strong>Pattern Matched:</strong> {attempt['pattern_matched']}</p>")
                html.append(f"        <p><strong>Raw Log:</strong></p>")
                html.append(f"        <div class='sample-log'>{attempt['raw_log']}</div>")
                
                html.append("      </div>")
            
            html.append("    </div>")
        
        # DDoS attempts
        if self.ddos_attempts:
            html.append("    <div class='card'>")
            html.append("      <h2>Potential DDoS Sources</h2>")
            
            for i, attempt in enumerate(self.ddos_attempts, 1):
                html.append("      <div class='threat'>")
                html.append(f"        <h3>Source #{i}: {attempt['ip_address']}</h3>")
                
                # Add geolocation info
                geo = attempt.get('geo_location', {})
                if geo:
                    html.append(f"        <p><strong>Location:</strong> {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}, {geo.get('country', 'Unknown')}</p>")
                    html.append(f"        <p><strong>Organization:</strong> {geo.get('org', 'Unknown')}</p>")
                
                html.append(f"        <p><strong>Max Requests per Minute:</strong> {attempt['max_requests_per_minute']}</p>")
                html.append(f"        <p><strong>High Traffic Minutes:</strong> {attempt['total_high_traffic_minutes']}</p>")
                html.append(f"        <p><strong>Time Period:</strong> {attempt['first_detected']} to {attempt['last_detected']}</p>")
                
                html.append("        <p><strong>Sample Log Entries:</strong></p>")
                for log in attempt['sample_logs'][:3]:
                    html.append(f"        <div class='sample-log'>{log}</div>")
                
                html.append("      </div>")
            
            html.append("    </div>")
        
        # End of report
        html.append("  </div>")
        html.append("</body>")
        html.append("</html>")
        
        # Write to file if requested
        html_content = "\n".join(html)
        if output_file:
            try:
                with open(output_file, 'w', encoding="utf-8") as f:
                    f.write(html_content)
                print(f"HTML report saved to {output_file}")
            except Exception as e:
                print(f"Error saving HTML report: {e}")
        
        return html_content
    
    def visualize_data(self, output_path="log_analysis"):
        """Create visualizations of the log data."""
        if not self.parsed_data:
            print("No parsed data available. Please parse logs first.")
            return
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        df = pd.DataFrame(self.parsed_data)
        
        # Create a figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Plot 1: Activity over time
        if 'timestamp' in df.columns:
            # Remove None values
            time_df = df[df['timestamp'].notna()]
            if not time_df.empty:
                time_df.set_index('timestamp').resample('h').size().plot(
                    ax=axes[0, 0], title='Activity by Hour', grid=True
                )
                axes[0, 0].set_xlabel('Time')
                axes[0, 0].set_ylabel('Number of Events')
        
        # Plot 2: Top IP addresses with geolocation
        if 'ip_address' in df.columns:
            ip_counts = df['ip_address'].value_counts().head(10)
            if not ip_counts.empty:
                # Add location information to labels
                labels = []
                for ip in ip_counts.index:
                    if ip:
                        geo = self.get_ip_geolocation(ip)
                        location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                        labels.append(f"{ip}\n({location})")
                    else:
                        labels.append("Unknown")
                
                # Plot with enhanced labels
                ax = axes[0, 1]
                bars = ax.barh(range(len(labels)), ip_counts.values)
                ax.set_yticks(range(len(labels)))
                ax.set_yticklabels(labels, fontsize=8)
                ax.set_title('Top 10 IP Addresses by Location')
                ax.set_xlabel('Number of Events')
        
        # Plot 3: Service distribution (for auth logs) or HTTP methods (for web logs)
        if 'service' in df.columns:
            service_counts = df['service'].value_counts()
            if not service_counts.empty:
                service_counts.plot(kind='pie', ax=axes[1, 0], title='Services', autopct='%1.1f%%')
                axes[1, 0].set_ylabel('')
        elif 'method' in df.columns:
            method_counts = df['method'].value_counts()
            if not method_counts.empty:
                method_counts.plot(kind='pie', ax=axes[1, 0], title='HTTP Methods', autopct='%1.1f%%')
                axes[1, 0].set_ylabel('')
        
        # Plot 4: HTTP status codes (for web server logs) or username attempts (for auth logs)
        if 'status' in df.columns:
            status_counts = df['status'].value_counts()
            if not status_counts.empty:
                status_counts.plot(kind='bar', ax=axes[1, 1], title='HTTP Status Codes')
                axes[1, 1].set_xlabel('Status Code')
                axes[1, 1].set_ylabel('Number of Requests')
        elif 'username' in df.columns and df['username'].notna().any():
            username_counts = df['username'].value_counts().head(10)
            if not username_counts.empty:
                username_counts.plot(kind='barh', ax=axes[1, 1], title='Top Usernames')
                axes[1, 1].set_xlabel('Number of Events')
                axes[1, 1].set_ylabel('Username')
        
        plt.tight_layout()
        plt.savefig(f'{output_path}_basic_report.png')
        plt.close()
        print(f"Basic visualizations saved to {output_path}_basic_report.png")
        
        # Create additional visualizations for security incidents
        self._visualize_security_incidents(output_path)
        
        # Create geographic map of threats
        self._create_threat_map(output_path)
    
    def _visualize_security_incidents(self, output_path):
        """Create visualizations specific to security incidents."""
        # Combine all threats for a consolidated view
        all_threats = []
        
        # Add brute force attempts
        for threat in self.suspicious_activity:
            all_threats.append({
                'ip': threat['ip_address'],
                'type': 'Brute Force',
                'count': threat['attempt_count'],
                'geo': threat.get('geo_location', {})
            })
        
        # Add SQL injection attempts
        sql_by_ip = {}
        for attempt in self.sqli_attempts:
            ip = attempt['ip_address']
            if ip in sql_by_ip:
                sql_by_ip[ip] += 1
            else:
                sql_by_ip[ip] = 1
        
        for ip, count in sql_by_ip.items():
            # Find first occurrence to get geo data
            for attempt in self.sqli_attempts:
                if attempt['ip_address'] == ip:
                    all_threats.append({
                        'ip': ip,
                        'type': 'SQL Injection',
                        'count': count,
                        'geo': attempt.get('geo_location', {})
                    })
                    break
        
        # Add DDoS attempts
        for attempt in self.ddos_attempts:
            all_threats.append({
                'ip': attempt['ip_address'],
                'type': 'DDoS',
                'count': attempt['max_requests_per_minute'],
                'geo': attempt.get('geo_location', {})
            })
        
        # If we have threats, create visualizations
        if all_threats:
            # Convert to DataFrame for easier analysis
            threats_df = pd.DataFrame(all_threats)
            
            # Create a figure for threat analysis
            fig, axes = plt.subplots(2, 1, figsize=(15, 12))
            
            # Plot 1: Threats by type
            threat_types = threats_df['type'].value_counts()
            threat_types.plot(kind='bar', ax=axes[0], title='Security Incidents by Type')
            axes[0].set_xlabel('Incident Type')
            axes[0].set_ylabel('Count')
            for i, v in enumerate(threat_types.values):
                axes[0].text(i, v + 0.5, str(v), ha='center')
            
            # Plot 2: Top threat sources
            top_ips = threats_df.groupby('ip')['count'].sum().sort_values(ascending=False).head(10)
            
            # Add location information to labels
            labels = []
            for ip in top_ips.index:
                # Find the threat entry with this IP to get geo info
                for threat in all_threats:
                    if threat['ip'] == ip:
                        geo = threat['geo']
                        location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                        labels.append(f"{ip}\n({location})")
                        break
                else:
                    labels.append(ip)
            
            # Plot with enhanced labels
            bars = axes[1].barh(range(len(labels)), top_ips.values)
            
            # Color bars by threat severity (count)
            norm = plt.Normalize(min(top_ips.values), max(top_ips.values))
            cmap = matplotlib.colormaps.get_cmap('YlOrRd')
            for i, bar in enumerate(bars):
                bar.set_color(cmap(norm(top_ips.values[i])))
            
            axes[1].set_yticks(range(len(labels)))
            axes[1].set_yticklabels(labels, fontsize=8)
            axes[1].set_title('Top Threat Sources')
            axes[1].set_xlabel('Total Activity Count')
            
            plt.tight_layout()
            plt.savefig(f'{output_path}_security_incidents.png')
            plt.close()
            print(f"Security incident visualizations saved to {output_path}_security_incidents.png")
    
    def _create_threat_map(self, output_path):
        """Create a geographic map of threat sources."""
        # Collect all threat IPs with their geo data
        threat_locations = []
        
        # Add brute force IPs
        for threat in self.suspicious_activity:
            geo = threat.get('geo_location', {})
            if 'loc' in geo and geo['loc'] != 'N/A' and geo['loc'] != 'Unknown':
                try:
                    lat, lon = geo['loc'].split(',')
                    threat_locations.append({
                        'ip': threat['ip_address'],
                        'lat': float(lat),
                        'lon': float(lon),
                        'type': 'Brute Force',
                        'count': threat['attempt_count'],
                        'details': f"Brute force: {threat['attempt_count']} attempts"
                    })
                except:
                    pass
        
        # Add SQL injection IPs
        for attempt in self.sqli_attempts:
            geo = attempt.get('geo_location', {})
            if 'loc' in geo and geo['loc'] != 'N/A' and geo['loc'] != 'Unknown':
                try:
                    lat, lon = geo['loc'].split(',')
                    threat_locations.append({
                        'ip': attempt['ip_address'],
                        'lat': float(lat),
                        'lon': float(lon),
                        'type': 'SQL Injection',
                        'count': 1,  # Each detection counts as 1
                        'details': f"SQL Injection attempt: {attempt['decoded_path'][:50]}..."
                    })
                except:
                    pass
        
        # Add DDoS IPs
        for attempt in self.ddos_attempts:
            geo = attempt.get('geo_location', {})
            if 'loc' in geo and geo['loc'] != 'N/A' and geo['loc'] != 'Unknown':
                try:
                    lat, lon = geo['loc'].split(',')
                    threat_locations.append({
                        'ip': attempt['ip_address'],
                        'lat': float(lat),
                        'lon': float(lon),
                        'type': 'DDoS',
                        'count': attempt['max_requests_per_minute'],
                        'details': f"DDoS: {attempt['max_requests_per_minute']} req/min"
                    })
                except:
                    pass

def main():
    parser = argparse.ArgumentParser(description='Security Log Analyzer')
    parser.add_argument('--file', '-f', required=True, help='Path to the log file')
    parser.add_argument('--type', '-t', choices=['ssh', 'apache'], required=True, help='Type of log file')
    parser.add_argument('--output', '-o', help='Output file prefix for the report')
    parser.add_argument('--format', choices=['txt', 'html'], default='txt', help='Output format for the report')
    parser.add_argument('--threshold', type=int, default=5, help='Threshold for brute force detection')
    parser.add_argument('--window', type=int, default=10, help='Time window in minutes for brute force detection')
    parser.add_argument('--ddos-threshold', type=int, default=100, help='Requests per minute threshold for DDoS detection')
    
    args = parser.parse_args()
    
    analyzer = SecurityLogAnalyzer()
    
    if analyzer.load_log_file(args.file):
        # Create report directory structure
        report_dir = os.path.join('report', args.type)
        os.makedirs(report_dir, exist_ok=True)
        
        # Parse logs based on type
        if args.type == 'ssh':
            analyzer.parse_ssh_log()
            analyzer.detect_brute_force_attempts(threshold=args.threshold, time_window_minutes=args.window)
        elif args.type == 'apache':
            analyzer.parse_apache_log()
            analyzer.detect_brute_force_attempts(threshold=args.threshold, time_window_minutes=args.window)
            analyzer.detect_sql_injection()
            analyzer.detect_ddos_attempts(request_threshold=args.ddos_threshold)
        
        # Generate output files with proper paths
        output_prefix = args.output or "security_analysis"
        output_file = os.path.join(report_dir, f"{output_prefix}.{args.format}")
        analyzer.generate_report(output_file, format=args.format)
        
        # Visualizations will also be saved in the same directory
        analyzer.visualize_data(os.path.join(report_dir, output_prefix))


if __name__ == "__main__":
    main()