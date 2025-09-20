"""
Log Parser Module
Extracts key fields from mixed-format log files:
- Timestamp
- IP address
- Request content
- Error level
"""

import re
import json
from datetime import datetime
import pandas as pd


class LogParser:
    def __init__(self):
        # Regular expressions for different log formats
        self.timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # YYYY-MM-DD HH:MM:SS
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',  # YYYY/MM/DD HH:MM:SS
            r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]',  # [YYYY-MM-DD HH:MM:SS]
        ]
        
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.error_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        
    def parse_line(self, log_line):
        """
        Parse a single log line and extract key fields.
        
        Args:
            log_line (str): A line from a log file
            
        Returns:
            dict: Parsed fields (timestamp, ip, content, level)
        """
        if not log_line or not log_line.strip():
            return None
            
        # Initialize result
        result = {
            'timestamp': None,
            'ip': None,
            'content': log_line.strip(),
            'level': 'UNKNOWN'
        }
        
        # Try to parse as JSON first
        if log_line.strip().startswith('{') and log_line.strip().endswith('}'):
            try:
                json_data = json.loads(log_line)
                result['content'] = json_data.get('message', log_line)
                result['timestamp'] = json_data.get('timestamp')
                result['ip'] = json_data.get('ip')
                result['level'] = json_data.get('level', 'UNKNOWN')
                return result
            except json.JSONDecodeError:
                pass  # Not valid JSON, continue with regex parsing
        
        # Extract timestamp
        for pattern in self.timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                result['timestamp'] = match.group().strip('[]')
                break
                
        # Extract IP address
        ip_match = re.search(self.ip_pattern, log_line)
        if ip_match:
            result['ip'] = ip_match.group()
            
        # Extract error level
        for level in self.error_levels:
            if level in log_line.upper():
                result['level'] = level
                break
                
        return result
    
    def parse_file(self, file_path):
        """
        Parse a log file and return a list of parsed entries.
        
        Args:
            file_path (str): Path to the log file
            
        Returns:
            list: List of parsed log entries
        """
        parsed_logs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        parsed_entry = self.parse_line(line)
                        if parsed_entry:
                            parsed_logs.append(parsed_entry)
                    except Exception as e:
                        print(f"Warning: Error parsing line {line_num} in {file_path}: {e}")
                        # Continue parsing other lines
        except FileNotFoundError:
            print(f"Error: File {file_path} not found")
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            
        return parsed_logs


# Example usage
if __name__ == "__main__":
    parser = LogParser()
    
    # Test with a sample log line
    test_line = '[2023-05-15 10:30:00] ERROR: 192.168.1.100 - "SELECT * FROM users" - HIGH'
    result = parser.parse_line(test_line)
    print("Parsed log entry:", result)