"""
Auto-Remediation Module
Performs automatic remediation actions when risks are detected:
1. Masking sensitive fields (email, phone numbers, etc.)
2. Generating JSON format alerts
"""

import re
import json
from datetime import datetime


class RemediationEngine:
    def __init__(self):
        # Patterns for sensitive data
        self.sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?(\d{1,3}))?[-.\s]?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b',
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b'
        }
    
    def mask_sensitive_data(self, content):
        """
        Mask sensitive data in log content.
        
        Args:
            content (str): Log content
            
        Returns:
            str: Content with sensitive data masked
        """
        masked_content = content
        
        # Mask each type of sensitive data
        for data_type, pattern in self.sensitive_patterns.items():
            masked_content = re.sub(pattern, '***', masked_content)
            
        return masked_content
    
    def generate_alert(self, log_entry, detection_result):
        """
        Generate JSON format alert for detected risks.
        
        Args:
            log_entry (dict): Original log entry
            detection_result (dict): Risk detection result
            
        Returns:
            dict: JSON format alert
        """
        # Mask sensitive data in content
        masked_content = self.mask_sensitive_data(log_entry.get('content', ''))
        
        # Create alert
        alert = {
            'level': detection_result.get('level', 'low').lower(),
            'ip': log_entry.get('ip', 'unknown'),
            'action': 'blocked' if detection_result.get('risk', False) else 'allowed',
            'reason': detection_result.get('reason', 'No risk detected'),
            'timestamp': log_entry.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'masked_content': masked_content
        }
        
        return alert
    
    def process_log_entry(self, log_entry, detection_result):
        """
        Process a log entry and perform remediation if needed.
        
        Args:
            log_entry (dict): Parsed log entry
            detection_result (dict): Risk detection result
            
        Returns:
            dict: Remediation result with alert
        """
        # Generate alert
        alert = self.generate_alert(log_entry, detection_result)
        
        # Perform additional remediation actions based on risk level
        if detection_result.get('risk', False):
            # For high-risk entries, we might want to take additional actions
            # This could include blocking IPs, sending notifications, etc.
            pass
            
        return alert


# Example usage
if __name__ == "__main__":
    remediation = RemediationEngine()
    
    log_entry = {
        'timestamp': '2023-05-15 10:30:00',
        'ip': '192.168.1.100',
        'content': "SELECT * FROM users WHERE email='test@example.com' AND phone='13800138000'",
        'level': 'ERROR'
    }
    
    detection_result = {
        'risk': True,
        'level': 'high',
        'type': 'SQL Injection',
        'reason': 'SQL Injection'
    }
    
    # Mask sensitive data
    masked_content = remediation.mask_sensitive_data(log_entry['content'])
    print("Masked content:", masked_content)
    
    # Generate alert
    alert = remediation.generate_alert(log_entry, detection_result)
    print("Generated alert:", json.dumps(alert, indent=2))