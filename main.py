"""
Main Module
Entry point for the Log Risk Detection and Auto-remediation System.
Provides both CLI interface and REST API.
"""

import argparse
import json
import sys
import os
from flask import Flask, request, jsonify

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from parser import LogParser
from detector import RuleBasedDetector, MLDetector
from remediation import RemediationEngine


class LogSecuritySystem:
    def __init__(self):
        self.parser = LogParser()
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector()
        self.remediation = RemediationEngine()
    
    def train_ml_model(self, normal_logs_path, malicious_logs_path):
        """
        Train the ML model with sample logs.
        
        Args:
            normal_logs_path (str): Path to normal logs file
            malicious_logs_path (str): Path to malicious logs file
        """
        # Parse training data
        normal_logs = self.parser.parse_file(normal_logs_path)
        malicious_logs = self.parser.parse_file(malicious_logs_path)
        
        # Train ML detector
        self.ml_detector.train(normal_logs, malicious_logs)
    
    def process_log_file(self, file_path):
        """
        Process a log file and detect/ remediate risks.
        
        Args:
            file_path (str): Path to the log file
            
        Returns:
            list: List of alerts for detected risks
        """
        # Parse logs
        parsed_logs = self.parser.parse_file(file_path)
        alerts = []
        
        # Process each log entry
        for log_entry in parsed_logs:
            alerts.extend(self.process_log_entry(log_entry))
            
        return alerts
    
    def process_log_text(self, log_text):
        """
        Process a single log text and detect/ remediate risks.
        
        Args:
            log_text (str): Log text to process
            
        Returns:
            list: List of alerts for detected risks
        """
        # Parse log
        log_entry = self.parser.parse_line(log_text)
        if not log_entry:
            return []
            
        return self.process_log_entry(log_entry)
    
    def process_log_entry(self, log_entry):
        """
        Process a single parsed log entry.
        
        Args:
            log_entry (dict): Parsed log entry
            
        Returns:
            list: List of alerts for detected risks
        """
        alerts = []
        
        # Rule-based detection
        rule_result = self.rule_detector.detect_risk(log_entry)
        
        # ML-based detection (if model is trained)
        ml_result = {'risk': False, 'level': 'low'}
        if self.ml_detector.is_trained:
            ml_result = self.ml_detector.predict(log_entry)
        
        # Combine results (prioritize higher risk)
        combined_result = rule_result
        if ml_result.get('level') == 'high' or (rule_result.get('risk') == False and ml_result.get('risk') == True):
            combined_result = ml_result
            
        # If any risk detected, perform remediation
        if combined_result.get('risk', False):
            alert = self.remediation.process_log_entry(log_entry, combined_result)
            alerts.append(alert)
            
        return alerts


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Log Risk Detection and Auto-remediation System')
    parser.add_argument('--file', type=str, help='Path to log file to process')
    parser.add_argument('--text', type=str, help='Log text to process')
    parser.add_argument('--train', action='store_true', help='Train the ML model with sample data')
    parser.add_argument('--api', action='store_true', help='Start REST API server')
    parser.add_argument('--port', type=int, default=5000, help='Port for REST API server (default: 5000)')
    
    args = parser.parse_args()
    
    # Initialize system
    system = LogSecuritySystem()
    
    # Train ML model if requested
    if args.train:
        normal_logs_path = os.path.join('sample_logs', 'normal_logs.log')
        malicious_logs_path = os.path.join('sample_logs', 'malicious_logs.log')
        
        if os.path.exists(normal_logs_path) and os.path.exists(malicious_logs_path):
            print("Training ML model...")
            system.train_ml_model(normal_logs_path, malicious_logs_path)
            print("ML model training completed.")
        else:
            print("Error: Sample log files not found. Please check the sample_logs directory.")
            return
    
    # Process log file if provided
    if args.file:
        if os.path.exists(args.file):
            print(f"Processing log file: {args.file}")
            alerts = system.process_log_file(args.file)
            
            if alerts:
                print(f"Found {len(alerts)} security risks:")
                for alert in alerts:
                    print(json.dumps(alert, indent=2))
            else:
                print("No security risks detected.")
        else:
            print(f"Error: File {args.file} not found.")
            return
    
    # Process log text if provided
    if args.text:
        print(f"Processing log text: {args.text}")
        alerts = system.process_log_text(args.text)
        
        if alerts:
            print(f"Found {len(alerts)} security risks:")
            for alert in alerts:
                print(json.dumps(alert, indent=2))
        else:
            print("No security risks detected.")
    
    # Start REST API if requested
    if args.api:
        app = Flask(__name__)
        
        @app.route('/detect', methods=['POST'])
        def detect_risk():
            try:
                data = request.get_json()
                
                if 'log_text' in data:
                    alerts = system.process_log_text(data['log_text'])
                    return jsonify(alerts)
                elif 'log_file' in data:
                    if os.path.exists(data['log_file']):
                        alerts = system.process_log_file(data['log_file'])
                        return jsonify(alerts)
                    else:
                        return jsonify({'error': 'Log file not found'}), 404
                else:
                    return jsonify({'error': 'Missing log_text or log_file parameter'}), 400
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({'status': 'healthy'})
        
        print(f"Starting REST API server on port {args.port}...")
        app.run(host='0.0.0.0', port=args.port, debug=False)


if __name__ == "__main__":
    main()