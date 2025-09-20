"""
Risk Detection Module
Detects potential security risks in parsed log entries using:
1. Rule-based detection for obvious malicious patterns
2. Machine learning detection using TF-IDF + Logistic Regression
"""

import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import os


class RuleBasedDetector:
    def __init__(self):
        # Define malicious patterns
        self.sql_injection_patterns = [
            r"(?i)select.*from",
            r"(?i)drop\s+table",
            r"(?i)delete\s+from",
            r"(?i)insert\s+into",
            r"(?i)update.*set",
            r"(?i)union\s+select",
            r"(?i)--",
            r"(?i)or\s+1=1",
            r"'[^']*'",
            r"(?i)admin'--",
        ]
        
        self.xss_patterns = [
            r"(?i)<script.*?>",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)javascript:",
            r"(?i)alert\s*\(",
        ]
        
        self.sensitive_info_patterns = [
            r"(?i)password\s*=",
            r"(?i)secret\s*=",
            r"(?i)key\s*=",
        ]
        
        # Combine all patterns
        self.all_patterns = {
            'SQL Injection': self.sql_injection_patterns,
            'XSS': self.xss_patterns,
            'Sensitive Info Exposure': self.sensitive_info_patterns
        }
    
    def detect_risk(self, log_entry):
        """
        Detect risks in a log entry using rule-based patterns.
        
        Args:
            log_entry (dict): Parsed log entry
            
        Returns:
            dict: Risk detection result with risk level and reason
        """
        content = log_entry.get('content', '')
        
        # Check for each type of risk
        for risk_type, patterns in self.all_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    # Determine risk level based on risk type
                    level = 'high' if risk_type in ['SQL Injection', 'XSS'] else 'medium'
                    return {
                        'risk': True,
                        'level': level,
                        'type': risk_type,
                        'reason': risk_type
                    }
        
        return {
            'risk': False,
            'level': 'low',
            'type': 'None',
            'reason': 'No known malicious patterns detected'
        }


class MLDetector:
    def __init__(self, model_path='models/ml_detector_model.pkl'):
        """
        Initialize ML-based detector.
        
        Args:
            model_path (str): Path to the trained model file
        """
        self.model_path = model_path
        self.vectorizer = None
        self.model = None
        self.is_trained = False
        
        # Try to load existing model
        if os.path.exists(model_path):
            self.load_model()
    
    def load_model(self):
        """Load a pre-trained model from disk."""
        try:
            loaded = joblib.load(self.model_path)
            self.vectorizer = loaded['vectorizer']
            self.model = loaded['model']
            self.is_trained = True
            print("ML model loaded successfully.")
        except Exception as e:
            print(f"Error loading ML model: {e}")
    
    def save_model(self):
        """Save the trained model to disk."""
        try:
            # Create models directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            joblib.dump({
                'vectorizer': self.vectorizer,
                'model': self.model
            }, self.model_path)
            print("ML model saved successfully.")
        except Exception as e:
            print(f"Error saving ML model: {e}")
    
    def train(self, normal_logs, malicious_logs):
        """
        Train the ML model with normal and malicious logs.
        
        Args:
            normal_logs (list): List of normal log entries
            malicious_logs (list): List of malicious log entries
        """
        # Prepare training data
        texts = []
        labels = []  # 0 for normal, 1 for malicious
        
        # Add normal logs
        for log in normal_logs:
            texts.append(log.get('content', ''))
            labels.append(0)
        
        # Add malicious logs
        for log in malicious_logs:
            texts.append(log.get('content', ''))
            labels.append(1)
        
        if len(texts) == 0 or len(set(labels)) < 2:
            print("Not enough training data. Need both normal and malicious samples.")
            return
        
        # Vectorize texts
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X = self.vectorizer.fit_transform(texts)
        
        # Train model
        self.model = LogisticRegression()
        self.model.fit(X, labels)
        self.is_trained = True
        
        # Save model
        self.save_model()
        
        print(f"ML model trained with {len(texts)} samples.")
    
    def predict(self, log_entry):
        """
        Predict if a log entry is malicious using the ML model.
        
        Args:
            log_entry (dict): Parsed log entry
            
        Returns:
            dict: Prediction result
        """
        if not self.is_trained:
            return {
                'risk': False,
                'level': 'low',
                'confidence': 0.0,
                'reason': 'ML model not trained'
            }
        
        content = log_entry.get('content', '')
        
        # Vectorize the content
        X = self.vectorizer.transform([content])
        
        # Predict
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        # Get confidence score (probability of malicious class)
        confidence = probability[1] if len(probability) > 1 else 0.0
        
        # Determine risk level based on confidence
        if prediction == 1 and confidence > 0.8:
            level = 'high'
        elif prediction == 1 and confidence > 0.5:
            level = 'medium'
        else:
            level = 'low'
        
        return {
            'risk': bool(prediction),
            'level': level,
            'confidence': confidence,
            'reason': 'ML model detection'
        }


# Example usage
if __name__ == "__main__":
    # Test rule-based detector
    rule_detector = RuleBasedDetector()
    
    test_entry = {
        'timestamp': '2023-05-15 10:30:00',
        'ip': '192.168.1.100',
        'content': "SELECT * FROM users WHERE id = 1",
        'level': 'ERROR'
    }
    
    result = rule_detector.detect_risk(test_entry)
    print("Rule-based detection result:", result)