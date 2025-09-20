# Log Risk Detection and Auto-remediation System

This system detects potential security risks (such as SQL injection and sensitive information leaks) from service logs and automatically triggers remediation actions (such as masking sensitive fields and blocking abnormal requests).

## Features

1. **Log Parser**: Extracts key fields from mixed-format log files (timestamp, IP address, request content, error level)
2. **Risk Detection**: 
   - Rule-based detection for obvious malicious patterns
   - Machine learning detection using TF-IDF + Logistic Regression
3. **Auto-Remediation**: 
   - Masks sensitive fields (email, phone numbers, etc.)
   - Returns JSON format alerts
4. **System Integration**: 
   - CLI interface
   - REST API (optional)

## Project Structure

```
qwen/
├── main.py          # Entry point with CLI interface
├── parser.py        # Log parsing module
├── detector.py      # Risk detection module
├── remediation.py   # Auto-remediation module
├── requirements.txt # Python dependencies
├── README.md        # This file
├── .gitignore       # Git ignore file
├── sample_logs/     # Sample log files for testing
│   ├── normal_logs.log
│   └── malicious_logs.log
└── models/          # Trained ML models (directory will be created after training)
    └── ml_detector_model.pkl  # ML model file (generated after training)
```

## Dependencies

- Python 3.7+
- scikit-learn
- pandas
- numpy
- flask (for REST API)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Train the ML Model (First Time Only)

Before using the system, you need to train the machine learning model:

```bash
python main.py --train
```

This will train the model using the sample logs in the `sample_logs` directory. The trained model will be saved in the `models/` directory.

### CLI Interface

```bash
# Process a log file
python main.py --file path/to/logfile.log

# Process log text directly
python main.py --text "Error: 2023-05-15 10:30:00, 192.168.1.100, SELECT * FROM users, ERROR"
```

### REST API (Optional)

```bash
# Start the API server
python main.py --api

# Send a request to the API
curl -X POST http://localhost:5000/detect -H "Content-Type: application/json" -d '{"log_text": "Error: 2023-05-15 10:30:00, 192.168.1.100, SELECT * FROM users, ERROR"}'
```

## Sample Input/Output

### Input Log
```
[2023-05-15 10:30:00] ERROR: 192.168.1.100 - "SELECT * FROM users WHERE email='test@example.com'" - HIGH
```

### Output Alert
```json
{
  "level": "high",
  "ip": "192.168.1.100",
  "action": "blocked",
  "reason": "SQL Injection",
  "timestamp": "2023-05-15 10:30:00",
  "masked_content": "[2023-05-15 10:30:00] ERROR: 192.168.1.100 - \"SELECT * FROM users WHERE email='***'\" - HIGH"
}
```

## Notes

- The `.gitignore` file excludes unnecessary files like Python bytecode (.pyc) files and virtual environments
- The ML model file (`ml_detector_model.pkl`) is not included in the repository and will be generated after training
- Make sure to run the training command before using the system for the first time