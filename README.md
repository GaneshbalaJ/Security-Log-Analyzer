# Security Log Analyzer

A beginner-built Python tool that parses authentication logs and flags IP addresses with repeated failed login attempts, a common indicator of brute-force activity.

## 🚀 How It Works
This tool reads raw server authentication logs, parses the data, and counts failed login attempts per IP. If an IP exceeds the configured security threshold (default: **3 or more failed attempts**), it is automatically flagged as a potential brute-force threat.

## ✨ Features
- **Zero Dependencies:** Built entirely using Python's standard library. No `requirements.txt` or external packages needed!
- **Automated Log Parsing:** Extracts timestamps, IP addresses, events, and usernames from unstructured log text.
- **Threat Detection:** Applies conditional logic to identify suspicious activity.
- **Automated Reporting:** Generates a professional summary report (`security_report.txt`) for security auditing.

## 📂 Project Structure
```text
Security-Log-Analyzer/
├── logs/
│   └── security.log
├── reports/
│   └── security_report.txt
└── src/
    ├── detector.py
    ├── log_parser.py
    └── main.py
