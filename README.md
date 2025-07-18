# automated-scanner
Automated Scanner is a Python-based tool that automates web vulnerability scanning using tools like Nmap, Nikto, and Gobuster. It helps detect open ports, missing headers, and common flaws, offering multiple scan modes and organized output for efficient security analysis.
# Automated Vulnerability Scanner
An advanced, multi-threaded vulnerability scanner with automated exploitation capabilities. This tool combines various security tools into a unified interface with enhanced reporting and safety features.

## Features

- 🎯 **Target Discovery**: Netdiscover for local network scanning
- 🔍 **Port Scanning**: Nmap with vulnerability scripts
- 🌐 **Web Assessment**: Nikto, WhatWeb, Gobuster, WafW00f
- 🔗 **Subdomain Enumeration**: Subfinder and Amass integration
- 🔒 **SSL Analysis**: SSLyze for TLS/SSL configuration checks
- 💣 **Exploit Integration**: Metasploit module automation
- 📊 **Reporting**: Consolidated vulnerability reports in multiple formats
- ⚡ **Performance**: Parallel scanning with configurable threads

## Installation

### Prerequisites

- Python 3.8+
- Kali Linux or similar security-focused distro recommended
- Root/sudo access for some scans

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/automated-scanner.git
cd automated-scanner

## Installation

### Prerequisites

- Python 3.8+
- Kali Linux or similar security-focused distro (recommended)
- Required tools:
  ```bash
  sudo apt install nmap nikto whatweb wafw00f sslyze gobuster subfinder amass metasploit-framework
```
### 2. Install Python Dependencies
   ```bash
   pip install -r requirements.txt
   ```
   Note that you should set up python environment for pip installation

   ### USAGE
   ```
   python3 scanner.py
   ```
  So you should be root user or super user in order to run this code
  
Ethical Use Policy ⚖️🔒

Legal & Ethical Requirements
Professional Ethics
Explicit Consent
📝 Always obtain written authorization before scanning any system

Responsible Disclosure
🕵️‍♂️ Report found vulnerabilities privately to system owners

Data Protection
🔐 Never extract, modify, or exfiltrate data without permission

Safety Measures
⚠️ Avoid scanning:

Medical systems

Industrial control systems

Emergency services

Any life-critical infrastructure

