# automated-scanner
Automated Scanner is a Python-based tool that automates web vulnerability scanning using tools like Nmap, Nikto, and Gobuster. It helps detect open ports, missing headers, and common flaws, offering multiple scan modes and organized output for efficient security analysis.
# Automated Vulnerability Scanner

![Banner](assets/banner.png) <!-- Optional: Add a banner image later -->

An advanced automated vulnerability scanner with exploitation capabilities, designed for ethical hacking and penetration testing.

## Features

- **Network Discovery**: Netdiscover integration for host enumeration
- **Port Scanning**: Nmap with vulnerability scripts
- **Web Assessment**:
  - Nikto (Quick/Standard/Deep scan modes)
  - WhatWeb for technology detection
  - WafW00f for WAF identification
  - Gobuster directory brute-forcing
- **Subdomain Enumeration**: Subfinder and Amass integration
- **SSL Analysis**: SSLyze for TLS/SSL configuration checks
- **Exploit Integration**:
  - Searchsploit for vulnerability matching
  - Metasploit module automation (with safety checks)
- **Reporting**:
  - Organized file structure with date-based directories
  - Consolidated vulnerability reports (Markdown)
  - JSON metadata storage

## Installation

### Prerequisites

- Python 3.8+
- Kali Linux or similar security-focused distro (recommended)
- Required tools:
  ```bash
  sudo apt install nmap nikto whatweb wafw00f sslyze gobuster subfinder amass metasploit-framework
