#!/usr/bin/env python3
import os
import sys
import time
import requests
import re
import subprocess
import json
from threading import Timer, Thread
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from pyfiglet import Figlet
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True, convert=True, strip=False)

vulnerabilities = []
cve_lookup_enabled = False

# Exploitation disclaimer
EXPLOIT_DISCLAIMER = f"""
{Fore.RED}
╔════════════════════════════════════════════════════════════╗
║                WARNING: EXPLOITATION CONSENT               ║
╠════════════════════════════════════════════════════════════╣
║ Automated exploitation can:                                ║
║ • Cause system instability and crashes                     ║
║ • Lead to data loss or corruption                          ║
║ • Disrupt critical services                                ║
║ • Have legal consequences if unauthorized                  ║
╚════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

class ScanError(Exception):
    """Base class for scan-related errors"""
    pass

class ToolNotFoundError(ScanError):
    """Raised when a required tool is not found"""
    pass

class NetworkError(ScanError):
    """Raised when there are network-related issues"""
    pass

class ScanTimeoutError(ScanError):
    """Raised when a scan times out"""
    pass

# Orange color (Dark Orange - RGB 255,140,0)
def orange(text):
    return "\033[38;2;255;140;0m" + text + "\033[0m"

# Typing effect with error handling
def typewrite(text, delay=0.005):
    try:
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()
    except (KeyboardInterrupt, IOError) as e:
        print(f"\n{Fore.RED}[!] Output interrupted: {e}{Style.RESET_ALL}")
        raise

# Banner with ORANGE AUTOMATED and GREEN SCANNER
def animated_banner():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        figlet = Figlet(font='slant')
        automated = figlet.renderText("AUTOMATED")
        scanner = figlet.renderText("SCANNER")

        for line in automated.splitlines():
            typewrite(orange(line), delay=0.002)

        for line in scanner.splitlines():
            typewrite(Fore.GREEN + Style.BRIGHT + line, delay=0.002)

        time.sleep(0.5)
        typewrite(Fore.YELLOW + Style.BRIGHT + "[*] Initializing engine...", 0.03)
        time.sleep(0.5)
        typewrite(Fore.YELLOW + Style.BRIGHT + "[*] Loading scanner modules...", 0.03)
        time.sleep(0.4)
        typewrite(Fore.GREEN + Style.BRIGHT + "[*] Ready to engage target.\n", 0.03)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to display banner: {e}{Style.RESET_ALL}")
        raise ScanError("Banner display failed") from e

def init_results_dir(target):
    """Create organized directory structure"""
    try:
        # Base paths
        date_str = datetime.now().strftime("%Y-%m-%d")
        safe_target = target.replace('.', '_').replace(':', '_')
        base_dir = Path(f"scan_results/{date_str}/{safe_target}")
        
        # Subdirectories
        dirs = {
            'base': base_dir,
            'subdomains': base_dir/"subdomains",
            'ports': base_dir/"ports",
            'web': base_dir/"web",
            'config': base_dir/"config",
            'exploits': base_dir/"exploits"
        }
        
        # Create structure
        for d in dirs.values():
            d.mkdir(parents=True, exist_ok=True)
            
        # Update latest symlink
        latest = Path("scan_results/latest")
        if latest.exists():
            latest.unlink()
        latest.symlink_to(date_str, target_is_directory=True)
        
        return dirs
    except Exception as e:
        print(f"{Fore.RED}[!] Filesystem init failed: {e}{Style.RESET_ALL}")
        raise ScanError("Could not create results structure")

def save_scan_artifact(target, tool, data, file_type="txt"):
    """Save tool output with standardized naming"""
    try:
        dirs = init_results_dir(target)
        safe_tool = tool.lower().replace('-', '_')
        
        # Special cases
        if tool == "nmap":
            path = dirs['ports']/f"{safe_tool}.{file_type}"
        elif tool in ("subfinder", "amass"):
            path = dirs['subdomains']/f"{safe_tool}.{file_type}"
        elif "gobuster" in tool:
            port = tool.split('_')[-1]  # Extract port
            path = dirs['web']/f"gobuster_{port}.{file_type}"
        elif "metasploit" in tool:
            path = dirs['exploits']/f"{safe_tool}.{file_type}"
        else:
            path = dirs['web']/f"{safe_tool}.{file_type}"
            
        # Write data
        with open(path, 'w') as f:
            if file_type == "json":
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))
                
        print(f"{Fore.BLUE}[+] Saved {tool} output to {path}{Style.RESET_ALL}")
        return path
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to save {tool} artifact: {e}{Style.RESET_ALL}")
        return None

def save_metadata(target, scan_type, duration):
    """Save scan metadata"""
    try:
        dirs = init_results_dir(target)
        meta = {
            "target": target,
            "scan_type": scan_type,
            "start_time": datetime.now().isoformat(),
            "duration_sec": round(duration, 2),
            "tools_used": list(set(vulnerabilities)),
            "cves_found": [v for v in vulnerabilities if "CVE-" in v],
            "exploits_attempted": [v for v in vulnerabilities if "metasploit" in v.lower()]
        }
        
        with open(dirs['base']/"meta.json", 'w') as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Metadata save failed: {e}{Style.RESET_ALL}")

def generate_summary(target):
    """Create consolidated vulnerability report"""
    try:
        dirs = init_results_dir(target)
        vuln_file = dirs['base']/"vulnerabilities.md"
        
        with open(vuln_file, 'w') as f:
            f.write(f"# Vulnerability Report: {target}\n\n")
            f.write(f"**Date**: {datetime.now()}\n\n")
            f.write("## Critical Findings\n")
            
            for vuln in vulnerabilities:
                if "CVE-" in vuln:
                    f.write(f"- ⚠ {vuln}\n")
                elif "metasploit" in vuln.lower():
                    f.write(f"- 💥 {vuln}\n")
                else:
                    f.write(f"- 🔍 {vuln}\n")
                    
        print(f"{Fore.GREEN}[+] Consolidated report: {vuln_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to generate summary: {e}{Style.RESET_ALL}")

def check_tool_installed(tool_name):
    """Check if a tool is installed with helpful messages"""
    try:
        if os.system(f"which {tool_name} > /dev/null 2>&1" if os.name != 'nt' else f"where {tool_name} > nul 2>&1"):
            raise ToolNotFoundError(
                f"{tool_name} not found in PATH\n"
                f"Install with: \n"
                f"Kali/Debian: sudo apt install {tool_name}\n"
                f"Other Linux: go install -v github.com/projectdiscovery/{tool_name}/v2/cmd/{tool_name}@latest\n"
                f"Then add $HOME/go/bin to your PATH"
            )
    except Exception as e:
        raise ToolNotFoundError(f"Error checking for {tool_name}: {e}") from e

def run_tool_with_timeout(command, timeout=300):
    """Run a command with timeout using subprocess"""
    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        timer = Timer(timeout, proc.kill)
        try:
            timer.start()
            stdout, stderr = proc.communicate()
            
            if timer.is_alive():
                if proc.returncode == 0:
                    return stdout
                else:
                    raise ScanError(f"Command failed with return code {proc.returncode}: {stderr.strip()}")
            else:
                raise ScanTimeoutError(f"Command timed out after {timeout} seconds")
        finally:
            timer.cancel()
    except subprocess.SubprocessError as e:
        raise ScanError(f"Subprocess error: {e}") from e
    except Exception as e:
        raise ScanError(f"Error running command: {e}") from e

def discover_hosts():
    print(f"{Fore.CYAN}[*] Running Netdiscover to list local network hosts...{Style.RESET_ALL}")
    try:
        check_tool_installed("netdiscover")
        result = run_tool_with_timeout("netdiscover -r 192.168.1.0/24 -P -N -c 10", timeout=300)
        if not result.strip():
            raise ScanError("Netdiscover returned empty output")
        print(f"{Fore.GREEN}[+] Discovered Hosts:{Style.RESET_ALL}\n")
        print(result)
        save_scan_artifact("network", "netdiscover", result)
        return result
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Netdiscover failed: {e}{Style.RESET_ALL}")
        return None

def get_http_ports(target):
    print(f"{Fore.CYAN}[*] Scanning for HTTP service ports...{Style.RESET_ALL}")
    start = time.time()
    try:
        check_tool_installed("nmap")
        result = run_tool_with_timeout(f"nmap -sV {target}", timeout=600)
        if not result.strip():
            raise ScanError("Nmap returned empty output")
        
        print(f"{Fore.GREEN}[+] Port scan completed in {time.time() - start:.2f} seconds{Style.RESET_ALL}")
        ports = []
        for match in re.finditer(r"(\d+)/tcp\s+open\s+(http[s]?)", result):
            port = match.group(1)
            scheme = match.group(2)
            ports.append((port, scheme))
        
        if not ports:
            print(f"{Fore.YELLOW}[!] No HTTP/HTTPS ports found. Web-based scans will be skipped.{Style.RESET_ALL}")
        save_scan_artifact(target, "nmap_quick", result)
        return ports
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] Port scan failed: {e}{Style.RESET_ALL}")
        return []

def select_port_for_gobuster():
    """Helper function to manually select port for Gobuster"""
    print(f"\n{Fore.CYAN}Enter port number to run Gobuster (or 'q' to skip):{Style.RESET_ALL}")
    while True:
        try:
            choice = input("Port number: ").strip()
            if choice.lower() == 'q':
                return None
            port = int(choice)
            if 1 <= port <= 65535:
                return str(port)
            print(f"{Fore.RED}[!] Port must be between 1-65535{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}[!] Please enter a valid port number or 'q'{Style.RESET_ALL}")

def run_gobuster(target, port, wordlist="/usr/share/wordlists/dirb/common.txt"):
    if not port:
        return
        
    print(f"{Fore.CYAN}[*] Running Gobuster on port {port}...{Style.RESET_ALL}")
    try:
        check_tool_installed("gobuster")
        
        if not os.path.exists(wordlist):
            print(f"{Fore.YELLOW}[!] Default wordlist not found at {wordlist}{Style.RESET_ALL}")
            wordlist = input("Enter path to wordlist file: ").strip()
            if not os.path.exists(wordlist):
                raise ScanError(f"Wordlist file not found: {wordlist}")
        
        url = f"http://{target}:{port}"
        command = f"gobuster dir -u {url} -w {wordlist} -t 50 -x php,html,txt"
        result = run_tool_with_timeout(command, timeout=600)
        
        save_scan_artifact(target, f"gobuster_{port}", result)
        if result.strip():
            print(f"{Fore.GREEN}[+] Gobuster results for {url}:{Style.RESET_ALL}\n{result}")
            if "Status: 200" in result or "Status: 301" in result or "Status: 302" in result:
                vulnerabilities.append(f"Gobuster found accessible directories/files on port {port}")
        else:
            print(f"{Fore.YELLOW}[!] No Gobuster results for {url}{Style.RESET_ALL}")
    except ScanTimeoutError as e:
        print(f"{Fore.RED}[!] Gobuster timed out on port {port}: {e}{Style.RESET_ALL}")
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Gobuster failed on port {port}: {e}{Style.RESET_ALL}")

def run_whatweb(target, ports):
    print(f"{Fore.CYAN}[*] Running WhatWeb...{Style.RESET_ALL}")
    if not ports:
        print(f"{Fore.YELLOW}[!] Skipping WhatWeb - No HTTP/HTTPS ports found.{Style.RESET_ALL}")
        return
    
    for port, scheme in ports[:2]:  # Limit to first 2 ports
        url = f"{scheme}://{target}:{port}"
        try:
            check_tool_installed("whatweb")
            result = run_tool_with_timeout(f"whatweb {url}", timeout=120)
            save_scan_artifact(target, f"whatweb_{port}", result, "json")
            if result.strip():
                print(f"{Fore.GREEN}[+] WhatWeb results for {url}:{Style.RESET_ALL}\n{result}")
            else:
                print(f"{Fore.YELLOW}[!] No WhatWeb results for {url}{Style.RESET_ALL}")
        except ScanTimeoutError as e:
            print(f"{Fore.RED}[!] WhatWeb timed out on port {port}: {e}{Style.RESET_ALL}")
        except ToolNotFoundError as e:
            print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}[!] WhatWeb failed on port {port}: {e}{Style.RESET_ALL}")

def run_searchsploit(target):
    print(f"{Fore.CYAN}[*] Running Searchsploit...{Style.RESET_ALL}")
    try:
        check_tool_installed("searchsploit")
        result = run_tool_with_timeout(f"searchsploit {target}", timeout=180)
        save_scan_artifact(target, "searchsploit", result)
        print(result)
    except ScanTimeoutError as e:
        print(f"{Fore.RED}[!] Searchsploit timed out: {e}{Style.RESET_ALL}")
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Searchsploit failed: {e}{Style.RESET_ALL}")

def run_wafw00f(target):
    print(f"{Fore.CYAN}[*] Running WafW00f...{Style.RESET_ALL}")
    try:
        check_tool_installed("wafw00f")
        result = run_tool_with_timeout(f"wafw00f http://{target}", timeout=120)
        save_scan_artifact(target, "wafw00f", result)
        print(result)
    except ScanTimeoutError as e:
        print(f"{Fore.RED}[!] WafW00f timed out: {e}{Style.RESET_ALL}")
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] WafW00f failed: {e}{Style.RESET_ALL}")

def run_sslyze(target):
    print(f"{Fore.CYAN}[*] Running SSLyze...{Style.RESET_ALL}")
    try:
        check_tool_installed("sslyze")
        result = run_tool_with_timeout(f"sslyze --regular {target}", timeout=300)
        save_scan_artifact(target, "sslyze", result)
        print(result)
    except ScanTimeoutError as e:
        print(f"{Fore.RED}[!] SSLyze timed out: {e}{Style.RESET_ALL}")
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] SSLyze failed: {e}{Style.RESET_ALL}")

def run_nmap(target):
    print(f"{Fore.CYAN}[*] Running Nmap...{Style.RESET_ALL}")
    try:
        check_tool_installed("nmap")
        result = run_tool_with_timeout(f"nmap -Pn -sV --script vuln {target}", timeout=600)
        save_scan_artifact(target, "nmap", result, "txt")
        if "VULNERABLE" in result.upper():
            vulnerabilities.append("Nmap found vulnerabilities.")
            for cve in extract_cves(result):
                vulnerabilities.append(f"Nmap: {cve}")
    except ScanTimeoutError as e:
        print(f"{Fore.RED}[!] Nmap timed out: {e}{Style.RESET_ALL}")
    except ToolNotFoundError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Nmap failed: {e}{Style.RESET_ALL}")

def run_advanced_nmap(target):
    """Stealthy Nmap scan with real-time progress tracking"""
    print(f"{Fore.CYAN}[*] Starting Advanced Nmap (Stealth Mode) on {target}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Note: Stealth scans are slower (~3-5x normal scan time){Style.RESET_ALL}")

    try:
        check_tool_installed("nmap")
        command = [
            "nmap",
            "-Pn",                  # No host discovery
            "-sS",                  # SYN scan (works with fragmentation)
            "-T3",                  # Balanced timing
            "--scan-delay", "2s",   # Delay between probes
            "-f",                   # Fragment packets
            "--max-retries", "2",
            "--stats-every", "5s",  # Progress updates
            target
        ]

        # Start process with real-time output
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Progress tracking
        start_time = time.time()
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            
            if "Stats:" in line:
                elapsed = int(time.time() - start_time)
                mins, secs = divmod(elapsed, 60)
                print(f"{Fore.YELLOW}[Progress] {mins}m{secs}s elapsed{Style.RESET_ALL}")

        if proc.returncode == 0:
            output = proc.stdout.read()
            save_scan_artifact(target, "nmap_advanced", output, "txt")
            
            duration = time.time() - start_time
            mins, secs = divmod(int(duration), 60)
            print(f"{Fore.GREEN}[+] Scan completed in {mins}m{secs}s{Style.RESET_ALL}")
            
            # Check for vulnerabilities
            if "VULNERABLE" in output.upper():
                vulnerabilities.append("Advanced Nmap found vulnerabilities.")
                for cve in extract_cves(output):
                    vulnerabilities.append(f"Advanced Nmap: {cve}")
            return output
        else:
            err = proc.stderr.read()
            print(f"{Fore.RED}[!] Failed (code {proc.returncode}): {err}{Style.RESET_ALL}")
            return None

    except Exception as e:
        print(f"{Fore.RED}[!] Advanced Nmap error: {e}{Style.RESET_ALL}")
        return None

def run_nikto_single_port(target, port, scheme, scan_mode="standard"):
    """Run Nikto on a single port with configurable scan modes"""
    url = f"{scheme}://{target}:{port}"
    try:
        check_tool_installed("nikto")
        
        # Configure scan parameters based on mode
        if scan_mode == "quick":
            cmd = f"nikto -h {url} -Tuning x 6 -timeout 3 -maxtime 120"  # Fast scan (2 min)
            print(f"{Fore.CYAN}[*] Running QUICK Nikto scan on port {port} (2 min max){Style.RESET_ALL}")
        elif scan_mode == "deep":
            cmd = f"nikto -h {url} -C all -timeout 5 -maxtime 1800"  # Deep scan (30 min)
            print(f"{Fore.CYAN}[*] Running DEEP Nikto scan on port {port} (30 min max){Style.RESET_ALL}")
        else:  # standard
            cmd = f"nikto -h {url} -Tuning xb -timeout 3 -maxtime 600"  # Standard (10 min)
            print(f"{Fore.CYAN}[*] Running STANDARD Nikto scan on port {port} (10 min max){Style.RESET_ALL}")
        
        # Start process with progress tracking
        proc = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Progress tracking
        start_time = time.time()
        last_update = start_time
        
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
                
            current_time = time.time()
            if current_time - last_update > 15:  # Update every 15 seconds
                elapsed = int(current_time - start_time)
                mins, secs = divmod(elapsed, 60)
                print(f"{Fore.YELLOW}[*] Nikto on port {port} running for {mins}m{secs}s...{Style.RESET_ALL}")
                last_update = current_time
        
        result = proc.stdout.read()
        save_scan_artifact(target, f"nikto_{port}_{scan_mode}", result)
        
        if "OSVDB" in result or "potentially" in result.lower():
            vulnerabilities.append(f"Nikto found potential vulnerabilities on port {port} ({scan_mode} scan).")
            for cve in extract_cves(result):
                vulnerabilities.append(f"Nikto: {cve}")
                
        return result
        
    except Exception as e:
        print(f"{Fore.RED}[!] Nikto failed on port {port}: {e}{Style.RESET_ALL}")
        return None

def run_nikto(target, ports):
    """Improved Nikto with configurable scan modes and parallel execution"""
    if not ports:
        print(f"{Fore.YELLOW}[!] Skipping Nikto - No HTTP/HTTPS ports found.{Style.RESET_ALL}")
        return
    
    # Let user select scan mode
    print("\nNikto Scan Options:")
    print("1 - Quick Scan (2 minutes per port, basic tests)")
    print("2 - Standard Scan (10 minutes per port, balanced tests)")
    print("3 - Deep Scan (30 minutes per port, all tests)")
    print("4 - Skip Nikto")
    
    while True:
        choice = input("Your choice (1-4): ").strip()
        if choice in ('1', '2', '3', '4'):
            break
        print(f"{Fore.RED}[!] Invalid choice. Please enter 1, 2, 3, or 4.{Style.RESET_ALL}")
    
    if choice == '4':
        return
    
    scan_mode = {
        '1': 'quick',
        '2': 'standard',
        '3': 'deep'
    }[choice]
    
    # Limit to first 3 ports for parallel scanning
    ports_to_scan = ports[:3]
    
    # Run scans in parallel (max 2 at a time)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for port, scheme in ports_to_scan:
            futures.append(
                executor.submit(
                    run_nikto_single_port,
                    target, port, scheme, scan_mode
                )
            )
        
        # Wait for completion
        for future in futures:
            try:
                future.result()  # Get results (or raise exceptions)
            except Exception as e:
                print(f"{Fore.RED}[!] Nikto scan failed: {e}{Style.RESET_ALL}")

def run_subfinder(target):
    """Run Subfinder for subdomain enumeration"""
    print(f"{Fore.CYAN}[*] Running Subfinder for subdomain discovery...{Style.RESET_ALL}")
    try:
        check_tool_installed("subfinder")
        output_file = f"subfinder_{target}.txt"
        cmd = f"subfinder -d {target} -silent -o {output_file}"
        result = run_tool_with_timeout(cmd, timeout=300)
        
        with open(output_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.GREEN}[+] Subfinder found {len(subdomains)} subdomains")
        save_scan_artifact(target, "subfinder", "\n".join(subdomains))
        return subdomains
    except Exception as e:
        print(f"{Fore.RED}[!] Subfinder failed: {e}{Style.RESET_ALL}")
        return []

def run_amass(target):
    """Run Amass for comprehensive subdomain discovery"""
    print(f"{Fore.CYAN}[*] Running Amass for deep subdomain enumeration...{Style.RESET_ALL}")
    try:
        check_tool_installed("amass")
        output_file = f"amass_{target}.txt"
        cmd = f"amass enum -passive -d {target} -o {output_file}"
        result = run_tool_with_timeout(cmd, timeout=600)
        
        with open(output_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.GREEN}[+] Amass found {len(subdomains)} subdomains")
        save_scan_artifact(target, "amass", "\n".join(subdomains))
        return subdomains
    except Exception as e:
        print(f"{Fore.RED}[!] Amass failed: {e}{Style.RESET_ALL}")
        return []

def extract_cves(text):
    try:
        return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())))
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error extracting CVEs: {e}{Style.RESET_ALL}")
        return []

def lookup_cve(cve_id):
    print(f"{Fore.YELLOW}[*] Looking up {cve_id}...{Style.RESET_ALL}")
    try:
        response = requests.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            summary = data.get("summary", "No summary available")
            cvss = data.get("cvss", "N/A")
            return f"{cve_id} (CVSS: {cvss}) - {summary}"
        elif response.status_code == 404:
            return f"{cve_id} - CVE not found in database."
        else:
            return f"{cve_id} - API returned status {response.status_code}"
    except requests.exceptions.Timeout:
        return f"{cve_id} - CVE lookup timed out"
    except requests.exceptions.RequestException as e:
        return f"{cve_id} - Error fetching CVE info: {e}"
    except Exception as e:
        return f"{cve_id} - Unexpected error: {e}"

def check_metasploit_module(cve_id):
    """Check if Metasploit has an exploit module for a CVE"""
    try:
        check_tool_installed("msfconsole")
        result = run_tool_with_timeout(
            f"msfconsole -q -x 'search {cve_id}; exit'", 
            timeout=30
        )
        
        if "exploit/" in result:
            modules = re.findall(r"exploit/.*", result)
            return list(set(modules))  # Deduplicate
        return None
    
    except Exception as e:
        print(f"{Fore.RED}[!] Metasploit search failed: {e}{Style.RESET_ALL}")
        return None

def confirm_exploitation(target, module, cve):
    """Get explicit confirmation before running any exploits"""
    print(EXPLOIT_DISCLAIMER)
    print(f"\n{Fore.RED}[!] EXPLOITATION WARNING{Style.RESET_ALL}")
    print(f"Target: {target}")
    print(f"Module: {module}")
    print(f"CVE: {cve}")
    
    while True:
        confirm = input(f"{Fore.RED}Do you want to proceed with this exploit? (yes/NO): {Style.RESET_ALL}").lower()
        if confirm == 'no' or confirm == '':
            return False
        elif confirm == 'yes':
            # Require additional verification
            verify = input("Type 'CONFIRM EXPLOIT' to proceed: ")
            if verify.strip().upper() == "CONFIRM EXPLOIT":
                return True
        else:
            print(f"{Fore.YELLOW}Please enter 'yes' or 'no'{Style.RESET_ALL}")

def run_metasploit_exploit(module, target, port=None):
    """Run a Metasploit exploit module with safety checks"""
    try:
        if not confirm_exploitation(target, module, "Associated CVE"):
            print(f"{Fore.YELLOW}[!] Exploitation cancelled by user{Style.RESET_ALL}")
            return None
            
        print(f"{Fore.YELLOW}[*] Preparing to run {module} against {target}:{port or 'default'}{Style.RESET_ALL}")
        
        # Safety countdown
        for i in range(5, 0, -1):
            print(f"{Fore.RED}[!] Starting exploit in {i} seconds (CTRL+C to abort){Style.RESET_ALL}")
            time.sleep(1)
            
        cmd = f"msfconsole -q -x 'use {module}; set RHOSTS {target};"
        if port:
            cmd += f" set RPORT {port};"
        cmd += " run; exit'"
        
        result = run_tool_with_timeout(cmd, timeout=120)
        
        # Enhanced logging
        exploit_log = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "target": target,
            "port": port,
            "output": result,
            "success": "succeeded" in result.lower()
        }
        
        save_scan_artifact(target, f"metasploit_{module.replace('/', '_')}", exploit_log, "json")
        
        if exploit_log["success"]:
            vulnerabilities.append(f"Metasploit exploit succeeded: {module}")
            print(f"{Fore.GREEN}[+] Exploit successful!{Style.RESET_ALL}")
            # Post-exploitation recommendations
            print(f"{Fore.CYAN}[*] Recommended actions:")
            print("- Change compromised credentials")
            print("- Patch vulnerable service")
            print("- Isolate affected system")
        else:
            print(f"{Fore.RED}[!] Exploit failed.{Style.RESET_ALL}")
            
        return result
        
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Exploitation aborted by user{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Exploit failed: {e}{Style.RESET_ALL}")
        return None

def handle_cve_exploitation(target, ports):
    """Handle the full CVE to exploitation workflow"""
    if not vulnerabilities:
        print(f"{Fore.YELLOW}[!] No vulnerabilities found to exploit{Style.RESET_ALL}")
        return
    
    # Extract unique CVEs from found vulnerabilities
    cves = set()
    for vuln in vulnerabilities:
        if "CVE-" in vuln:
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", vuln)
            if cve_match:
                cves.add(cve_match.group())
    
    if not cves:
        print(f"{Fore.YELLOW}[!] No CVEs found in vulnerabilities{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.MAGENTA}=== CVE Exploitation Analysis ==={Style.RESET_ALL}")
    
    exploit_modules = {}
    for cve in sorted(cves):
        print(f"\n{Fore.CYAN}[*] Checking exploit for {cve}{Style.RESET_ALL}")
        
        # Lookup CVE details
        cve_details = lookup_cve(cve)
        print(f"{Fore.WHITE}{cve_details}{Style.RESET_ALL}")
        
        # Check Metasploit for modules
        modules = check_metasploit_module(cve)
        if modules:
            print(f"{Fore.GREEN}[+] Available Metasploit modules:{Style.RESET_ALL}")
            for i, module in enumerate(modules, 1):
                print(f"{i}. {module}")
            exploit_modules[cve] = modules
        else:
            print(f"{Fore.YELLOW}[-] No Metasploit modules found{Style.RESET_ALL}")
    
    if not exploit_modules:
        print(f"{Fore.YELLOW}[!] No exploit modules available for any CVEs{Style.RESET_ALL}")
        return
    
    # Get user selection of which exploits to attempt
    print(f"\n{Fore.MAGENTA}=== Exploit Selection ==={Style.RESET_ALL}")
    selected_exploits = []
    
    for cve, modules in exploit_modules.items():
        print(f"\n{Fore.CYAN}CVE: {cve}{Style.RESET_ALL}")
        for i, module in enumerate(modules, 1):
            while True:
                choice = input(f"Attempt exploit {i} ({module})? [y/n]: ").lower()
                if choice in ('y', 'n'):       
                    if choice == 'y':
                        selected_exploits.append((cve, module))
                    break
                print(f"{Fore.RED}[!] Please enter 'y' or 'n'{Style.RESET_ALL}")
    
    if not selected_exploits:
        print(f"{Fore.YELLOW}[!] No exploits selected{Style.RESET_ALL}")
        return
    
    # Execute selected exploits with confirmation
    print(f"\n{Fore.MAGENTA}=== Exploitation Confirmation ==={Style.RESET_ALL}")
    print(f"{Fore.RED}[!] WARNING: The following actions may disrupt the target system{Style.RESET_ALL}")
    print("Selected exploits:")
    for cve, module in selected_exploits:
        print(f"- {module} (for {cve})")
    
    confirm = input(f"\n{Fore.RED}Type 'LAUNCH EXPLOITS' to confirm execution: {Style.RESET_ALL}")
    if confirm.strip().upper() != "LAUNCH EXPLOITS":
        print(f"{Fore.YELLOW}[!] Exploitation cancelled{Style.RESET_ALL}")
        return
    
    # Run the exploits
    print(f"\n{Fore.MAGENTA}=== Starting Exploitation ==={Style.RESET_ALL}")
    for cve, module in selected_exploits:
        print(f"\n{Fore.CYAN}[*] Attempting {module} for {cve}{Style.RESET_ALL}")
        
        # Find appropriate port if available
        exploit_port = None
        for port, scheme in ports:
            if scheme == 'https' and 'ssl' in module.lower():
                exploit_port = port
                break
            elif scheme == 'http':
                exploit_port = port
        
        # Run with countdown
        for i in range(5, 0, -1):
            print(f"{Fore.RED}Launching in {i}... (CTRL+C to abort){Style.RESET_ALL}")
            time.sleep(1)
        
        result = run_metasploit_exploit(module, target, exploit_port)
        
        if result and "succeeded" in result.lower():
            vulnerabilities.append(f"Successful exploit: {module} for {cve}")
        elif result:
            vulnerabilities.append(f"Failed exploit attempt: {module} for {cve}")

def run_all_scans(target, ports):
    """Run all available scans (full scan mode)"""
    run_subfinder(target)
    run_amass(target)
    run_nmap(target)
    run_nikto(target, ports)
    run_whatweb(target, ports)
    run_searchsploit(target)
    run_wafw00f(target)
    run_sslyze(target)
    if ports:
        run_gobuster(target, ports[0][0])

def run_default_scan(target, ports):
    """Default scan includes Subfinder and standard tools"""
    run_subfinder(target)
    run_nmap(target)
    run_nikto(target, ports)
    run_whatweb(target, ports)
    if ports:
        run_gobuster(target, ports[0][0])

def run_manual_scan(target, ports):
    """Manual scan with tool selection menu"""
    print("\nSelect tools (comma separated):")
    print("1 - Nmap (Default)\n2 - Advanced Nmap (Stealth) [SLOW]\n3 - Nikto\n4 - WhatWeb\n5 - Searchsploit")
    print("6 - WafW00f\n7 - SSLyze\n8 - Gobuster\n9 - Subfinder\n10 - Amass")
    
    while True:
        selected = input("Your choices (e.g., 1,3,8): ").split(',')
        selected = [s.strip() for s in selected if s.strip()]
        if selected and all(s in ('1','2','3','4','5','6','7','8','9','10') for s in selected):
            break
        print(f"{Fore.RED}[!] Invalid selection. Choose numbers 1-10 separated by commas.{Style.RESET_ALL}")
    
    tool_map = {
        '1': lambda t, _: run_nmap(t),
        '2': lambda t, _: run_advanced_nmap(t),
        '3': run_nikto,
        '4': run_whatweb,
        '5': lambda t, _: run_searchsploit(t),
        '6': lambda t, _: run_wafw00f(t),
        '7': lambda t, _: run_sslyze(t),
        '8': lambda t, _: run_gobuster(t, select_port_for_gobuster()),
        '9': lambda t, _: run_subfinder(t),
        '10': lambda t, _: run_amass(t)
    }
    
    for tool_id in selected:
        tool = tool_map.get(tool_id)
        if tool:
            try:
                tool(target, ports if tool.__name__ in ('run_nikto', 'run_whatweb') else None)
            except Exception as e:
                print(f"{Fore.RED}[!] Tool {tool_id} failed: {e}{Style.RESET_ALL}")

def main():
    try:
        start_time = time.time()
        animated_banner()
        
        # Network discovery
        netdiscover_choice = input("Do you want to run Netdiscover? (yes/no): ").lower()
        if netdiscover_choice == "yes":
            discover_hosts()
        elif netdiscover_choice != "no":
            print(f"{Fore.YELLOW}[!] Invalid choice, skipping network discovery.{Style.RESET_ALL}")

        # Target input
        while True:
            target = input("Enter target domain or ip: ").strip()
            if target:
                break
            print(f"{Fore.RED}[!] Target cannot be empty.{Style.RESET_ALL}")

        # Port scanning
        ports = []
        try:
            ports = get_http_ports(target)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to scan ports: {e}{Style.RESET_ALL}")
            if input("Continue without port scan results? (yes/no): ").lower() != 'yes':
                return

        # Scan mode selection
        print("\nChoose scan mode:")
        print("1 - Default (Subfinder + Nmap + Nikto + WhatWeb + Gobuster)")
        print("2 - Manual (Choose tools)")
        print("3 - Full Scan (All tools including Amass)")
        
        while True:
            choice = input("Enter your choice (1/2/3): ").strip()
            if choice in ('1', '2', '3'):
                break
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

        if choice == '1':
            run_default_scan(target, ports)
        elif choice == '2':
            run_manual_scan(target, ports)
        elif choice == '3':
            run_all_scans(target, ports)

        # Post-scan reporting
        scan_duration = time.time() - start_time
        save_metadata(target, 
                     "full" if choice == '3' else "default", 
                     scan_duration)
        generate_summary(target)

        # Vulnerability reporting and exploitation
        print(f"\n{Fore.MAGENTA}=== Vulnerabilities Found ==={Style.RESET_ALL}")
        for v in vulnerabilities:
            if "CVE-" in v:
                print(f"{Fore.RED}[!] {v}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] {v}{Style.RESET_ALL}")
        
        if vulnerabilities:
            print(f"{Fore.GREEN}[+] Found {len(vulnerabilities)} potential vulnerabilities.{Style.RESET_ALL}")
            cve_choice = input("\nDo you want to analyze CVEs for exploitation? (yes/no): ").lower()
            if cve_choice == 'yes':
                handle_cve_exploitation(target, ports)
        else:
            print(f"{Fore.GREEN}[+] No vulnerabilities found.{Style.RESET_ALL}")
            
        print(Fore.GREEN + "[+] Scan completed.\n" + Style.RESET_ALL)
        print('\a')  # beep

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user." + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
