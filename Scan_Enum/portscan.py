"""
Port Scanning Module
AI-powered port scanning and enumeration
"""

import subprocess
import socket
import json
from modules.report_utils import append_section

def run(target, report_path=None, level='basic', ports=None):
    """Run AI-powered port scanning against target."""
    print(f"[+] Starting AI-powered port scanning against {target}")
    
    results = {
        'target': target,
        'level': level,
        'ports_scanned': [],
        'open_ports': [],
        'services': {},
        'ai_analysis': {}
    }
    
    # AI analysis integration
    try:
        from modules.ai_engine import HackingAI
        ai_engine = HackingAI()
        if ai_engine.is_ai_available():
            ai_analysis = ai_engine.analyze_recon_target(target, "active", level)
            results['ai_analysis'] = ai_analysis
            print(f"[+] AI Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk level")
    except ImportError:
        print("[!] AI engine not available, continuing with standard scanning")
    
    # Determine ports to scan based on level
    if ports:
        port_list = [int(p) for p in ports.split(',')]
    elif level == 'basic':
        port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    elif level == 'intermediate':
        port_list = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]
    elif level == 'advanced':
        port_list = list(range(1, 65536))
    else:  # stealth
        port_list = [22, 80, 443, 8080, 8443]
    
    results['ports_scanned'] = port_list
    
    print(f"[*] Scanning {len(port_list)} ports at {level} level...")
    
    # Basic port scanning
    open_ports = []
    services = {}
    
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
                service_name = get_service_name(port)
                services[port] = {
                    'name': service_name,
                    'status': 'open',
                    'banner': get_banner(target, port)
                }
                print(f"[+] Port {port}/tcp open - {service_name}")
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
    
    results['open_ports'] = open_ports
    results['services'] = services
    
    # Advanced scanning based on level
    if level in ['intermediate', 'advanced', 'stealth'] and open_ports:
        print("[*] Running advanced port analysis...")
        
        # Service version detection
        for port in open_ports:
            if port in [22, 21, 23, 25, 80, 443]:
                version_info = get_service_version(target, port)
                if version_info:
                    services[port]['version'] = version_info
    
    # Nmap integration for advanced scanning
    if level in ['advanced', 'stealth'] and open_ports:
        print("[*] Running Nmap service detection...")
        try:
            nmap_result = run_nmap_scan(target, open_ports)
            if nmap_result:
                results['nmap_results'] = nmap_result
        except Exception as e:
            print(f"[!] Nmap scan failed: {e}")
    
    # Generate recommendations based on findings
    recommendations = []
    if open_ports:
        recommendations.append(f"Found {len(open_ports)} open ports")
        
        # Security recommendations based on open services
        if 22 in open_ports:
            recommendations.append("SSH service detected - consider key-based authentication")
        if 23 in open_ports:
            recommendations.append("Telnet service detected - highly insecure, recommend disabling")
        if 80 in open_ports and 443 not in open_ports:
            recommendations.append("HTTP service detected without HTTPS - recommend enabling SSL/TLS")
        if 21 in open_ports:
            recommendations.append("FTP service detected - consider using SFTP instead")
    
    # Add AI-powered recommendations if available
    if 'ai_analysis' in results and results['ai_analysis']:
        ai_recommendations = results['ai_analysis'].get('ai_analysis', {}).get('next_steps', [])
        recommendations.extend(ai_recommendations)
    
    # Add to report
    if report_path:
        append_section(
            report_path,
            "AI-Powered Port Scanning",
            f"Comprehensive port scanning at {level} level using AI analysis",
            [
                f"nmap -sS -sV -O {target}",
                f"nmap -p- {target}",
                f"nmap --script vuln {target}"
            ],
            {
                'open_ports': open_ports,
                'services': services,
                'scan_level': level,
                'total_ports_scanned': len(port_list)
            },
            [f"Level: {level}", f"Target: {target}", f"Open ports: {len(open_ports)}"],
            recommendations,
            results
        )
    
    print(f"[+] AI-powered port scanning completed for {target}")
    print(f"[+] Found {len(open_ports)} open ports")
    return results

def get_service_name(port):
    """Get service name for common ports."""
    common_services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9000: 'Web'
    }
    return common_services.get(port, 'Unknown')

def get_banner(target, port):
    """Get service banner for a port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        sock.send(b'\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except:
        return None

def get_service_version(target, port):
    """Get service version information."""
    try:
        if port == 22:  # SSH
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            version = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return version
        elif port == 80:  # HTTP
            import requests
            response = requests.get(f"http://{target}", timeout=5)
            server = response.headers.get('Server', 'Unknown')
            return f"Server: {server}"
        elif port == 443:  # HTTPS
            import requests
            response = requests.get(f"https://{target}", timeout=5, verify=False)
            server = response.headers.get('Server', 'Unknown')
            return f"Server: {server}"
    except:
        return None
    return None

def run_nmap_scan(target, ports):
    """Run Nmap scan for detailed service information."""
    try:
        port_str = ','.join(map(str, ports))
        cmd = ['nmap', '-sS', '-sV', '-O', '-p', port_str, target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return {
                'status': 'success',
                'output': result.stdout,
                'ports': ports
            }
        else:
            return {
                'status': 'failed',
                'error': result.stderr
            }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {
            'status': 'not_available',
            'note': 'nmap command not available or timed out'
        } 