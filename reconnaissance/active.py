"""
Active Reconnaissance Module

This module handles active reconnaissance tasks for the AI-powered ethical hacking tool.
Implements beginner, intermediate, advanced/master, and stealth workflows.
"""
import subprocess
import platform
import os
from modules import report_utils

def run_basic(target, report_path):
    """Beginner: Ping sweep, basic port scan, banner grabbing, traceroute."""
    print(f"[Active Recon - Basic] Running ping sweep, port scan, banner grabbing, and traceroute on: {target}")
    results = {}
    commands = []
    notable = []
    recommendations = []
    system = platform.system().lower()

    # 1. Ping Sweep
    try:
        if system == 'windows':
            ping_cmd = ['ping', '-n', '2', target]
        else:
            ping_cmd = ['ping', '-c', '2', target]
        ping_out = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, text=True)
        results['ping'] = ping_out
        commands.append(' '.join(ping_cmd))
    except Exception as e:
        results['ping'] = f"Error: {e}"

    # 2. Basic Port Scan (Nmap)
    try:
        nmap_cmd = ['nmap', '-Pn', '-sS', '-T4', '-F', target]
        nmap_out = subprocess.check_output(nmap_cmd, stderr=subprocess.STDOUT, text=True)
        results['nmap_port_scan'] = nmap_out
        commands.append(' '.join(nmap_cmd))
        if 'open' in nmap_out:
            notable.append("Open ports detected in fast scan.")
    except Exception as e:
        results['nmap_port_scan'] = f"Error: {e}"

    # 3. Banner Grabbing (Nmap Service Version)
    try:
        nmap_sv_cmd = ['nmap', '-sV', target]
        nmap_sv_out = subprocess.check_output(nmap_sv_cmd, stderr=subprocess.STDOUT, text=True)
        results['nmap_banner_grab'] = nmap_sv_out
        commands.append(' '.join(nmap_sv_cmd))
    except Exception as e:
        results['nmap_banner_grab'] = f"Error: {e}"

    # 4. Traceroute
    try:
        if system == 'windows':
            trace_cmd = ['tracert', target]
        else:
            trace_cmd = ['traceroute', target]
        trace_out = subprocess.check_output(trace_cmd, stderr=subprocess.STDOUT, text=True)
        results['traceroute'] = trace_out
        commands.append(' '.join(trace_cmd))
    except Exception as e:
        results['traceroute'] = f"Error: {e}"

    # Recommendations
    if 'open' in results.get('nmap_port_scan', ''):
        recommendations.append("Restrict unnecessary open ports and services.")
    recommendations.append("Review firewall and network segmentation.")

    # Append to report
    report_utils.append_section(
        report_path,
        section_title="Active Recon - Basic",
        methodology="Ping sweep, fast port scan, banner grabbing, and traceroute using system tools and Nmap.",
        commands=commands,
        findings=results,
        notable=notable,
        recommendations=recommendations,
        raw_output=results
    )
    return {
        "status": "success",
        "level": "basic",
        "target": target,
        "results": results
    }

def run_stealth(target, report_path):
    """Stealth: Use Nmap stealth techniques to evade detection (SYN scan, slow timing, fragmented packets, decoys, source port, data length)."""
    print(f"[Active Recon - Stealth] Running stealthy Nmap scan on: {target}")
    results = {}
    commands = []
    notable = []
    recommendations = []
    try:
        nmap_cmd = [
            'nmap', '-sS', '-T1', '-f', '-D', 'RND:5', '-g', '53', '--data-length', '100', target
        ]
        nmap_out = subprocess.check_output(nmap_cmd, stderr=subprocess.STDOUT, text=True)
        results['nmap_stealth_scan'] = nmap_out
        commands.append(' '.join(nmap_cmd))
        if 'open' in nmap_out:
            notable.append("Open ports detected in stealth scan.")
    except Exception as e:
        results['nmap_stealth_scan'] = f"Error: {e}"
    recommendations.append("Monitor for stealthy scans and anomalous traffic.")
    report_utils.append_section(
        report_path,
        section_title="Active Recon - Stealth",
        methodology="Stealthy Nmap scan with SYN, slow timing, fragmentation, decoys, and source port manipulation.",
        commands=commands,
        findings=results,
        notable=notable,
        recommendations=recommendations,
        raw_output=results
    )
    return {
        "status": "success",
        "level": "stealth",
        "target": target,
        "results": results
    }

def run_intermediate(target, report_path):
    """Intermediate: Service enumeration, OS fingerprinting, vuln scanning, web scanning, dir brute-forcing."""
    print(f"[Active Recon - Intermediate] Running service enumeration, OS fingerprinting, vuln scanning, web scanning, and dir brute-forcing on: {target}")
    results = {}
    commands = []
    notable = []
    recommendations = []
    system = platform.system().lower()

    # 1. Service Enumeration (Nmap NSE, enum4linux, snmpwalk)
    try:
        nmap_smb_cmd = ['nmap', '--script', 'smb-enum-shares,smb-enum-users', '-p', '445', target]
        results['nmap_smb_enum'] = subprocess.check_output(nmap_smb_cmd, stderr=subprocess.STDOUT, text=True)
        commands.append(' '.join(nmap_smb_cmd))
    except Exception as e:
        results['nmap_smb_enum'] = f"Error: {e}"
    try:
        nmap_ftp_cmd = ['nmap', '--script', 'ftp-anon,ftp-bounce', '-p', '21', target]
        results['nmap_ftp_enum'] = subprocess.check_output(nmap_ftp_cmd, stderr=subprocess.STDOUT, text=True)
        commands.append(' '.join(nmap_ftp_cmd))
    except Exception as e:
        results['nmap_ftp_enum'] = f"Error: {e}"
    try:
        nmap_snmp_cmd = ['nmap', '--script', 'snmp-info', '-p', '161', target]
        results['nmap_snmp_enum'] = subprocess.check_output(nmap_snmp_cmd, stderr=subprocess.STDOUT, text=True)
        commands.append(' '.join(nmap_snmp_cmd))
    except Exception as e:
        results['nmap_snmp_enum'] = f"Error: {e}"
    try:
        results['enum4linux'] = subprocess.check_output(['enum4linux', '-a', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"enum4linux -a {target}")
    except Exception as e:
        results['enum4linux'] = f"Error: {e}"
    try:
        results['snmpwalk'] = subprocess.check_output(['snmpwalk', '-v', '2c', '-c', 'public', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"snmpwalk -v 2c -c public {target}")
    except Exception as e:
        results['snmpwalk'] = f"Error: {e}"

    # 2. OS Fingerprinting
    try:
        nmap_os_cmd = ['nmap', '-O', target]
        results['nmap_os_fingerprint'] = subprocess.check_output(nmap_os_cmd, stderr=subprocess.STDOUT, text=True)
        commands.append(' '.join(nmap_os_cmd))
    except Exception as e:
        results['nmap_os_fingerprint'] = f"Error: {e}"

    # 3. Vulnerability Scanning
    try:
        nmap_vuln_cmd = ['nmap', '--script', 'vuln', target]
        results['nmap_vuln_scan'] = subprocess.check_output(nmap_vuln_cmd, stderr=subprocess.STDOUT, text=True)
        commands.append(' '.join(nmap_vuln_cmd))
    except Exception as e:
        results['nmap_vuln_scan'] = f"Error: {e}"
    try:
        results['nikto'] = subprocess.check_output(['nikto', '-h', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"nikto -h {target}")
    except Exception as e:
        results['nikto'] = f"Error: {e}"

    # 4. Web Scanning (Nikto)
    # Already included above

    # 5. Directory Brute-Forcing (gobuster/dirb)
    try:
        results['gobuster'] = subprocess.check_output(['gobuster', 'dir', '-u', f'http://{target}', '-w', '/usr/share/wordlists/dirb/common.txt'], stderr=subprocess.STDOUT, text=True)
        commands.append(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt")
    except Exception as e:
        results['gobuster'] = f"Error: {e}"
    try:
        results['dirb'] = subprocess.check_output(['dirb', f'http://{target}'], stderr=subprocess.STDOUT, text=True)
        commands.append(f"dirb http://{target}")
    except Exception as e:
        results['dirb'] = f"Error: {e}"

    # Notable/Recommendations
    if 'open' in results.get('nmap_vuln_scan', ''):
        notable.append("Potential vulnerabilities detected in Nmap vuln scan.")
    recommendations.append("Review and patch vulnerabilities, restrict unnecessary services, and harden web applications.")

    report_utils.append_section(
        report_path,
        section_title="Active Recon - Intermediate",
        methodology="Service enumeration, OS fingerprinting, vulnerability scanning, web scanning, and directory brute-forcing using Nmap, enum4linux, snmpwalk, nikto, gobuster, and dirb.",
        commands=commands,
        findings=results,
        notable=notable,
        recommendations=recommendations,
        raw_output=results
    )
    return {
        "status": "success",
        "level": "intermediate",
        "target": target,
        "results": results
    }

def run_advanced(target, report_path):
    """Advanced/Master: Custom packet crafting, proxy/Tor, timing randomization, wireless/IoT, post-exploitation, advanced web fuzzing."""
    print(f"[Active Recon - Advanced] Running advanced recon techniques on: {target}")
    results = {}
    commands = []
    notable = []
    recommendations = []
    system = platform.system().lower()

    # 1. Custom Packet Crafting (Scapy/hping3)
    try:
        results['hping3_syn'] = subprocess.check_output(['hping3', '-S', '-p', '80', '-c', '3', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"hping3 -S -p 80 -c 3 {target}")
    except Exception as e:
        results['hping3_syn'] = f"Error: {e}"
    # Scapy would require a Python script; placeholder for now
    results['scapy'] = 'Custom Scapy scripts can be integrated here.'
    commands.append("scapy (custom script)")

    # 2. Proxy Chains/Tor (demonstrate with nmap through proxychains)
    try:
        results['proxychains_nmap'] = subprocess.check_output(['proxychains', 'nmap', '-Pn', '-sS', '-T2', '-F', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"proxychains nmap -Pn -sS -T2 -F {target}")
    except Exception as e:
        results['proxychains_nmap'] = f"Error: {e}"

    # 3. Timing Randomization (demonstrate with nmap randomization)
    try:
        results['nmap_random_timing'] = subprocess.check_output(['nmap', '-Pn', '-sS', '--randomize-hosts', '-T2', '-F', target], stderr=subprocess.STDOUT, text=True)
        commands.append(f"nmap -Pn -sS --randomize-hosts -T2 -F {target}")
    except Exception as e:
        results['nmap_random_timing'] = f"Error: {e}"

    # 4. Wireless/IoT Recon (Aircrack-ng/Kismet)
    results['aircrack-ng'] = 'Run: aircrack-ng <capture_file> (manual integration required)'
    results['kismet'] = 'Run: kismet (manual integration required)'
    commands.append("aircrack-ng <capture_file>")
    commands.append("kismet")

    # 5. Post-Exploitation Recon (internal Nmap, arp-scan)
    try:
        results['arp-scan'] = subprocess.check_output(['arp-scan', '-l'], stderr=subprocess.STDOUT, text=True)
        commands.append("arp-scan -l")
    except Exception as e:
        results['arp-scan'] = f"Error: {e}"
    try:
        results['internal_nmap'] = subprocess.check_output(['nmap', '-sS', '-T4', '-F', '192.168.1.0/24'], stderr=subprocess.STDOUT, text=True)
        commands.append("nmap -sS -T4 -F 192.168.1.0/24")
    except Exception as e:
        results['internal_nmap'] = f"Error: {e}"

    # 6. Advanced Web Fuzzing (ffuf)
    try:
        results['ffuf'] = subprocess.check_output(['ffuf', '-u', f'http://{target}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt'], stderr=subprocess.STDOUT, text=True)
        commands.append(f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt")
    except Exception as e:
        results['ffuf'] = f"Error: {e}"

    recommendations.append("Review advanced findings, patch vulnerabilities, and harden all exposed services.")
    report_utils.append_section(
        report_path,
        section_title="Active Recon - Advanced",
        methodology="Custom packet crafting, proxy/Tor, timing randomization, wireless/IoT, post-exploitation, and advanced web fuzzing using hping3, scapy, proxychains, nmap, aircrack-ng, kismet, arp-scan, and ffuf.",
        commands=commands,
        findings=results,
        notable=notable,
        recommendations=recommendations,
        raw_output=results
    )
    return {
        "status": "success",
        "level": "advanced",
        "target": target,
        "results": results
    }

def run(target, report_path=None, level='basic'):
    """Run AI-powered active reconnaissance against target."""
    print(f"[+] Starting AI-powered active reconnaissance against {target}")
    
    results = {
        'target': target,
        'level': level,
        'findings': {},
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
        print("[!] AI engine not available, continuing with standard reconnaissance")
    
    # Execute active reconnaissance based on level
    if level == 'basic':
        return run_basic(target, report_path)
    elif level == 'stealth':
        return run_stealth(target, report_path)
    elif level == 'intermediate':
        return run_intermediate(target, report_path)
    elif level == 'advanced':
        return run_advanced(target, report_path)
    else:
        raise ValueError(f"Unknown active recon level: {level}") 