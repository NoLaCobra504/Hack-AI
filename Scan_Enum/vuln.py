"""
Vulnerability Scanning Module

This module handles vulnerability scanning (Nmap scripts, Nikto) for the AI-powered ethical hacking tool.
"""

import subprocess
from modules import report_utils

def run(target, report_path=None, level='basic'):
    """Run vulnerability scanning at the specified level and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[VulnScan] Running vulnerability scan on: {target} (level: {level})")
    findings = {}
    commands = []
    notable = []
    recommendations = []
    raw_output = {}

    # --- BASIC LEVEL ---
    methodology = [
        "Performed vulnerability scanning using Nmap vuln scripts and Nikto.",
    ]
    nmap_vuln_cmd = ['nmap', '--script', 'vuln', target]
    try:
        nmap_vuln_out = subprocess.check_output(nmap_vuln_cmd, stderr=subprocess.STDOUT, text=True)
        findings['nmap_vuln'] = nmap_vuln_out
        raw_output['nmap_vuln'] = nmap_vuln_out
        commands.append(' '.join(nmap_vuln_cmd))
        if 'CVE' in nmap_vuln_out:
            notable.append("Potential vulnerabilities (CVEs) detected by Nmap.")
    except Exception as e:
        findings['nmap_vuln'] = f"Error: {e}"
        raw_output['nmap_vuln'] = str(e)

    nikto_cmd = ['nikto', '-h', target]
    try:
        nikto_out = subprocess.check_output(nikto_cmd, stderr=subprocess.STDOUT, text=True)
        findings['nikto'] = nikto_out
        raw_output['nikto'] = nikto_out
        commands.append(' '.join(nikto_cmd))
        if 'OSVDB' in nikto_out or 'CVE' in nikto_out:
            notable.append("Potential web vulnerabilities detected by Nikto.")
    except Exception as e:
        findings['nikto'] = f"Error: {e}"
        raw_output['nikto'] = str(e)

    # --- INTERMEDIATE LEVEL ---
    if level in ['intermediate', 'advanced', 'stealth']:
        methodology.append("Targeted Nmap NSE scripts for web, SMB, and SSL vulnerabilities. Added wpscan and sslscan for web/SSL checks.")
        # Nmap NSE scripts for web vulns
        nmap_web_cmd = ['nmap', '-p80,443', '--script', 'http-vuln*', target]
        try:
            nmap_web_out = subprocess.check_output(nmap_web_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_web_vuln'] = nmap_web_out
            raw_output['nmap_web_vuln'] = nmap_web_out
            commands.append(' '.join(nmap_web_cmd))
            if 'CVE' in nmap_web_out:
                notable.append("Potential web vulnerabilities detected by Nmap http-vuln scripts.")
        except Exception as e:
            findings['nmap_web_vuln'] = f"Error: {e}"
            raw_output['nmap_web_vuln'] = str(e)
        # Nmap NSE scripts for SMB vulns
        nmap_smb_cmd = ['nmap', '-p445', '--script', 'smb-vuln*', target]
        try:
            nmap_smb_out = subprocess.check_output(nmap_smb_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_smb_vuln'] = nmap_smb_out
            raw_output['nmap_smb_vuln'] = nmap_smb_out
            commands.append(' '.join(nmap_smb_cmd))
            if 'CVE' in nmap_smb_out:
                notable.append("Potential SMB vulnerabilities detected by Nmap smb-vuln scripts.")
        except Exception as e:
            findings['nmap_smb_vuln'] = f"Error: {e}"
            raw_output['nmap_smb_vuln'] = str(e)
        # sslscan
        sslscan_cmd = ['sslscan', target]
        try:
            sslscan_out = subprocess.check_output(sslscan_cmd, stderr=subprocess.STDOUT, text=True)
            findings['sslscan'] = sslscan_out
            raw_output['sslscan'] = sslscan_out
            commands.append(' '.join(sslscan_cmd))
            if 'SSLv2' in sslscan_out or 'SSLv3' in sslscan_out:
                notable.append("Weak SSL/TLS protocols detected by sslscan.")
        except Exception as e:
            findings['sslscan'] = f"Error: {e}"
            raw_output['sslscan'] = str(e)
        # wpscan (WordPress)
        wpscan_cmd = ['wpscan', '--url', f'http://{target}', '--enumerate', 'vp']
        try:
            wpscan_out = subprocess.check_output(wpscan_cmd, stderr=subprocess.STDOUT, text=True)
            findings['wpscan'] = wpscan_out
            raw_output['wpscan'] = wpscan_out
            commands.append(' '.join(wpscan_cmd))
            if 'vulnerable' in wpscan_out.lower():
                notable.append("WordPress vulnerabilities detected by wpscan.")
        except Exception as e:
            findings['wpscan'] = f"Error: {e}"
            raw_output['wpscan'] = str(e)

    # --- ADVANCED LEVEL ---
    if level in ['advanced', 'stealth']:
        methodology.append("Integrated searchsploit and Vulners NSE for offline/online vulnerability database checks. Optionally run OpenVAS if available.")
        # searchsploit
        searchsploit_cmd = ['searchsploit', target]
        try:
            searchsploit_out = subprocess.check_output(searchsploit_cmd, stderr=subprocess.STDOUT, text=True)
            findings['searchsploit'] = searchsploit_out
            raw_output['searchsploit'] = searchsploit_out
            commands.append(' '.join(searchsploit_cmd))
            if 'Exploit' in searchsploit_out:
                notable.append("Potential exploits found by searchsploit.")
        except Exception as e:
            findings['searchsploit'] = f"Error: {e}"
            raw_output['searchsploit'] = str(e)
        # Vulners NSE
        vulners_cmd = ['nmap', '--script', 'vulners', target]
        try:
            vulners_out = subprocess.check_output(vulners_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_vulners'] = vulners_out
            raw_output['nmap_vulners'] = vulners_out
            commands.append(' '.join(vulners_cmd))
            if 'CVE' in vulners_out:
                notable.append("Vulnerabilities detected by Nmap Vulners script.")
        except Exception as e:
            findings['nmap_vulners'] = f"Error: {e}"
            raw_output['nmap_vulners'] = str(e)
        # OpenVAS (if available)
        openvas_cmd = ['gvm-cli', 'socket', '--gmp-username', 'admin', '--gmp-password', 'admin', 'help']
        try:
            openvas_out = subprocess.check_output(openvas_cmd, stderr=subprocess.STDOUT, text=True)
            findings['openvas'] = openvas_out
            raw_output['openvas'] = openvas_out
            commands.append(' '.join(openvas_cmd))
            notable.append("OpenVAS scan attempted (manual review required for results).")
        except Exception as e:
            findings['openvas'] = f"Error: {e}"
            raw_output['openvas'] = str(e)

    # --- STEALTH LEVEL ---
    if level == 'stealth':
        methodology.append("Stealthy vulnerability scanning using slow timing, minimal probes, and low-noise scripts.")
        stealth_cmd = ['nmap', '--script', 'vuln', '-T1', '--max-retries', '2', target]
        try:
            stealth_out = subprocess.check_output(stealth_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_stealth_vuln'] = stealth_out
            raw_output['nmap_stealth_vuln'] = stealth_out
            commands.append(' '.join(stealth_cmd))
            if 'CVE' in stealth_out:
                notable.append("Potential vulnerabilities detected by stealthy Nmap scan.")
        except Exception as e:
            findings['nmap_stealth_vuln'] = f"Error: {e}"
            raw_output['nmap_stealth_vuln'] = str(e)

    # Recommendations
    recommendations.append("Review and patch detected vulnerabilities. Harden web applications.")
    if level in ['intermediate', 'advanced', 'stealth']:
        recommendations.append("Investigate protocol-specific and web vulnerabilities in detail. Use authenticated scans if possible.")
    if level in ['advanced', 'stealth']:
        recommendations.append("Correlate findings with exploit databases and consider in-depth scanning with OpenVAS or similar tools.")
    if level == 'stealth':
        recommendations.append("Consider using additional evasion techniques if target is highly monitored.")

    report_utils.append_section(
        report_path,
        section_title=f"Vulnerability Scanning ({level.title()})",
        methodology='\n'.join(methodology),
        commands=commands,
        findings=findings,
        notable=notable,
        recommendations=recommendations,
        raw_output=raw_output
    )
    return {
        "status": "success",
        "target": target,
        "report": report_path,
        "findings": findings,
        "notable": notable,
        "recommendations": recommendations,
        "level": level
    } 