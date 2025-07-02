"""
Web Enumeration Module

This module handles web enumeration (directory/file brute-forcing, tech detection) for the AI-powered ethical hacking tool.
"""

import subprocess
from modules import report_utils

def run(target, report_path=None, level='basic'):
    """Run web enumeration at the specified level and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[WebEnum] Running web enumeration on: {target} (level: {level})")
    findings = {}
    commands = []
    notable = []
    recommendations = []
    raw_output = {}

    # --- BASIC LEVEL ---
    methodology = [
        "Performed directory/file brute-forcing with Gobuster and technology detection with WhatWeb.",
    ]
    gobuster_cmd = ['gobuster', 'dir', '-u', f'http://{target}', '-w', '/usr/share/wordlists/dirb/common.txt']
    try:
        gobuster_out = subprocess.check_output(gobuster_cmd, stderr=subprocess.STDOUT, text=True)
        findings['gobuster'] = gobuster_out
        raw_output['gobuster'] = gobuster_out
        commands.append(' '.join(gobuster_cmd))
        if '/' in gobuster_out:
            notable.append("Directories/files discovered by Gobuster.")
    except Exception as e:
        findings['gobuster'] = f"Error: {e}"
        raw_output['gobuster'] = str(e)

    try:
        whatweb_cmd = ['whatweb', f'http://{target}']
        whatweb_out = subprocess.check_output(whatweb_cmd, stderr=subprocess.STDOUT, text=True)
        findings['whatweb'] = whatweb_out
        raw_output['whatweb'] = whatweb_out
        commands.append(' '.join(whatweb_cmd))
        if whatweb_out:
            notable.append("Technologies detected by WhatWeb.")
    except Exception as e:
        findings['whatweb'] = f"Error: {e} (WhatWeb may not be installed)"
        raw_output['whatweb'] = str(e)

    # --- INTERMEDIATE LEVEL ---
    if level in ['intermediate', 'advanced', 'stealth']:
        methodology.append("Added ffuf for fast directory fuzzing, wafw00f for WAF detection, and feroxbuster for recursive brute-forcing.")
        # ffuf
        ffuf_cmd = ['ffuf', '-u', f'http://{target}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-mc', '200,204,301,302,307,401,403']
        try:
            ffuf_out = subprocess.check_output(ffuf_cmd, stderr=subprocess.STDOUT, text=True)
            findings['ffuf'] = ffuf_out
            raw_output['ffuf'] = ffuf_out
            commands.append(' '.join(ffuf_cmd))
            if '/ ' in ffuf_out or '/\n' in ffuf_out:
                notable.append("Directories/files discovered by ffuf.")
        except Exception as e:
            findings['ffuf'] = f"Error: {e}"
            raw_output['ffuf'] = str(e)
        # wafw00f
        wafw00f_cmd = ['wafw00f', f'http://{target}']
        try:
            wafw00f_out = subprocess.check_output(wafw00f_cmd, stderr=subprocess.STDOUT, text=True)
            findings['wafw00f'] = wafw00f_out
            raw_output['wafw00f'] = wafw00f_out
            commands.append(' '.join(wafw00f_cmd))
            if 'is behind a' in wafw00f_out:
                notable.append("WAF detected by wafw00f.")
        except Exception as e:
            findings['wafw00f'] = f"Error: {e}"
            raw_output['wafw00f'] = str(e)
        # feroxbuster
        ferox_cmd = ['feroxbuster', '-u', f'http://{target}', '-w', '/usr/share/wordlists/dirb/common.txt', '-q']
        try:
            ferox_out = subprocess.check_output(ferox_cmd, stderr=subprocess.STDOUT, text=True)
            findings['feroxbuster'] = ferox_out
            raw_output['feroxbuster'] = ferox_out
            commands.append(' '.join(ferox_cmd))
            if '/ ' in ferox_out or '/\n' in ferox_out:
                notable.append("Directories/files discovered by feroxbuster.")
        except Exception as e:
            findings['feroxbuster'] = f"Error: {e}"
            raw_output['feroxbuster'] = str(e)

    # --- ADVANCED LEVEL ---
    if level in ['advanced', 'stealth']:
        methodology.append("Added nmap http-enum, nikto, and CMS-specific enumeration (wpscan, droopescan, joomscan).")
        # nmap http-enum
        nmap_http_cmd = ['nmap', '-p80,443', '--script', 'http-enum', target]
        try:
            nmap_http_out = subprocess.check_output(nmap_http_cmd, stderr=subprocess.STDOUT, text=True)
            findings['nmap_http_enum'] = nmap_http_out
            raw_output['nmap_http_enum'] = nmap_http_out
            commands.append(' '.join(nmap_http_cmd))
            if 'PORT' in nmap_http_out:
                notable.append("Web directories/files enumerated by Nmap http-enum.")
        except Exception as e:
            findings['nmap_http_enum'] = f"Error: {e}"
            raw_output['nmap_http_enum'] = str(e)
        # nikto
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
        # wpscan
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
        # droopescan
        droopescan_cmd = ['droopescan', 'scan', 'drupal', '-u', f'http://{target}']
        try:
            droopescan_out = subprocess.check_output(droopescan_cmd, stderr=subprocess.STDOUT, text=True)
            findings['droopescan'] = droopescan_out
            raw_output['droopescan'] = droopescan_out
            commands.append(' '.join(droopescan_cmd))
            if 'Interesting urls' in droopescan_out:
                notable.append("Drupal findings detected by droopescan.")
        except Exception as e:
            findings['droopescan'] = f"Error: {e}"
            raw_output['droopescan'] = str(e)
        # joomscan
        joomscan_cmd = ['joomscan', '-u', f'http://{target}']
        try:
            joomscan_out = subprocess.check_output(joomscan_cmd, stderr=subprocess.STDOUT, text=True)
            findings['joomscan'] = joomscan_out
            raw_output['joomscan'] = joomscan_out
            commands.append(' '.join(joomscan_cmd))
            if 'Joomla' in joomscan_out:
                notable.append("Joomla findings detected by joomscan.")
        except Exception as e:
            findings['joomscan'] = f"Error: {e}"
            raw_output['joomscan'] = str(e)

    # --- STEALTH LEVEL ---
    if level == 'stealth':
        methodology.append("Stealthy web enumeration using slow timing, minimal probes, and low-noise tools.")
        stealth_cmd = ['gobuster', 'dir', '-u', f'http://{target}', '-w', '/usr/share/wordlists/dirb/common.txt', '-t', '2']
        try:
            stealth_out = subprocess.check_output(stealth_cmd, stderr=subprocess.STDOUT, text=True)
            findings['gobuster_stealth'] = stealth_out
            raw_output['gobuster_stealth'] = stealth_out
            commands.append(' '.join(stealth_cmd))
            if '/' in stealth_out:
                notable.append("Stealthy Gobuster scan found directories/files.")
        except Exception as e:
            findings['gobuster_stealth'] = f"Error: {e}"
            raw_output['gobuster_stealth'] = str(e)

    # Recommendations
    recommendations.append("Review discovered directories/files and detected technologies for potential attack vectors.")
    if level in ['intermediate', 'advanced', 'stealth']:
        recommendations.append("Investigate WAF, CMS, and vulnerability findings in detail. Use authenticated scans if possible.")
    if level in ['advanced', 'stealth']:
        recommendations.append("Correlate findings with vulnerability scans and consider in-depth CMS enumeration.")
    if level == 'stealth':
        recommendations.append("Consider using additional evasion techniques if target is highly monitored.")

    report_utils.append_section(
        report_path,
        section_title=f"Web Enumeration ({level.title()})",
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