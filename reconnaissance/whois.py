"""
WHOIS Reconnaissance Module

This module handles WHOIS reconnaissance tasks for the AI-powered ethical hacking tool.
"""

import requests
from datetime import datetime
import os
import subprocess
from modules import report_utils

RDAP_URL = 'https://rdap.org/domain/{target}'


def run(target, report_path=None):
    """Run WHOIS recon and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[WHOIS Recon] Running WHOIS reconnaissance on: {target}")
    findings = {}
    commands = []
    raw_output = {}
    notable = []
    recommendations = []

    # 1. RDAP WHOIS lookup
    rdap_data = {}
    try:
        resp = requests.get(RDAP_URL.format(target=target), timeout=10)
        if resp.status_code == 200:
            rdap_data = resp.json()
            findings['RDAP'] = rdap_data
            raw_output['RDAP'] = rdap_data
            commands.append(f"curl {RDAP_URL.format(target=target)}")
        else:
            findings['RDAP'] = f"Error: {resp.status_code}"
            raw_output['RDAP'] = findings['RDAP']
    except Exception as e:
        findings['RDAP'] = str(e)
        raw_output['RDAP'] = str(e)

    # 2. Local whois command (if available)
    whois_cmd_output = ''
    try:
        proc = subprocess.run(['whois', target], capture_output=True, text=True, timeout=10)
        whois_cmd_output = proc.stdout.strip()
        findings['whois_cmd'] = whois_cmd_output
        raw_output['whois_cmd'] = whois_cmd_output
        commands.append(f"whois {target}")
    except Exception as e:
        findings['whois_cmd'] = str(e)
        raw_output['whois_cmd'] = str(e)

    # 3. Notable findings
    if isinstance(rdap_data, dict):
        if 'entities' in rdap_data:
            notable.append("RDAP data contains entities (registrant, admin, etc.).")
        if 'events' in rdap_data:
            for event in rdap_data['events']:
                if event.get('eventAction') == 'registration':
                    notable.append(f"Domain registered on {event.get('eventDate')}")
                if event.get('eventAction') == 'expiration':
                    notable.append(f"Domain expires on {event.get('eventDate')}")
        if 'status' in rdap_data:
            notable.append(f"Domain status: {', '.join(rdap_data['status'])}")
        if 'nameservers' in rdap_data:
            notable.append(f"Nameservers: {', '.join([ns['ldhName'] for ns in rdap_data['nameservers']])}")
    if whois_cmd_output:
        if 'privacy' in whois_cmd_output.lower():
            notable.append("Privacy protection detected in WHOIS output.")
        if 'Registrar:' in whois_cmd_output:
            registrar = next((line for line in whois_cmd_output.splitlines() if 'Registrar:' in line), None)
            if registrar:
                notable.append(registrar.strip())

    # 4. Recommendations
    if isinstance(rdap_data, dict):
        if 'events' in rdap_data:
            for event in rdap_data['events']:
                if event.get('eventAction') == 'expiration':
                    exp_date = event.get('eventDate')
                    try:
                        exp_dt = datetime.strptime(exp_date[:10], '%Y-%m-%d')
                        if (exp_dt - datetime.now()).days < 60:
                            recommendations.append("Domain expires soon. Renew to avoid loss of control.")
                    except Exception:
                        pass
    if whois_cmd_output and 'privacy' not in whois_cmd_output.lower():
        recommendations.append("Consider enabling privacy protection for WHOIS data.")
    recommendations.append("Monitor WHOIS for unauthorized changes or transfers.")

    report_utils.append_section(
        report_path,
        section_title="WHOIS Reconnaissance",
        methodology="Queried WHOIS data using RDAP API and the local whois command.",
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
        "recommendations": recommendations
    } 