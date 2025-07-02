"""
Shodan Reconnaissance Module

This module handles Shodan reconnaissance tasks for the AI-powered ethical hacking tool.
"""

import os
import requests
from datetime import datetime
from modules import report_utils

SHODAN_API_URL = 'https://api.shodan.io/shodan/host/{target}?key={api_key}'


def run(target, report_path=None):
    """Run Shodan recon and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[Shodan Recon] Running Shodan reconnaissance on: {target}")
    findings = {}
    commands = []
    raw_output = {}
    notable = []
    recommendations = []

    api_key = os.environ.get('SHODAN_API_KEY')
    if not api_key:
        print("[Shodan Recon] Error: No SHODAN_API_KEY environment variable set. Please set your own Shodan API key.")
        findings['Shodan'] = 'Error: No SHODAN_API_KEY environment variable set.'
        raw_output['Shodan'] = findings['Shodan']
        report_utils.append_section(
            report_path,
            section_title="Shodan Reconnaissance",
            methodology="Queried Shodan API for host information.",
            commands=commands,
            findings=findings,
            notable=notable,
            recommendations=recommendations,
            raw_output=raw_output
        )
        return {
            "status": "error",
            "target": target,
            "report": report_path,
            "findings": findings,
            "notable": notable,
            "recommendations": recommendations
        }

    url = SHODAN_API_URL.format(target=target, api_key=api_key)
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            findings['Shodan'] = data
            raw_output['Shodan'] = data
            commands.append(f"curl '{url}'")
        else:
            findings['Shodan'] = f"Error: {resp.status_code} {resp.text}"
            raw_output['Shodan'] = findings['Shodan']
    except Exception as e:
        findings['Shodan'] = str(e)
        raw_output['Shodan'] = str(e)

    # Notable findings
    data = findings.get('Shodan', {})
    if isinstance(data, dict):
        if data.get('ports'):
            notable.append(f"Open ports: {', '.join(map(str, data['ports']))}")
        if data.get('vulns'):
            notable.append(f"Vulnerabilities: {', '.join(data['vulns'])}")
        if data.get('hostnames'):
            notable.append(f"Hostnames: {', '.join(data['hostnames'])}")
        if data.get('org'):
            notable.append(f"Organization: {data['org']}")
        if data.get('os'):
            notable.append(f"Operating System: {data['os']}")
    # Recommendations
    if isinstance(data, dict):
        if data.get('vulns'):
            recommendations.append("Review and patch known vulnerabilities.")
        if data.get('ports'):
            recommendations.append("Restrict unnecessary open ports and services.")
        recommendations.append("Monitor Shodan for new exposures or changes.")

    report_utils.append_section(
        report_path,
        section_title="Shodan Reconnaissance",
        methodology="Queried Shodan API for host data, open ports, vulnerabilities, and banners.",
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