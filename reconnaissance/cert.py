"""
Certificate Transparency (CT) Reconnaissance Module

This module handles CT reconnaissance tasks for the AI-powered ethical hacking tool.
"""

import requests
import json
from datetime import datetime
import os
from modules import report_utils

def run(target, report_path=None):
    """Run Certificate Transparency recon and append results as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[CT Recon] Running Certificate Transparency reconnaissance on: {target}")
    # Query crt.sh for all certs for the target domain and subdomains
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[CT Recon] Error querying crt.sh: {e}")
        return {"status": "error", "target": target, "error": str(e)}

    # Parse and deduplicate subdomains and certs
    subdomains = set()
    certs = []
    for entry in data:
        name_value = entry.get('name_value', '')
        for name in name_value.split('\n'):
            if name.endswith(target):
                subdomains.add(name.strip())
        certs.append({
            'subdomain': name_value.replace('\n', ', '),
            'issuer': entry.get('issuer_name', ''),
            'not_before': entry.get('not_before', ''),
            'not_after': entry.get('not_after', ''),
            'id': entry.get('id', ''),
        })

    # Analyze findings
    wildcard_certs = [c for c in certs if '*' in c['subdomain']]
    expired_certs = [c for c in certs if c['not_after'] and datetime.strptime(c['not_after'], '%Y-%m-%dT%H:%M:%S') < datetime.now()]
    issuers = set(c['issuer'] for c in certs)

    # Prepare Markdown report
    report_name = f"ct_recon_{target.replace('.', '_')}.md"
    with open(report_name, 'w', encoding='utf-8') as f:
        f.write(f"# Certificate Transparency Reconnaissance Report\n\n")
        f.write(f"**Target:** `{target}`  \n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## Methodology\n\n")
        f.write(f"Queried [crt.sh](https://crt.sh) for all certificates issued for `{target}` and its subdomains.\n\n")
        f.write(f"**Command:**\n")
        f.write(f"```shell\ncurl '{url}'\n```\n\n")
        f.write(f"## Findings\n\n")
        f.write(f"| Subdomain | Issuer | Not Before | Not After | Wildcard | Expired |\n")
        f.write(f"|-----------|--------|------------|-----------|----------|---------|\n")
        for c in certs:
            sub = c['subdomain']
            issuer = c['issuer']
            nb = c['not_before'][:10] if c['not_before'] else ''
            na = c['not_after'][:10] if c['not_after'] else ''
            wildcard = 'Yes' if '*' in sub else 'No'
            expired = 'Yes' if c['not_after'] and datetime.strptime(c['not_after'], '%Y-%m-%dT%H:%M:%S') < datetime.now() else 'No'
            f.write(f"| {sub} | {issuer} | {nb} | {na} | {wildcard} | {expired} |\n")
        f.write(f"\n## Notable Observations\n\n")
        if wildcard_certs:
            f.write(f"- Wildcard certificate(s) found.\n")
        if expired_certs:
            f.write(f"- {len(expired_certs)} expired certificate(s) found.\n")
        if len(issuers) > 1:
            f.write(f"- Multiple certificate issuers detected.\n")
        if not certs:
            f.write(f"- No certificates found for this domain.\n")
        f.write(f"\n## Recommendations\n\n")
        f.write(f"- Monitor CT logs for unauthorized or suspicious certificates.\n")
        f.write(f"- Revoke expired or unused certificates.\n")
        f.write(f"- Avoid using wildcard certificates unless necessary.\n")
        f.write(f"- Use Certificate Authority Authorization (CAA) DNS records to restrict which CAs can issue certificates for your domain.\n")
        f.write(f"\n## Raw Output\n\n")
        f.write(f"```json\n")
        json.dump(data, f, indent=2)
        f.write(f"\n```")

    print(f"[CT Recon] Report saved to {os.path.abspath(report_name)}")
    report_utils.append_section(
        report_path,
        section_title="Certificate Transparency Reconnaissance",
        methodology="Queried crt.sh for all certificates issued for the target and its subdomains.",
        commands=[f"curl '{url}'"],
        findings=certs,
        notable=notable,
        recommendations=[
            "Monitor CT logs for unauthorized or suspicious certificates.",
            "Revoke expired or unused certificates.",
            "Avoid using wildcard certificates unless necessary.",
            "Use CAA DNS records to restrict which CAs can issue certificates for your domain."
        ],
        raw_output=data
    )
    return {
        "status": "success",
        "target": target,
        "report": report_path,
        "subdomains": sorted(subdomains),
        "certs": certs
    } 