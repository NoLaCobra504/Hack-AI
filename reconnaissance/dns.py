"""
DNS Reconnaissance Module

This module handles DNS reconnaissance tasks for the AI-powered ethical hacking tool.
"""

import dns.resolver
import dns.query
import dns.zone
import socket
import subprocess
from datetime import datetime
import os
from modules import report_utils

# Simple wordlist for brute-force (can be replaced with a larger one)
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'test', 'dev', 'api', 'staging', 'admin', 'portal', 'vpn', 'webmail', 'blog', 'shop', 'ns1', 'ns2'
]

def run(target, report_path=None):
    """Run DNS recon and generate a professional Markdown report as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[DNS Recon] Running DNS reconnaissance on: {target}")
    findings = {}
    commands = []
    raw_output = {}
    notable = []
    recommendations = []

    # 1. Query all standard DNS records
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            findings[rtype] = [str(a) for a in answers]
            raw_output[rtype] = findings[rtype]
            commands.append(f"dig {rtype} {target}")
        except Exception as e:
            findings[rtype] = []
            raw_output[rtype] = str(e)

    # 2. Attempt zone transfer from all NS
    zone_transfer_results = []
    ns_records = findings.get('NS', [])
    for ns in ns_records:
        ns_host = ns.split()[-1].strip('.')
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, target, lifetime=5))
            domains = [str(n) + '.' + target for n in z.nodes.keys()]
            zone_transfer_results.append({'ns': ns_host, 'success': True, 'domains': domains})
            notable.append(f"Zone transfer successful from {ns_host}.")
            recommendations.append(f"Restrict zone transfers on {ns_host}.")
        except Exception as e:
            zone_transfer_results.append({'ns': ns_host, 'success': False, 'error': str(e)})
    raw_output['zone_transfer'] = zone_transfer_results
    commands.append("dig AXFR <ns> <target>")

    # 3. Brute-force common subdomains
    brute_subs = []
    for sub in SUBDOMAIN_WORDLIST:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            brute_subs.append({'subdomain': fqdn, 'ip': ip})
        except Exception:
            continue
    raw_output['brute_force'] = brute_subs
    commands.append(f"for sub in ...; do dig $sub.{target}; done")

    # 4. Wildcard DNS check
    try:
        wildcard_test = f"wildcard-check-{datetime.now().timestamp()}.{target}"
        socket.gethostbyname(wildcard_test)
        notable.append("Wildcard DNS appears to be enabled.")
        recommendations.append("Review wildcard DNS configuration and restrict if not needed.")
    except Exception:
        pass

    # 5. SPF/DMARC checks
    spf = [r for r in findings.get('TXT', []) if 'v=spf1' in r]
    dmarc = []
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{target}", 'TXT', lifetime=5)
        dmarc = [str(a) for a in dmarc_answers]
    except Exception:
        pass
    if spf:
        notable.append("SPF record found.")
    if dmarc:
        notable.append("DMARC record found.")
    raw_output['SPF'] = spf
    raw_output['DMARC'] = dmarc

    # Recommendations
    if not spf:
        recommendations.append("Implement an SPF record to prevent email spoofing.")
    if not dmarc:
        recommendations.append("Implement a DMARC record to improve email security.")
    if not findings.get('MX'):
        recommendations.append("No MX records found. If email is used, configure MX records.")

    report_utils.append_section(
        report_path,
        section_title="DNS Reconnaissance",
        methodology="Queried DNS records using dnspython and socket. Attempted zone transfers and brute-forced common subdomains.",
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
        "zone_transfer": raw_output.get('zone_transfer', []),
        "brute_force": raw_output.get('brute_force', []),
        "spf": raw_output.get('SPF', []),
        "dmarc": raw_output.get('DMARC', [])
    } 