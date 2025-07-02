"""
OSINT Reconnaissance Module

This module handles OSINT reconnaissance tasks for the AI-powered ethical hacking tool.
"""

import requests
from datetime import datetime
import os
import re
from modules import report_utils

# Helper: Google dork queries (can be expanded)
GOOGLE_DORKS = [
    'site:{target}',
    'site:pastebin.com {target}',
    'site:github.com {target}',
    'site:linkedin.com {target}',
    'intitle:index.of {target}',
    'inurl:{target} ext:log | ext:txt | ext:conf',
    'site:twitter.com {target}',
]

# Helper: Public breach check (HaveIBeenPwned API is rate-limited, so just link for now)
HIBP_URL = 'https://haveibeenpwned.com/unifiedsearch/{target}'

# Helper: Simple WHOIS lookup
WHOIS_URL = 'https://rdap.org/domain/{target}'

# Helper: GitHub code search (public API is limited, so just link for now)
GITHUB_CODE_SEARCH = 'https://github.com/search?q={target}'

# Helper: Pastebin search (no API, so just link)
PASTEBIN_SEARCH = 'https://pastebin.com/search?q={target}'

# Helper: LinkedIn search (no API, so just link)
LINKEDIN_SEARCH = 'https://www.linkedin.com/search/results/all/?keywords={target}'

# Helper: Twitter search (no API, so just link)
TWITTER_SEARCH = 'https://twitter.com/search?q={target}'


def run(target, report_path=None):
    """Run OSINT recon and generate a professional Markdown report as a section in the unified report."""
    if report_path is None:
        report_path = report_utils.get_report_name(cve_id=None)
    report_utils.init_report(report_path, target)
    print(f"[OSINT Recon] Running OSINT reconnaissance on: {target}")
    findings = {}
    commands = []
    raw_output = {}
    notable = []
    recommendations = []

    # 1. Google dorks (simulate, provide links)
    findings['Google Dorks'] = []
    for dork in GOOGLE_DORKS:
        query = dork.format(target=target)
        url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
        findings['Google Dorks'].append({'query': query, 'url': url})
        commands.append(f"Google: {query}")
    raw_output['Google Dorks'] = findings['Google Dorks']

    # 2. WHOIS lookup
    whois_data = {}
    try:
        resp = requests.get(WHOIS_URL.format(target=target), timeout=10)
        if resp.status_code == 200:
            whois_data = resp.json()
            findings['WHOIS'] = whois_data
            raw_output['WHOIS'] = whois_data
            commands.append(f"curl {WHOIS_URL.format(target=target)}")
        else:
            findings['WHOIS'] = f"Error: {resp.status_code}"
            raw_output['WHOIS'] = findings['WHOIS']
    except Exception as e:
        findings['WHOIS'] = str(e)
        raw_output['WHOIS'] = str(e)

    # 3. Breach data (link to HIBP)
    findings['Breach Data'] = HIBP_URL.format(target=target)
    raw_output['Breach Data'] = findings['Breach Data']
    commands.append(f"Visit: {HIBP_URL.format(target=target)}")

    # 4. GitHub code search (link)
    findings['GitHub Code Search'] = GITHUB_CODE_SEARCH.format(target=target)
    raw_output['GitHub Code Search'] = findings['GitHub Code Search']
    commands.append(f"Visit: {GITHUB_CODE_SEARCH.format(target=target)}")

    # 5. Pastebin search (link)
    findings['Pastebin Search'] = PASTEBIN_SEARCH.format(target=target)
    raw_output['Pastebin Search'] = findings['Pastebin Search']
    commands.append(f"Visit: {PASTEBIN_SEARCH.format(target=target)}")

    # 6. LinkedIn search (link)
    findings['LinkedIn Search'] = LINKEDIN_SEARCH.format(target=target)
    raw_output['LinkedIn Search'] = findings['LinkedIn Search']
    commands.append(f"Visit: {LINKEDIN_SEARCH.format(target=target)}")

    # 7. Twitter search (link)
    findings['Twitter Search'] = TWITTER_SEARCH.format(target=target)
    raw_output['Twitter Search'] = findings['Twitter Search']
    commands.append(f"Visit: {TWITTER_SEARCH.format(target=target)}")

    # 8. Notable findings (basic analysis)
    if whois_data:
        if 'entities' in whois_data:
            notable.append("WHOIS data contains entities (registrant, admin, etc.).")
        if 'events' in whois_data:
            for event in whois_data['events']:
                if event.get('eventAction') == 'registration':
                    notable.append(f"Domain registered on {event.get('eventDate')}")
    # Recommend monitoring for leaks
    recommendations.append("Monitor public sources (Google, GitHub, Pastebin, social media) for sensitive data leaks.")
    recommendations.append("Set up Google Alerts for your domain and key assets.")
    recommendations.append("Check HaveIBeenPwned regularly for breach exposure.")

    report_utils.append_section(
        report_path,
        section_title="OSINT Reconnaissance",
        methodology="Gathered public information from search engines, breach data, code repositories, paste sites, and social media.",
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