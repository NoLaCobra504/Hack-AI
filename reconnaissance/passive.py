"""
Passive Reconnaissance Module
AI-powered passive reconnaissance techniques
"""

import subprocess
import socket
import requests
from modules.report_utils import append_section

def run(target, report_path=None, level='basic'):
    """Run AI-powered passive reconnaissance against target."""
    print(f"[+] Starting AI-powered passive reconnaissance against {target}")
    
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
            ai_analysis = ai_engine.analyze_recon_target(target, "passive", level)
            results['ai_analysis'] = ai_analysis
            print(f"[+] AI Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk level")
    except ImportError:
        print("[!] AI engine not available, continuing with standard reconnaissance")
    
    # Basic passive reconnaissance
    print("[*] Running basic passive reconnaissance...")
    
    # DNS resolution
    try:
        ip = socket.gethostbyname(target)
        results['findings']['dns_resolution'] = {
            'domain': target,
            'ip_address': ip,
            'status': 'resolved'
        }
        print(f"[+] DNS Resolution: {target} -> {ip}")
    except socket.gaierror:
        results['findings']['dns_resolution'] = {
            'domain': target,
            'status': 'failed'
        }
        print(f"[!] DNS Resolution failed for {target}")
    
    # WHOIS lookup
    try:
        whois_result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
        if whois_result.returncode == 0:
            results['findings']['whois'] = {
                'status': 'success',
                'data': whois_result.stdout[:1000]  # Limit output for report
            }
            print("[+] WHOIS lookup completed")
        else:
            results['findings']['whois'] = {
                'status': 'failed',
                'error': whois_result.stderr
            }
            print("[!] WHOIS lookup failed")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        results['findings']['whois'] = {
            'status': 'not_available',
            'note': 'whois command not available or timed out'
        }
        print("[!] WHOIS command not available")
    
    # HTTP response analysis
    try:
        response = requests.get(f"http://{target}", timeout=10, allow_redirects=True)
        results['findings']['http_response'] = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'server': response.headers.get('Server', 'Unknown'),
            'final_url': response.url
        }
        print(f"[+] HTTP Response: {response.status_code} - Server: {response.headers.get('Server', 'Unknown')}")
    except requests.RequestException as e:
        results['findings']['http_response'] = {
            'status': 'failed',
            'error': str(e)
        }
        print(f"[!] HTTP request failed: {e}")
    
    # HTTPS response analysis
    try:
        response = requests.get(f"https://{target}", timeout=10, allow_redirects=True, verify=False)
        results['findings']['https_response'] = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'server': response.headers.get('Server', 'Unknown'),
            'final_url': response.url
        }
        print(f"[+] HTTPS Response: {response.status_code} - Server: {response.headers.get('Server', 'Unknown')}")
    except requests.RequestException as e:
        results['findings']['https_response'] = {
            'status': 'failed',
            'error': str(e)
        }
        print(f"[!] HTTPS request failed: {e}")
    
    # Advanced passive reconnaissance based on level
    if level in ['intermediate', 'advanced', 'stealth']:
        print("[*] Running intermediate passive reconnaissance...")
        
        # DNS enumeration
        try:
            dns_result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=30)
            if dns_result.returncode == 0:
                results['findings']['dns_enumeration'] = {
                    'status': 'success',
                    'data': dns_result.stdout
                }
                print("[+] DNS enumeration completed")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results['findings']['dns_enumeration'] = {
                'status': 'not_available'
            }
    
    if level in ['advanced', 'stealth']:
        print("[*] Running advanced passive reconnaissance...")
        
        # Certificate transparency logs (simulated)
        results['findings']['certificate_transparency'] = {
            'status': 'simulated',
            'note': 'Certificate transparency log checking would be implemented here'
        }
        
        # Search engine reconnaissance (simulated)
        results['findings']['search_engine_recon'] = {
            'status': 'simulated',
            'note': 'Search engine reconnaissance would be implemented here'
        }
    
    # Generate recommendations based on findings
    recommendations = []
    if 'dns_resolution' in results['findings'] and results['findings']['dns_resolution'].get('status') == 'resolved':
        recommendations.append("Target is reachable via DNS resolution")
    
    if 'http_response' in results['findings'] and 'status_code' in results['findings']['http_response']:
        if results['findings']['http_response']['status_code'] == 200:
            recommendations.append("HTTP service is accessible")
        elif results['findings']['http_response']['status_code'] in [301, 302]:
            recommendations.append("Target redirects HTTP traffic")
    
    if 'https_response' in results['findings'] and 'status_code' in results['findings']['https_response']:
        if results['findings']['https_response']['status_code'] == 200:
            recommendations.append("HTTPS service is accessible")
    
    # Add AI-powered recommendations if available
    if 'ai_analysis' in results and results['ai_analysis']:
        ai_recommendations = results['ai_analysis'].get('ai_analysis', {}).get('next_steps', [])
        recommendations.extend(ai_recommendations)
    
    # Add to report
    if report_path:
        append_section(
            report_path,
            "AI-Powered Passive Reconnaissance",
            f"Comprehensive passive reconnaissance at {level} level using AI analysis",
            [
                f"nslookup {target}",
                f"whois {target}",
                f"curl -I http://{target}",
                f"curl -I https://{target}"
            ],
            results['findings'],
            [f"Level: {level}", f"Target: {target}"],
            recommendations,
            results
        )
    
    print(f"[+] AI-powered passive reconnaissance completed for {target}")
    return results 