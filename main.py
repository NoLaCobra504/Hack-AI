#!/usr/bin/env python3
"""
HackingAI - AI-Powered Ethical Hacking Automation Tool
Main CLI interface for the modular hacking framework
"""

import argparse
import sys
import os
from datetime import datetime

# Import modules
from reconnaissance import passive, active, osint, dns, cert, shodan, whois
from Scan_Enum import portscan, service, vuln, web
from Exploitation import password_attack, web_exploit, service_exploit
from Post_Exploitation import privilege_escalation, research_cve, suggest_exploits, cleanup_artifacts, learn_from_result, get_ai_status
from Post_Exploitation import run_post_exploit
from modules.report_utils import init_report, get_report_name, append_section, ensure_final_reports_dir

# Initialize Final_Reports directory
ensure_final_reports_dir()

# Initialize AI engine
try:
    from modules.ai_engine import HackingAI
    ai_engine = HackingAI()
    # Add a small delay to ensure Ollama is ready
    import time
    time.sleep(1)
    ai_available = ai_engine.is_ai_available()
    print(f"[+] HackingAI - AI-Powered Ethical Hacking Tool")
    print(f"[+] AI Engine Status: {'Available' if ai_available else 'Not Available'}")
except ImportError as e:
    print(f"[!] AI Engine not available: {e}")
    ai_engine = None
    ai_available = False
except Exception as e:
    print(f"[!] AI Engine initialization error: {e}")
    ai_engine = None
    ai_available = False

def main():
    parser = argparse.ArgumentParser(
        description="HackingAI - AI-Powered Ethical Hacking Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # AI-powered reconnaissance
  python main.py recon passive example.com --level advanced
  
  # AI-powered port scanning with analysis
  python main.py scan ports example.com --level advanced
  
  # AI-powered web exploitation
  python main.py exploit web example.com --level intermediate
  
  # AI-powered privilege escalation
  python main.py post-exploit privilege-escalation example.com --level advanced
  
  # AI-powered CVE research
  python main.py ai cve-research example.com --cve CVE-2021-44228 --post-exploit-type privilege_escalation
  
  # AI-powered reconnaissance analysis
  python main.py ai recon-analysis example.com --recon-type passive --level advanced
  
  # AI-powered scan analysis
  python main.py ai scan-analysis example.com --scan-type ports
  
  # AI-powered exploitation suggestions
  python main.py ai exploit-suggestions example.com --exploit-type web
  
  # Generate AI executive summary
  python main.py ai summary example.com
  
  # Start interactive AI assistant
  python main.py ai-assistant
  python main.py ai-assistant --target example.com
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Reconnaissance commands
    recon_parser = subparsers.add_parser('recon', help='AI-powered reconnaissance operations')
    recon_parser.add_argument('type', choices=['passive', 'active', 'osint', 'dns', 'cert', 'shodan', 'whois'], 
                             help='Type of reconnaissance')
    recon_parser.add_argument('target', help='Target domain/IP')
    recon_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'], 
                             default='basic', help='Scan level')
    recon_parser.add_argument('--report', help='Custom report path')
    
    # Scanning/Enumeration commands
    scan_parser = subparsers.add_parser('scan', help='AI-powered scanning and enumeration operations')
    scan_parser.add_argument('type', choices=['ports', 'services', 'vulns', 'web'], 
                            help='Type of scan')
    scan_parser.add_argument('target', help='Target domain/IP')
    scan_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'], 
                            default='basic', help='Scan level')
    scan_parser.add_argument('--ports', help='Specific ports to scan (e.g., 80,443,8080)')
    scan_parser.add_argument('--report', help='Custom report path')
    
    # Exploitation commands
    exploit_parser = subparsers.add_parser('exploit', help='AI-powered exploitation operations')
    exploit_parser.add_argument('type', choices=['password', 'web', 'service'], 
                               help='Type of exploitation')
    exploit_parser.add_argument('target', help='Target domain/IP')
    exploit_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'], 
                               default='basic', help='Exploitation level')
    exploit_parser.add_argument('--credentials', help='Credentials file or string')
    exploit_parser.add_argument('--report', help='Custom report path')
    
    # Post-Exploitation commands
    post_exploit_parser = subparsers.add_parser('post-exploit', help='AI-powered post-exploitation operations')
    post_exploit_parser.add_argument('type', choices=['privilege-escalation', 'persistence', 'lateral-movement', 'data-exfiltration'], 
                                    help='Type of post-exploitation')
    post_exploit_parser.add_argument('target', help='Target domain/IP')
    post_exploit_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'], 
                                    default='basic', help='Post-exploitation level')
    post_exploit_parser.add_argument('--credentials', help='Credentials file or string')
    post_exploit_parser.add_argument('--report', help='Custom report path')
    
    # AI commands
    ai_parser = subparsers.add_parser('ai', help='AI-powered analysis and intelligence')
    ai_parser.add_argument('type', choices=['cve-research', 'generate-exploit', 'suggest-exploits', 'cleanup', 'status', 
                                           'recon-analysis', 'scan-analysis', 'exploit-suggestions', 'summary'], 
                          help='Type of AI operation')
    ai_parser.add_argument('target', help='Target domain/IP')
    ai_parser.add_argument('--cve', help='CVE ID for research')
    ai_parser.add_argument('--exploit-type', choices=['web', 'service', 'password', 'privilege-escalation'], 
                          help='Type of exploit to generate')
    ai_parser.add_argument('--post-exploit-type', choices=['privilege_escalation', 'persistence', 'lateral_movement', 'data_exfiltration', 'all'], 
                          help='Type of post-exploitation for research')
    ai_parser.add_argument('--recon-type', choices=['passive', 'active', 'osint', 'dns', 'cert', 'shodan', 'whois'],
                          help='Type of reconnaissance for analysis')
    ai_parser.add_argument('--scan-type', choices=['ports', 'services', 'vulns', 'web'],
                          help='Type of scan for analysis')
    ai_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'],
                          help='Level for analysis')
    ai_parser.add_argument('--report', help='Custom report path')
    
    # Full assessment command
    full_parser = subparsers.add_parser('full-assessment', help='Run complete AI-powered assessment workflow')
    full_parser.add_argument('target', help='Target domain/IP')
    full_parser.add_argument('--level', choices=['basic', 'intermediate', 'advanced', 'stealth'], 
                            default='basic', help='Assessment level')
    full_parser.add_argument('--report', help='Custom report path')
    full_parser.add_argument('--skip-recon', action='store_true', help='Skip reconnaissance phase')
    full_parser.add_argument('--skip-scan', action='store_true', help='Skip scanning phase')
    full_parser.add_argument('--skip-exploit', action='store_true', help='Skip exploitation phase')
    full_parser.add_argument('--skip-post-exploit', action='store_true', help='Skip post-exploitation phase')
    
    # Interactive AI Assistant command
    assistant_parser = subparsers.add_parser('ai-assistant', help='Start interactive AI assistant')
    assistant_parser.add_argument('--target', help='Initial target to set')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize report
    report_path = args.report if hasattr(args, 'report') and args.report else get_report_name()
    if hasattr(args, 'target'):
        init_report(report_path, args.target)
    
    try:
        if args.command == 'recon':
            handle_recon(args, report_path)
        elif args.command == 'scan':
            handle_scan(args, report_path)
        elif args.command == 'exploit':
            handle_exploit(args, report_path)
        elif args.command == 'post-exploit':
            handle_post_exploit(args, report_path)
        elif args.command == 'ai':
            handle_ai(args, report_path)
        elif args.command == 'full-assessment':
            handle_full_assessment(args, report_path)
        elif args.command == 'ai-assistant':
            handle_ai_assistant(args)
            
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

def handle_recon(args, report_path):
    """Handle AI-powered reconnaissance commands."""
    print(f"\n[+] Starting AI-powered {args.type} reconnaissance against {args.target}")
    
    # AI analysis of reconnaissance target
    if ai_engine and ai_available:
        ai_analysis = ai_engine.analyze_recon_target(args.target, args.type, args.level)
        print(f"[+] AI Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk level")
        
        # Add AI analysis to report
        append_section(
            report_path,
            f"AI Reconnaissance Analysis - {args.type.title()}",
            f"AI-powered analysis of {args.type} reconnaissance at {args.level} level",
            ai_analysis['ai_analysis'].get('commands', []),
            ai_analysis['ai_analysis'].get('key_information', []),
            ai_analysis['ai_analysis'].get('attack_vectors', []),
            [f"Risk Assessment: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')}"],
            ai_analysis
        )
    
    # Execute reconnaissance
    if args.type == 'passive':
        passive.run(args.target, report_path, level=args.level)
    elif args.type == 'active':
        active.run(args.target, report_path, level=args.level)
    elif args.type == 'osint':
        osint.run(args.target, report_path, level=args.level)
    elif args.type == 'dns':
        dns.run(args.target, report_path, level=args.level)
    elif args.type == 'cert':
        cert.run(args.target, report_path, level=args.level)
    elif args.type == 'shodan':
        shodan.run(args.target, report_path, level=args.level)
    elif args.type == 'whois':
        whois.run(args.target, report_path, level=args.level)

def handle_scan(args, report_path):
    """Handle AI-powered scanning commands."""
    print(f"\n[+] Starting AI-powered {args.type} scanning against {args.target}")
    
    # Execute scanning
    if args.type == 'ports':
        results = portscan.run(args.target, report_path, level=args.level, ports=args.ports)
    elif args.type == 'services':
        results = service.run(args.target, report_path, level=args.level)
    elif args.type == 'vulns':
        results = vuln.run(args.target, report_path, level=args.level)
    elif args.type == 'web':
        results = web.run(args.target, report_path, level=args.level)
    
    # AI analysis of scan results
    if ai_engine and ai_available and results:
        ai_analysis = ai_engine.analyze_scan_results(args.target, args.type, results)
        print(f"[+] AI Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk level")
        
        # Add AI analysis to report
        append_section(
            report_path,
            f"AI Scan Analysis - {args.type.title()}",
            f"AI-powered analysis of {args.type} scan results",
            [],
            ai_analysis['ai_analysis'].get('critical_vulnerabilities', []),
            ai_analysis['ai_analysis'].get('exploitation_opportunities', []),
            [f"Risk Assessment: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')}"],
            ai_analysis
        )

def handle_exploit(args, report_path):
    """Handle AI-powered exploitation commands."""
    print(f"\n[+] Starting AI-powered {args.type} exploitation against {args.target}")
    
    # AI exploitation suggestions
    if ai_engine and ai_available:
        target_info = {"target": args.target, "level": args.level, "type": args.type}
        ai_suggestions = ai_engine.suggest_exploitation_techniques(args.target, args.type, target_info)
        print(f"[+] AI Suggestions: {ai_suggestions['ai_suggestions'].get('success_probability', 0.0)} success probability")
        
        # Add AI suggestions to report
        append_section(
            report_path,
            f"AI Exploitation Suggestions - {args.type.title()}",
            f"AI-powered exploitation suggestions for {args.type}",
            [],
            ai_suggestions['ai_suggestions'].get('techniques', []),
            ai_suggestions['ai_suggestions'].get('tools', []),
            [f"Success Probability: {ai_suggestions['ai_suggestions'].get('success_probability', 0.0)}"],
            ai_suggestions
        )
    
    # Execute exploitation
    if args.type == 'password':
        password_attack.run(args.target, report_path, level=args.level, credentials=args.credentials)
    elif args.type == 'web':
        web_exploit.run(args.target, report_path, level=args.level)
    elif args.type == 'service':
        service_exploit.run(args.target, report_path, level=args.level)

def handle_post_exploit(args, report_path):
    """Handle AI-powered post-exploitation commands."""
    print(f"\n[+] Starting AI-powered {args.type} post-exploitation against {args.target}")
    
    # Map CLI type to dispatcher type
    type_map = {
        'privilege-escalation': 'privilege_escalation',
        'persistence': 'persistence',
        'lateral-movement': 'lateral_movement',
        'data-exfiltration': 'data_exfiltration',
    }
    post_exploit_type = type_map.get(args.type)
    if post_exploit_type:
        run_post_exploit(post_exploit_type, args.target, report_path, level=args.level, credentials=getattr(args, 'credentials', None))
    else:
        print(f"[!] Unknown post-exploitation type: {args.type}")

def handle_ai(args, report_path):
    """Handle AI-powered commands."""
    print(f"\n[+] Starting AI-powered {args.type} for {args.target}")
    
    if args.type == 'cve-research':
        if not args.cve:
            print("[!] CVE ID required for CVE research")
            return
        
        post_exploit_type = getattr(args, 'post_exploit_type', 'privilege_escalation')
        print(f"[*] Researching CVE {args.cve} for {post_exploit_type} against {args.target}")
        
        # Import and use the research function
        research_results = research_cve(args.cve, args.target, post_exploit_type)
        
        # Add research results to report
        if report_path:
            append_section(
                report_path,
                f"AI CVE Research - {args.cve}",
                f"AI-powered research of CVE {args.cve} for {post_exploit_type}",
                [f"Research CVE {args.cve} for {post_exploit_type}"],
                [f"Complexity: {research_results['ai_analysis']['complexity']}", 
                 f"Success Probability: {research_results['ai_analysis']['success_probability']}"],
                research_results['ai_analysis']['techniques'],
                [research_results['ai_analysis']['ai_notes']],
                research_results
            )
        
    elif args.type == 'recon-analysis':
        if not args.recon_type:
            print("[!] Reconnaissance type required for analysis")
            return
        
        level = getattr(args, 'level', 'basic')
        print(f"[*] Analyzing {args.recon_type} reconnaissance for {args.target}")
        
        if ai_engine and ai_available:
            ai_analysis = ai_engine.analyze_recon_target(args.target, args.recon_type, level)
            
            # Add analysis to report
            if report_path:
                append_section(
                    report_path,
                    f"AI Reconnaissance Analysis - {args.recon_type.title()}",
                    f"AI-powered analysis of {args.recon_type} reconnaissance",
                    ai_analysis['ai_analysis'].get('commands', []),
                    ai_analysis['ai_analysis'].get('key_information', []),
                    ai_analysis['ai_analysis'].get('attack_vectors', []),
                    [f"Risk Assessment: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')}"],
                    ai_analysis
                )
        
    elif args.type == 'scan-analysis':
        if not args.scan_type:
            print("[!] Scan type required for analysis")
            return
        
        print(f"[*] Analyzing {args.scan_type} scan results for {args.target}")
        
        # Simulate scan results for analysis (in real implementation, this would be actual results)
        scan_results = {"scan_type": args.scan_type, "target": args.target, "status": "completed"}
        
        if ai_engine and ai_available:
            ai_analysis = ai_engine.analyze_scan_results(args.target, args.scan_type, scan_results)
            
            # Add analysis to report
            if report_path:
                append_section(
                    report_path,
                    f"AI Scan Analysis - {args.scan_type.title()}",
                    f"AI-powered analysis of {args.scan_type} scan results",
                    [],
                    ai_analysis['ai_analysis'].get('critical_vulnerabilities', []),
                    ai_analysis['ai_analysis'].get('exploitation_opportunities', []),
                    [f"Risk Assessment: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')}"],
                    ai_analysis
                )
        
    elif args.type == 'exploit-suggestions':
        if not args.exploit_type:
            print("[!] Exploit type required for suggestions")
            return
        
        print(f"[*] Generating {args.exploit_type} exploitation suggestions for {args.target}")
        
        target_info = {"target": args.target, "type": args.exploit_type}
        
        if ai_engine and ai_available:
            ai_suggestions = ai_engine.suggest_exploitation_techniques(args.target, args.exploit_type, target_info)
            
            # Add suggestions to report
            if report_path:
                append_section(
                    report_path,
                    f"AI Exploitation Suggestions - {args.exploit_type.title()}",
                    f"AI-powered exploitation suggestions for {args.exploit_type}",
                    [],
                    ai_suggestions['ai_suggestions'].get('techniques', []),
                    ai_suggestions['ai_suggestions'].get('tools', []),
                    [f"Success Probability: {ai_suggestions['ai_suggestions'].get('success_probability', 0.0)}"],
                    ai_suggestions
                )
        
    elif args.type == 'summary':
        print(f"[*] Generating AI executive summary for {args.target}")
        
        if ai_engine and ai_available:
            phases_completed = ["reconnaissance", "scanning", "exploitation", "post-exploitation"]
            ai_summary = ai_engine.generate_ai_report_summary(args.target, phases_completed)
            
            # Add summary to report
            if report_path:
                append_section(
                    report_path,
                    "AI Executive Summary",
                    "AI-powered executive summary of the entire engagement",
                    [],
                    ai_summary['ai_summary'].get('critical_findings', []),
                    ai_summary['ai_summary'].get('recommendations', []),
                    [f"Overall Risk Assessment: {ai_summary['ai_summary'].get('risk_assessment', 'Unknown')}"],
                    ai_summary
                )
        
    elif args.type == 'generate-exploit':
        if not args.exploit_type:
            print("[!] Exploit type required for exploit generation")
            return
        print(f"[*] Generating {args.exploit_type} exploit for {args.target}")
        
    elif args.type == 'suggest-exploits':
        post_exploit_type = getattr(args, 'post_exploit_type', 'privilege_escalation')
        print(f"[*] Suggesting {post_exploit_type} exploits for {args.target}")
        
        # Import and use the suggest function
        suggestions = suggest_exploits(args.target, post_exploit_type)
        
        # Add suggestions to report
        if report_path:
            append_section(
                report_path,
                f"AI Exploit Suggestions - {post_exploit_type}",
                f"AI-powered exploit suggestions for {post_exploit_type}",
                [f"Generate suggestions for {post_exploit_type}"],
                suggestions['ai_suggestions'],
                [f"Generated {len(suggestions['ai_suggestions'])} suggestions"],
                ["Review and validate all AI suggestions before implementation"],
                suggestions
            )
        
    elif args.type == 'cleanup':
        post_exploit_type = getattr(args, 'post_exploit_type', 'all')
        print(f"[*] Cleaning up {post_exploit_type} artifacts for {args.target}")
        
        # Import and use the cleanup function
        cleanup_results = cleanup_artifacts(post_exploit_type)
        
    elif args.type == 'status':
        print(f"[*] Checking AI engine status for {args.target}")
        
        # Get AI status
        ai_status = get_ai_status()
        
        # Display status
        print(f"[+] AI Engine Status:")
        print(f"  - Ollama Available: {ai_status['ollama_available']}")
        print(f"  - Learning Enabled: {ai_status['learning_enabled']}")
        print(f"  - Cache Location: {ai_status['cache_location']}")
        print(f"  - Model: {ai_status['model']}")
        if 'capabilities' in ai_status:
            print(f"  - Capabilities: {', '.join(ai_status['capabilities'])}")
        
        # Add status to report
        if report_path:
            append_section(
                report_path,
                "AI Engine Status",
                "AI engine status check",
                ["Check AI engine status"],
                [f"Ollama Available: {ai_status['ollama_available']}", 
                 f"Learning Enabled: {ai_status['learning_enabled']}"],
                [f"Model: {ai_status['model']}", f"Cache: {ai_status['cache_location']}"],
                ["Ensure Ollama is running for full AI capabilities"],
                ai_status
            )

def handle_full_assessment(args, report_path):
    """Handle complete AI-powered assessment workflow."""
    print(f"\n[+] Starting AI-powered full assessment against {args.target}")
    print(f"[+] Level: {args.level}")
    
    results = {
        'target': args.target,
        'timestamp': datetime.now().isoformat(),
        'level': args.level,
        'phases': {}
    }
    
    phases_completed = []
    
    # Phase 1: Reconnaissance
    if not args.skip_recon:
        print("\n[+] Phase 1: AI-Powered Reconnaissance")
        phases_completed.append("reconnaissance")
        results['phases']['reconnaissance'] = {}
        
        # AI reconnaissance analysis
        if ai_engine and ai_available:
            ai_analysis = ai_engine.analyze_recon_target(args.target, "passive", args.level)
            print(f"[+] AI Recon Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk")
        
        # Passive reconnaissance
        print("[*] Running passive reconnaissance...")
        try:
            passive_results = passive.run(args.target, report_path, level=args.level)
            results['phases']['reconnaissance']['passive'] = passive_results
        except Exception as e:
            print(f"[!] Passive reconnaissance failed: {e}")
        
        # Active reconnaissance
        print("[*] Running active reconnaissance...")
        try:
            active_results = active.run(args.target, report_path, level=args.level)
            results['phases']['reconnaissance']['active'] = active_results
        except Exception as e:
            print(f"[!] Active reconnaissance failed: {e}")
    
    # Phase 2: Scanning/Enumeration
    if not args.skip_scan:
        print("\n[+] Phase 2: AI-Powered Scanning and Enumeration")
        phases_completed.append("scanning")
        results['phases']['scanning'] = {}
        
        # Port scanning
        print("[*] Running port scanning...")
        try:
            port_results = portscan.run(args.target, report_path, level=args.level)
            results['phases']['scanning']['ports'] = port_results
            
            # AI scan analysis
            if ai_engine and ai_available:
                ai_analysis = ai_engine.analyze_scan_results(args.target, "ports", port_results)
                print(f"[+] AI Scan Analysis: {ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')} risk")
        except Exception as e:
            print(f"[!] Port scanning failed: {e}")
        
        # Service enumeration
        print("[*] Running service enumeration...")
        try:
            service_results = service.run(args.target, report_path, level=args.level)
            results['phases']['scanning']['services'] = service_results
        except Exception as e:
            print(f"[!] Service enumeration failed: {e}")
        
        # Vulnerability scanning
        print("[*] Running vulnerability scanning...")
        try:
            vuln_results = vuln.run(args.target, report_path, level=args.level)
            results['phases']['scanning']['vulnerabilities'] = vuln_results
        except Exception as e:
            print(f"[!] Vulnerability scanning failed: {e}")
    
    # Phase 3: Exploitation
    if not args.skip_exploit:
        print("\n[+] Phase 3: AI-Powered Exploitation")
        phases_completed.append("exploitation")
        results['phases']['exploitation'] = {}
        
        # AI exploitation suggestions
        if ai_engine and ai_available:
            target_info = {"target": args.target, "level": args.level, "phases_completed": phases_completed}
            ai_suggestions = ai_engine.suggest_exploitation_techniques(args.target, "web", target_info)
            print(f"[+] AI Exploit Suggestions: {ai_suggestions['ai_suggestions'].get('success_probability', 0.0)} success probability")
        
        # Web exploitation
        print("[*] Running web exploitation...")
        try:
            web_exploit_results = web_exploit.run(args.target, report_path, level=args.level)
            results['phases']['exploitation']['web'] = web_exploit_results
        except Exception as e:
            print(f"[!] Web exploitation failed: {e}")
        
        # Service exploitation
        print("[*] Running service exploitation...")
        try:
            service_exploit_results = service_exploit.run(args.target, report_path, level=args.level)
            results['phases']['exploitation']['service'] = service_exploit_results
        except Exception as e:
            print(f"[!] Service exploitation failed: {e}")
    
    # Phase 4: Post-Exploitation
    if not args.skip_post_exploit:
        print("\n[+] Phase 4: AI-Powered Post-Exploitation")
        phases_completed.append("post-exploitation")
        results['phases']['post_exploitation'] = {}
        
        # Privilege escalation
        print("[*] Running privilege escalation...")
        try:
            priv_esc_results = privilege_escalation.run(args.target, report_path, level=args.level)
            results['phases']['post_exploitation']['privilege_escalation'] = priv_esc_results
        except Exception as e:
            print(f"[!] Privilege escalation failed: {e}")
    
    # Generate AI executive summary
    if ai_engine and ai_available:
        print("\n[+] Generating AI executive summary...")
        ai_summary = ai_engine.generate_ai_report_summary(args.target, phases_completed)
        
        # Add summary to report
        append_section(
            report_path,
            "AI Executive Summary",
            "AI-powered executive summary of the entire engagement",
            [],
            ai_summary['ai_summary'].get('critical_findings', []),
            ai_summary['ai_summary'].get('recommendations', []),
            [f"Overall Risk Assessment: {ai_summary['ai_summary'].get('risk_assessment', 'Unknown')}"],
            ai_summary
        )
    
    print(f"\n[+] AI-powered full assessment completed. Report saved to: {report_path}")
    return results

def handle_ai_assistant(args):
    """Handle interactive AI assistant."""
    try:
        from ai_assistant import HackingAIAssistant
        
        assistant = HackingAIAssistant()
        
        # Set initial target if provided
        if args.target:
            assistant.target = args.target
            assistant.report_path = get_report_name()
            init_report(assistant.report_path, args.target)
            print(f"🎯 Initial target set: {args.target}")
        
        assistant.start_conversation()
        
    except ImportError as e:
        print(f"[!] AI Assistant not available: {e}")
        print("[!] Make sure ai_assistant.py is in the current directory")
    except Exception as e:
        print(f"[!] Error starting AI assistant: {e}")

if __name__ == "__main__":
    main() 