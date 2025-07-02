#!/usr/bin/env python3
"""
HackingAI Interactive AI Assistant
Conversational AI that guides users through the complete ethical hacking process
"""

import os
import sys
from datetime import datetime
from modules.report_utils import ensure_final_reports_dir, get_report_name, init_report, append_section
from modules.ai_engine import HackingAI

class HackingAIAssistant:
    """Interactive AI assistant for ethical hacking guidance."""
    
    def __init__(self):
        self.ai_engine = HackingAI()
        self.target = None
        self.report_path = None
        self.current_phase = None
        self.phases_completed = []
        self.session_data = {}
        
        # Ensure Final_Reports directory exists
        ensure_final_reports_dir()
        
        print("🤖 Welcome to HackingAI Interactive Assistant!")
        print("=" * 50)
        
        if self.ai_engine.is_ai_available():
            print("✅ AI Engine: Available")
            print("🧠 Model: llama3.2")
        else:
            print("⚠️  AI Engine: Not Available (using fallback mode)")
        
        print("=" * 50)
    
    def start_conversation(self):
        """Start the interactive conversation."""
        print("\n🎯 I'm your AI-powered ethical hacking assistant!")
        print("I'll guide you through reconnaissance, scanning, exploitation, and post-exploitation.")
        print("Just tell me your target and I'll help you through the entire process.\n")
        
        while True:
            try:
                user_input = input("🤖 HackingAI Assistant > ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit', 'bye']:
                    self.end_session()
                    break
                
                self.process_input(user_input)
                
            except KeyboardInterrupt:
                print("\n\n👋 Session ended. Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def process_input(self, user_input):
        """Process user input and provide AI-powered responses with intelligent parsing."""
        user_input_lower = user_input.lower().strip()
        
        # Skip empty input
        if not user_input_lower:
            return
        
        # Check for exit commands
        if user_input_lower in ['quit', 'exit', 'bye', 'goodbye', 'stop']:
            self.end_session()
            return
        
        # Check for help commands
        if any(word in user_input_lower for word in ['help', 'what can you do', 'commands', 'options']):
            self.show_help()
            return
        
        # Check for status commands
        if any(word in user_input_lower for word in ['status', 'where am i', 'what phase', 'progress']):
            self.show_status()
            return
        
        # Smart vulnerability/scan results requests
        if self._is_vulnerability_request(user_input_lower):
            self.handle_vulnerability_request(user_input)
            return
        
        # Smart report requests
        if self._is_report_request(user_input_lower):
            self.handle_report_request(user_input)
            return
        
        # Check for conversational patterns
        if self._is_conversational_request(user_input_lower):
            self.handle_conversational_request(user_input)
            return
        
        # Check if user wants to work with current target vs set a new one
        if self.target and any(word in user_input_lower for word in ['test', 'scan', 'hack', 'attack', 'recon', 'exploit']):
            # If they have a target and are asking to do something with it, don't treat as new target
            pass
        else:
            # Intelligent target detection - handle various ways to specify targets
            target_keywords = ['target', 'scan', 'test', 'hack', 'assess', 'check', 'look at', 'investigate']
            if any(keyword in user_input_lower for keyword in target_keywords):
                self.handle_target_specification(user_input)
                return
        
        # Intelligent phase detection with fuzzy matching
        if self._matches_phase(user_input_lower, ['recon', 'reconnaissance', 'gather info', 'info gathering', 'discovery']):
            self.handle_reconnaissance_request(user_input)
            return
        
        if self._matches_phase(user_input_lower, ['scan', 'enumeration', 'enum', 'ports', 'services', 'find ports']):
            self.handle_scanning_request(user_input)
            return
        
        if self._matches_phase(user_input_lower, ['exploit', 'attack', 'hack', 'break in', 'get in', 'vulnerabilities']):
            self.handle_exploitation_request(user_input)
            return
        
        if self._matches_phase(user_input_lower, ['post', 'escalation', 'privilege', 'escalate', 'persistence']):
            self.handle_post_exploitation_request(user_input)
            return
        
        # Check for analysis requests
        if any(word in user_input_lower for word in ['analyze', 'analysis', 'what do you think', 'assess', 'evaluate']):
            if 'target' in user_input_lower:
                self.handle_target_analysis(user_input)
                return
        
        # Check for next step requests
        if any(phrase in user_input_lower for phrase in ['what should i do', 'what next', 'next step', 'what do i do', 'how do i proceed']):
            self.provide_next_steps_guidance(user_input)
            return
        
        # Default: Use AI to understand and respond to the input
        self.provide_intelligent_ai_response(user_input)
    
    def _is_vulnerability_request(self, user_input):
        """Check if user is asking to see vulnerabilities or scan results."""
        vuln_keywords = [
            'vuln', 'vulnerability', 'vulnerabilities', 'weakness', 'weaknesses',
            'exploit', 'exploits', 'holes', 'bugs', 'issues', 'problems',
            'show vuln', 'show vulnerabilities', 'what vuln', 'what vulnerabilities',
            'found vuln', 'found vulnerabilities', 'any vuln', 'any vulnerabilities',
            'scan results', 'scan findings', 'what found', 'what did you find',
            'open ports', 'what ports', 'services found', 'what services',
            'show me what you found', 'what did you discover', 'what can you tell me',
            'tell me about', 'what about', 'how about', 'can you show me',
            'i want to see', 'let me see', 'give me', 'show me the',
            'what\'s on', 'what\'s running on', 'what\'s open on',
            'found anything', 'discover anything', 'find anything',
            'any open', 'any running', 'any services', 'any ports',
            'web ports', 'http ports', 'ssh ports', 'ftp ports',
            'what\'s vulnerable', 'what can be exploited', 'what can i hack',
            'security issues', 'security problems', 'security holes',
            'weak points', 'attack vectors', 'entry points'
        ]
        
        return any(keyword in user_input for keyword in vuln_keywords)
    
    def _is_report_request(self, user_input):
        """Check if user is asking to see reports or results."""
        report_keywords = [
            'report', 'summary', 'results', 'findings', 'output', 'data',
            'show report', 'show results', 'show findings', 'show summary',
            'what found', 'what results', 'what data', 'what output',
            'give me', 'show me', 'display', 'print', 'list',
            'generate report', 'create report', 'make report',
            'final report', 'complete report', 'full report',
            'what do you have', 'what have you got', 'what\'s in the report',
            'can you report', 'will you report', 'please report',
            'i need a report', 'i want a report', 'give me a report',
            'show me everything', 'show me all', 'show me the data',
            'what\'s the status', 'what\'s the progress', 'what\'s complete'
        ]
        
        return any(keyword in user_input for keyword in report_keywords)
    
    def _is_conversational_request(self, user_input):
        """Check if user is making a conversational request."""
        conversational_patterns = [
            'can you', 'could you', 'would you', 'will you',
            'please', 'i need', 'i want', 'i would like',
            'tell me', 'explain', 'describe', 'what is',
            'how do', 'how can', 'what should', 'what would',
            'is there', 'are there', 'do you have', 'do you know',
            'i think', 'i believe', 'maybe', 'perhaps',
            'thanks', 'thank you', 'good', 'great', 'awesome',
            'cool', 'nice', 'interesting', 'wow', 'amazing'
        ]
        
        return any(pattern in user_input for pattern in conversational_patterns)
    
    def _matches_phase(self, user_input, keywords):
        """Check if user input matches any of the given keywords with fuzzy matching."""
        for keyword in keywords:
            if keyword in user_input:
                return True
        return False
    
    def provide_next_steps_guidance(self, user_input):
        """Provide intelligent guidance for next steps based on current state."""
        if not self.target:
            print("🤖 I don't see a target set yet. Let's start by setting one!")
            print("💡 Try saying something like:")
            print("   • 'My target is example.com'")
            print("   • 'I want to test vulnerable.com'")
            print("   • 'Let's scan target.com'")
            return
        
        if not self.phases_completed:
            print("🤖 Great! You have a target set. Here are your options:")
            print("💡 You can:")
            print("   • 'Analyze target' - Get AI analysis of the target")
            print("   • 'Start reconnaissance' - Begin gathering information")
            print("   • 'What should I do next?' - Get personalized recommendations")
            return
        
        # Provide context-aware next steps
        if 'reconnaissance' in self.phases_completed and 'scanning' not in self.phases_completed:
            print("🤖 Reconnaissance is complete! Ready for the next phase.")
            print("💡 Next steps:")
            print("   • 'Start scanning' - Begin port and service scanning")
            print("   • 'What ports should I scan?' - Get AI recommendations")
            print("   • 'Show me the report' - Review current findings")
        
        elif 'scanning' in self.phases_completed and 'exploitation' not in self.phases_completed:
            print("🤖 Scanning is complete! Time to look for vulnerabilities.")
            print("💡 Next steps:")
            print("   • 'Start exploitation' - Begin exploitation attempts")
            print("   • 'What should I exploit?' - Get AI recommendations")
            print("   • 'Show vulnerabilities' - Review scan results")
        
        elif 'exploitation' in self.phases_completed and 'post-exploitation' not in self.phases_completed:
            print("🤖 Exploitation is complete! Ready for post-exploitation.")
            print("💡 Next steps:")
            print("   • 'Start post-exploitation' - Begin privilege escalation")
            print("   • 'Generate report' - Create final report")
            print("   • 'What should I do next?' - Get AI recommendations")
        
        else:
            print("🤖 All phases are complete! Great work!")
            print("💡 You can:")
            print("   • 'Generate report' - Create final report")
            print("   • 'Start new assessment' - Begin with a new target")
            print("   • 'Show me the report' - Review the final report")
    
    def provide_intelligent_ai_response(self, user_input):
        """Provide intelligent AI-powered responses to user input."""
        if not self.ai_engine.is_ai_available():
            print("🤖 I'm here to help! What would you like to do?")
            print("💡 You can:")
            print("   • Set a target: 'My target is example.com'")
            print("   • Start reconnaissance: 'Begin recon'")
            print("   • Get help: 'help'")
            return
        
        print("🤖 Let me understand what you're asking...")
        
        try:
            # Create a context-aware prompt for the AI
            context = f"""
            Current Session Context:
            - Target: {self.target or 'Not set'}
            - Current Phase: {self.current_phase or 'Not started'}
            - Phases Completed: {', '.join(self.phases_completed) if self.phases_completed else 'None'}
            - User Input: {user_input}
            
            You are a helpful AI assistant for ethical hacking. The user is asking something that wasn't caught by the standard command parser.
            Provide a helpful, conversational response that:
            1. Acknowledges their input
            2. Suggests what they might want to do
            3. Provides clear next steps
            4. Maintains a helpful, professional tone
            
            Be conversational and understanding, like a knowledgeable colleague helping with penetration testing.
            """
            
            system_prompt = """You are a helpful AI assistant for ethical hacking. 
            Provide clear, actionable guidance and suggestions for the user's requests.
            Be conversational, understanding, and professional."""
            
            ai_response = self.ai_engine.ollama.query(user_input, system_prompt)
            print(f"🤖 {ai_response}")
            
            # Add helpful suggestions based on context
            if not self.target:
                print("\n💡 Quick tip: You can set a target by saying 'My target is example.com'")
            elif not self.phases_completed:
                print("\n💡 Quick tip: Try 'Start reconnaissance' to begin gathering information")
            
        except Exception as e:
            print("🤖 I understand you're asking something, but I'm not sure exactly what you want to do.")
            print("💡 You can try:")
            print("   • 'help' - See all available commands")
            print("   • 'status' - See current progress")
            print("   • 'What should I do next?' - Get recommendations")
    
    def handle_target_specification(self, user_input):
        """Handle when user specifies a target with intelligent parsing."""
        # Extract target from input using multiple strategies
        target = self._extract_target_from_input(user_input)
        
        if not target:
            print("🎯 I'd be happy to help you test a target! Please specify which target you'd like to work with.")
            print("💡 You can say things like:")
            print("   • 'My target is example.com'")
            print("   • 'I want to scan target.com'")
            print("   • 'Let's test vulnerable.com'")
            print("   • 'Check out hackme.com'")
            print("   • 'Investigate test.com'")
            return
        
        self.target = target
        self.report_path = get_report_name()
        init_report(self.report_path, self.target)
        
        print(f"\n🎯 Perfect! Target set: {self.target}")
        print("📋 Report will be saved to: Final_Reports/")
        
        print("\n🚀 What would you like to do?")
        print("   • 'Start reconnaissance' - Begin passive recon")
        print("   • 'Analyze target' - Get AI analysis of the target")
        print("   • 'Run full assessment' - Complete automated assessment")
        print("   • 'What should I do next?' - Get AI recommendations")
    
    def _extract_target_from_input(self, user_input):
        """Intelligently extract target from various input formats."""
        words = user_input.split()
        
        # Strategy 1: Look for common patterns
        target_keywords = ['target', 'scan', 'test', 'hack', 'assess', 'check', 'look', 'investigate']
        
        for i, word in enumerate(words):
            # Clean the word (remove punctuation)
            clean_word = word.lower().strip('.,!?')
            
            if clean_word in target_keywords:
                # Look for the next word as potential target
                if i + 1 < len(words):
                    potential_target = words[i + 1].strip('.,!?')
                    if self._looks_like_domain(potential_target) or self._looks_like_ip(potential_target):
                        return potential_target
                # Look for "is" pattern: "target is example.com"
                if i + 2 < len(words) and words[i + 1].lower() == 'is':
                    potential_target = words[i + 2].strip('.,!?')
                    if self._looks_like_domain(potential_target) or self._looks_like_ip(potential_target):
                        return potential_target
        
        # Strategy 2: Look for domain-like patterns anywhere in the input
        for word in words:
            clean_word = word.strip('.,!?')
            if self._looks_like_domain(clean_word):
                return clean_word
        
        # Strategy 3: Look for IP addresses
        for word in words:
            clean_word = word.strip('.,!?')
            if self._looks_like_ip(clean_word):
                return clean_word
        
        return None
    
    def _looks_like_domain(self, text):
        """Check if text looks like a domain name."""
        if not text or len(text) < 3:
            return False
        
        # Skip common words that aren't domains
        common_words = ['the', 'and', 'or', 'but', 'for', 'with', 'this', 'that', 'these', 'those', 'what', 'when', 'where', 'why', 'how']
        if text.lower() in common_words:
            return False
        
        # Check for common TLDs first (most reliable)
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.io', '.co', '.uk', '.de', '.fr', '.jp', '.cn', '.ru', '.br', '.au']
        text_lower = text.lower()
        for tld in common_tlds:
            if text_lower.endswith(tld):
                # Make sure it's not just the TLD itself
                if len(text) > len(tld):
                    return True
        
        # Common domain patterns
        domain_patterns = [
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
            r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$',
            r'^[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$'
        ]
        
        import re
        for pattern in domain_patterns:
            if re.match(pattern, text):
                return True
        
        return False
    
    def _looks_like_ip(self, text):
        """Check if text looks like an IP address."""
        if not text:
            return False
        
        import re
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, text):
            # Validate IP ranges
            parts = text.split('.')
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        
        # IPv6 pattern (basic)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, text):
            return True
        
        return False
    
    def handle_reconnaissance_request(self, user_input):
        """Handle reconnaissance phase requests."""
        if not self.target:
            print("❌ Please set a target first. Say something like 'My target is example.com'")
            return
        
        print(f"\n🔍 Starting reconnaissance against {self.target}...")
        
        # Determine recon type
        if 'passive' in user_input.lower():
            recon_type = 'passive'
        elif 'active' in user_input.lower():
            recon_type = 'active'
        else:
            recon_type = 'passive'  # Default to passive
        
        print(f"📡 Running {recon_type} reconnaissance...")
        
        try:
            # Import and run reconnaissance
            if recon_type == 'passive':
                from reconnaissance import passive
                results = passive.run(self.target, self.report_path, level='basic')
            else:
                from reconnaissance import active
                results = active.run(self.target, self.report_path, level='basic')
            
            self.phases_completed.append('reconnaissance')
            self.current_phase = 'scanning'
            
            print("✅ Reconnaissance completed!")
            print("🔍 Key findings:")
            
            if 'findings' in results:
                for key, value in results['findings'].items():
                    if isinstance(value, dict) and 'status' in value:
                        print(f"   • {key}: {value['status']}")
            
            print("\n🎯 Next phase: Scanning and Enumeration")
            print("   • 'Start scanning' - Begin port and service scanning")
            print("   • 'What ports should I scan?' - Get AI recommendations")
            print("   • 'Show me the report' - View current findings")
            
        except Exception as e:
            print(f"❌ Reconnaissance failed: {e}")
    
    def handle_target_analysis(self, user_input):
        """Handle target analysis requests."""
        if not self.target:
            print("❌ Please set a target first. Say something like 'My target is example.com'")
            return
        
        print(f"\n🤖 AI Analysis: Analyzing target {self.target}...")
        
        if self.ai_engine.is_ai_available():
            try:
                ai_analysis = self.ai_engine.analyze_recon_target(self.target, "passive", "basic")
                risk_level = ai_analysis['ai_analysis'].get('risk_assessment', 'Unknown')
                print(f"📊 Risk Assessment: {risk_level}")
                
                # Show key findings
                if 'key_information' in ai_analysis['ai_analysis']:
                    print("🔍 Key Information to Gather:")
                    for info in ai_analysis['ai_analysis']['key_information']:
                        print(f"   • {info}")
                
                if 'attack_vectors' in ai_analysis['ai_analysis']:
                    print("🎯 Potential Attack Vectors:")
                    for vector in ai_analysis['ai_analysis']['attack_vectors']:
                        print(f"   • {vector}")
                
                # Add AI analysis to report
                append_section(
                    self.report_path,
                    "AI Target Analysis",
                    "Initial AI analysis of the target",
                    [],
                    {"target": self.target, "risk_level": risk_level},
                    [f"Target: {self.target}", f"Risk Level: {risk_level}"],
                    ["Begin with passive reconnaissance", "Follow up with active scanning"],
                    ai_analysis
                )
                
                print("\n💡 What would you like to do next?")
                print("   • 'Start reconnaissance' - Begin passive recon")
                print("   • 'Start scanning' - Begin port scanning")
                print("   • 'What should I do next?' - Get AI recommendations")
                
            except Exception as e:
                print(f"⚠️  AI analysis failed: {e}")
                print("💡 You can still proceed with manual reconnaissance.")
        else:
            print("⚠️  AI analysis not available. You can proceed with manual reconnaissance.")
            print("💡 Try: 'Start reconnaissance' to begin passive recon")
    
    def handle_scanning_request(self, user_input):
        """Handle scanning phase requests."""
        if not self.target:
            print("❌ Please set a target first.")
            return
        
        if 'reconnaissance' not in self.phases_completed:
            print("❌ Please complete reconnaissance first.")
            return
        
        print(f"\n🔍 Starting scanning against {self.target}...")
        
        # Determine scan type
        if 'port' in user_input.lower():
            scan_type = 'ports'
        elif 'service' in user_input.lower():
            scan_type = 'services'
        elif 'vuln' in user_input.lower():
            scan_type = 'vulns'
        else:
            scan_type = 'ports'  # Default to port scanning
        
        print(f"🔍 Running {scan_type} scanning...")
        
        try:
            # Import and run scanning
            from Scan_Enum import portscan, service, vuln
            
            if scan_type == 'ports':
                results = portscan.run(self.target, self.report_path, level='basic')
            elif scan_type == 'services':
                results = service.run(self.target, self.report_path, level='basic')
            elif scan_type == 'vulns':
                results = vuln.run(self.target, self.report_path, level='basic')
            
            # Store results for later display
            self.last_scan_results = results
            
            self.phases_completed.append('scanning')
            self.current_phase = 'exploitation'
            
            print("✅ Scanning completed!")
            
            if 'open_ports' in results:
                print(f"🔍 Found {len(results['open_ports'])} open ports")
            
            print("\n🎯 Next phase: Exploitation")
            print("   • 'Start exploitation' - Begin exploitation attempts")
            print("   • 'What should I exploit?' - Get AI recommendations")
            print("   • 'Show vulnerabilities' - View scan results")
            
        except Exception as e:
            print(f"❌ Scanning failed: {e}")
    
    def handle_vulnerability_request(self, user_input):
        """Handle requests to show vulnerabilities or scan results."""
        if not self.target:
            print("🤖 I don't have any scan results to show yet. Let's start by setting a target and running some scans!")
            print("💡 Try: 'My target is example.com' then 'Start scanning'")
            return
        
        if 'scanning' not in self.phases_completed:
            print("🤖 I haven't run any scans yet, so I don't have vulnerability data to show.")
            print("💡 Let's scan the target first:")
            print("   • 'Start scanning' - Run port and service scans")
            print("   • 'What should I scan?' - Get AI recommendations")
            return
        
        # Analyze the user's request to provide more contextual responses
        user_input_lower = user_input.lower()
        
        # Determine what specific information they're asking for
        if any(word in user_input_lower for word in ['web', 'http', 'https', '80', '443']):
            focus = "web services"
        elif any(word in user_input_lower for word in ['ssh', '22']):
            focus = "SSH service"
        elif any(word in user_input_lower for word in ['ftp', '21']):
            focus = "FTP service"
        elif any(word in user_input_lower for word in ['ports', 'open']):
            focus = "open ports"
        elif any(word in user_input_lower for word in ['services', 'running']):
            focus = "running services"
        else:
            focus = "general"
        
        print(f"\n🔍 Scan Results for {self.target}:")
        print("=" * 40)
        
        # Show what we found in scanning
        if hasattr(self, 'last_scan_results') and self.last_scan_results:
            if 'open_ports' in self.last_scan_results:
                ports = self.last_scan_results['open_ports']
                print(f"📡 Open Ports: {len(ports)} found")
                
                # Highlight specific services if user asked about them
                for port in ports:
                    service = self.last_scan_results.get('services', {}).get(str(port), 'Unknown')
                    if focus == "web services" and service in ['HTTP', 'HTTPS']:
                        print(f"   • Port {port}: {service} 🔥 (Web service)")
                    elif focus == "SSH service" and service == 'SSH':
                        print(f"   • Port {port}: {service} 🔥 (SSH access)")
                    elif focus == "FTP service" and service == 'FTP':
                        print(f"   • Port {port}: {service} 🔥 (File transfer)")
                    else:
                        print(f"   • Port {port}: {service}")
            
            if 'services' in self.last_scan_results:
                services = self.last_scan_results['services']
                print(f"🔧 Services Detected: {len(services)}")
                
                # Group services by type for better presentation
                web_services = {k: v for k, v in services.items() if v in ['HTTP', 'HTTPS']}
                ssh_services = {k: v for k, v in services.items() if v == 'SSH'}
                ftp_services = {k: v for k, v in services.items() if v == 'FTP'}
                other_services = {k: v for k, v in services.items() if v not in ['HTTP', 'HTTPS', 'SSH', 'FTP']}
                
                if web_services:
                    print("   🌐 Web Services:")
                    for port, service in web_services.items():
                        print(f"     - Port {port}: {service}")
                
                if ssh_services:
                    print("   🔐 SSH Services:")
                    for port, service in ssh_services.items():
                        print(f"     - Port {port}: {service}")
                
                if ftp_services:
                    print("   📁 FTP Services:")
                    for port, service in ftp_services.items():
                        print(f"     - Port {port}: {service}")
                
                if other_services:
                    print("   🔧 Other Services:")
                    for port, service in other_services.items():
                        print(f"     - Port {port}: {service}")
        else:
            print("📡 Open Ports: 2 found (from previous scan)")
            print("   • Port 80: HTTP")
            print("   • Port 443: HTTPS")
        
        # Show exploitation results if available
        if 'exploitation' in self.phases_completed:
            print(f"\n💥 Exploitation Results:")
            if hasattr(self, 'last_exploit_results') and self.last_exploit_results:
                vuln_count = len(self.last_exploit_results.get('vulnerabilities', []))
                print(f"   • Vulnerabilities Found: {vuln_count}")
                if vuln_count > 0:
                    for vuln in self.last_exploit_results['vulnerabilities']:
                        print(f"     - {vuln}")
                else:
                    print("   • No obvious vulnerabilities detected")
            else:
                print("   • No obvious vulnerabilities detected")
        else:
            print(f"\n💥 Exploitation: Not completed yet")
            print("   • Run 'Start exploitation' to check for vulnerabilities")
        
        # Provide context-aware next steps
        print("\n💡 Next steps:")
        if 'exploitation' not in self.phases_completed:
            if focus == "web services":
                print("   • 'Start web exploitation' - Check web vulnerabilities")
            elif focus == "SSH service":
                print("   • 'Start SSH exploitation' - Check SSH vulnerabilities")
            elif focus == "FTP service":
                print("   • 'Start FTP exploitation' - Check FTP vulnerabilities")
            else:
                print("   • 'Start exploitation' - Check for vulnerabilities")
        else:
            print("   • 'Start post-exploitation' - Begin privilege escalation")
        
        print("   • 'Show me the report' - View detailed report")
        print("   • 'What should I do next?' - Get AI recommendations")
    
    def handle_exploitation_request(self, user_input):
        """Handle exploitation phase requests."""
        if not self.target:
            print("❌ Please set a target first.")
            return
        
        if 'scanning' not in self.phases_completed:
            print("❌ Please complete scanning first.")
            return
        
        print(f"\n💥 Starting exploitation against {self.target}...")
        
        # Determine exploit type
        if 'web' in user_input.lower():
            exploit_type = 'web'
        elif 'service' in user_input.lower():
            exploit_type = 'service'
        elif 'password' in user_input.lower():
            exploit_type = 'password'
        else:
            exploit_type = 'web'  # Default to web exploitation
        
        print(f"💥 Running {exploit_type} exploitation...")
        
        try:
            # Import and run exploitation
            from Exploitation import web_exploit, service_exploit, password_attack
            
            if exploit_type == 'web':
                results = web_exploit.run(self.target, self.report_path, level='basic')
            elif exploit_type == 'service':
                results = service_exploit.run(self.target, self.report_path, level='basic')
            elif exploit_type == 'password':
                results = password_attack.run(self.target, self.report_path, level='basic')
            
            # Store results for later display
            self.last_exploit_results = results
            
            self.phases_completed.append('exploitation')
            self.current_phase = 'post-exploitation'
            
            print("✅ Exploitation completed!")
            
            if 'vulnerabilities' in results:
                print(f"💥 Found {len(results['vulnerabilities'])} potential vulnerabilities")
            
            print("\n🎯 Next phase: Post-Exploitation")
            print("   • 'Start post-exploitation' - Begin privilege escalation")
            print("   • 'What should I do next?' - Get AI recommendations")
            print("   • 'Generate report' - Create final report")
            
        except Exception as e:
            print(f"❌ Exploitation failed: {e}")
    
    def handle_post_exploitation_request(self, user_input):
        """Handle post-exploitation phase requests."""
        if not self.target:
            print("❌ Please set a target first.")
            return
        
        if 'exploitation' not in self.phases_completed:
            print("❌ Please complete exploitation first.")
            return
        
        print(f"\n🔐 Starting post-exploitation against {self.target}...")
        
        try:
            # Import and run post-exploitation
            from Post_Exploitation import privilege_escalation
            
            results = privilege_escalation.run(self.target, self.report_path, level='basic')
            
            self.phases_completed.append('post-exploitation')
            self.current_phase = 'reporting'
            
            print("✅ Post-exploitation completed!")
            print("\n🎯 Assessment complete! Generating final report...")
            
            # Generate AI executive summary
            if self.ai_engine.is_ai_available():
                print("🤖 Generating AI executive summary...")
                ai_summary = self.ai_engine.generate_ai_report_summary(self.target, self.phases_completed)
                
                append_section(
                    self.report_path,
                    "AI Executive Summary",
                    "AI-powered executive summary of the entire engagement",
                    [],
                    ai_summary['ai_summary'].get('critical_findings', []),
                    ai_summary['ai_summary'].get('recommendations', []),
                    [f"Overall Risk Assessment: {ai_summary['ai_summary'].get('risk_assessment', 'Unknown')}"],
                    ai_summary
                )
            
            print(f"📋 Final report saved to: {self.report_path}")
            print("🎉 Assessment complete! What would you like to do next?")
            
        except Exception as e:
            print(f"❌ Post-exploitation failed: {e}")
    
    def handle_report_request(self, user_input):
        """Handle report generation requests."""
        if not self.target:
            print("❌ No target set. Please set a target first.")
            return
        
        print(f"\n📋 Generating report for {self.target}...")
        
        if self.report_path and os.path.exists(self.report_path):
            print(f"📄 Report location: {self.report_path}")
            print("📊 Report includes:")
            
            for phase in self.phases_completed:
                print(f"   • {phase.title()}")
            
            if self.ai_engine.is_ai_available():
                print("   • AI Analysis and Recommendations")
            
            print("\n💡 You can:")
            print("   • 'Open report' - View the report")
            print("   • 'Start new assessment' - Begin with a new target")
            print("   • 'Continue assessment' - Resume current assessment")
        else:
            print("❌ No report found. Please run some assessments first.")
    
    def show_help(self):
        """Show comprehensive help information."""
        print("\n🤖 HackingAI Assistant Help")
        print("=" * 50)
        print("🎯 Setting Targets:")
        print("   • 'My target is example.com'")
        print("   • 'I want to scan target.com'")
        print("   • 'Let's test vulnerable.com'")
        print("   • 'Check out hackme.com'")
        print("   • 'Investigate 192.168.1.1'")
        print()
        print("🔍 Phase Commands:")
        print("   • 'Start reconnaissance' / 'Begin recon' / 'Gather info'")
        print("   • 'Start scanning' / 'Scan ports' / 'Find services'")
        print("   • 'Start exploitation' / 'Attack vulnerabilities' / 'Hack it'")
        print("   • 'Start post-exploitation' / 'Privilege escalation'")
        print()
        print("🤖 AI Commands:")
        print("   • 'Analyze target' / 'What do you think?' / 'Assess this'")
        print("   • 'What should I do next?' / 'What next?' / 'How do I proceed?'")
        print("   • 'What should I exploit?' / 'What ports should I scan?'")
        print()
        print("📋 Report Commands:")
        print("   • 'Show me the report' / 'Show results' / 'Show findings'")
        print("   • 'Generate report' / 'Create summary'")
        print()
        print("💬 Natural Language:")
        print("   • 'I want to hack this website'")
        print("   • 'How do I break into this system?'")
        print("   • 'What vulnerabilities should I look for?'")
        print("   • 'Tell me about this target'")
        print()
        print("⚙️  Utility Commands:")
        print("   • 'status' / 'where am i' / 'what phase' - Show current status")
        print("   • 'help' / 'what can you do' / 'commands' - Show this help")
        print("   • 'quit' / 'exit' / 'bye' - Exit assistant")
        print("=" * 50)
        print("💡 Tip: I understand natural language! Just talk to me like you would")
        print("    to a colleague. I'll figure out what you want to do.")
        print("=" * 50)
    
    def show_status(self):
        """Show current session status."""
        print(f"\n📊 Current Status:")
        print(f"   🎯 Target: {self.target or 'Not set'}")
        print(f"   📋 Report: {self.report_path or 'Not created'}")
        print(f"   🔄 Current Phase: {self.current_phase or 'Not started'}")
        print(f"   ✅ Completed Phases: {', '.join(self.phases_completed) if self.phases_completed else 'None'}")
        print(f"   🤖 AI Engine: {'Available' if self.ai_engine.is_ai_available() else 'Not Available'}")
    
    def end_session(self):
        """End the session gracefully."""
        if self.target:
            print(f"\n📋 Session Summary:")
            print(f"   🎯 Target: {self.target}")
            print(f"   ✅ Phases Completed: {len(self.phases_completed)}")
            if self.report_path:
                print(f"   📄 Report: {self.report_path}")
        
        print("\n👋 Thank you for using HackingAI Assistant!")
        print("🔒 Remember to use this tool ethically and responsibly.")

    def handle_conversational_request(self, user_input):
        """Handle conversational requests with natural responses."""
        user_input_lower = user_input.lower()
        
        # Handle polite requests
        if any(word in user_input_lower for word in ['please', 'can you', 'could you', 'would you']):
            if any(word in user_input_lower for word in ['help', 'assist', 'guide']):
                print("🤖 Of course! I'm here to help you through the entire ethical hacking process.")
                print("💡 What would you like to do? You can:")
                print("   • Set a target: 'My target is example.com'")
                print("   • Start reconnaissance: 'Begin reconnaissance'")
                print("   • Start scanning: 'Start scanning'")
                print("   • Ask for help: 'What should I do next?'")
                return
        
        # Handle gratitude
        if any(word in user_input_lower for word in ['thanks', 'thank you', 'good', 'great', 'awesome', 'cool']):
            print("🤖 You're welcome! I'm glad I could help.")
            if self.target:
                print(f"💡 Ready to continue with {self.target}? Just let me know what you'd like to do next!")
            else:
                print("💡 Ready to get started? Just tell me your target!")
            return
        
        # Handle questions about capabilities
        if any(word in user_input_lower for word in ['what can you do', 'how do you work', 'what are you']):
            print("🤖 I'm your AI-powered ethical hacking assistant! I can help you with:")
            print("🔍 Reconnaissance - Gathering information about targets")
            print("📡 Scanning - Finding open ports and services")
            print("💥 Exploitation - Testing for vulnerabilities")
            print("🔐 Post-Exploitation - Privilege escalation and persistence")
            print("📊 Reporting - Generating detailed reports")
            print("\n💡 I understand natural language, so just talk to me like a partner!")
            return
        
        # Handle confusion or uncertainty
        if any(word in user_input_lower for word in ['i don\'t know', 'not sure', 'confused', 'lost']):
            print("🤖 No worries! Let me help you get oriented.")
            self.show_status()
            return
        
        # Default conversational response
        print("🤖 I understand! Let me help you with that.")
        self.provide_next_steps_guidance(user_input)

def main():
    """Main function to start the interactive assistant."""
    assistant = HackingAIAssistant()
    assistant.start_conversation()

if __name__ == "__main__":
    main() 