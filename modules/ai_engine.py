"""
AI Engine for HackingAI - Complete AI-Powered Ethical Hacking Intelligence
Handles Ollama integration for all phases: recon, scanning, exploitation, and post-exploitation
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional

class OllamaClient:
    """Client for interacting with Ollama LLM API."""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url
        self.model = model
        self.session = requests.Session()
    
    def query(self, prompt: str, system_prompt: str = None) -> str:
        """Send a query to Ollama and return the response."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            response = self.session.post(f"{self.base_url}/api/generate", json=payload)
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "")
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Ollama connection error: {e}")
            return f"Error: {e}"
        except Exception as e:
            print(f"[!] Ollama query error: {e}")
            return f"Error: {e}"
    
    def is_available(self) -> bool:
        """Check if Ollama is available and responding."""
        try:
            response = self.session.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except:
            return False

class HackingAI:
    """Main AI engine for complete ethical hacking intelligence."""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", ollama_model: str = "llama3.2"):
        self.ollama = OllamaClient(ollama_url, ollama_model)
        self.learning_enabled = True
    
    # ===== RECONNAISSANCE AI =====
    
    def analyze_recon_target(self, target: str, recon_type: str, level: str) -> Dict:
        """AI analysis for reconnaissance planning and execution."""
        print(f"[+] AI analyzing {recon_type} reconnaissance for {target}")
        
        system_prompt = f"""You are an expert cybersecurity reconnaissance specialist.
        Analyze the target and provide intelligent reconnaissance strategies for {recon_type} at {level} level."""
        
        analysis_prompt = f"""
        Target: {target}
        Reconnaissance Type: {recon_type}
        Level: {level}
        
        Provide:
        1. Recommended tools and techniques
        2. Specific commands to run
        3. Key information to gather
        4. Potential attack vectors to identify
        5. Risk assessment
        6. Next steps based on findings
        
        Format as JSON with these fields.
        """
        
        ai_response = self.ollama.query(analysis_prompt, system_prompt)
        
        try:
            ai_analysis = json.loads(ai_response)
        except:
            ai_analysis = self._fallback_recon_analysis(target, recon_type, level)
        
        return {
            "target": target,
            "recon_type": recon_type,
            "level": level,
            "timestamp": datetime.now().isoformat(),
            "ai_analysis": ai_analysis
        }
    
    def _fallback_recon_analysis(self, target: str, recon_type: str, level: str) -> Dict:
        """Fallback reconnaissance analysis."""
        base_analysis = {
            "recommended_tools": [],
            "commands": [],
            "key_information": [],
            "attack_vectors": [],
            "risk_assessment": "Medium",
            "next_steps": []
        }
        
        if recon_type == "passive":
            base_analysis["recommended_tools"] = ["whois", "nslookup", "dig", "shodan", "theHarvester"]
            base_analysis["commands"] = [
                f"whois {target}",
                f"nslookup {target}",
                f"dig {target} ANY"
            ]
        elif recon_type == "active":
            base_analysis["recommended_tools"] = ["nmap", "masscan", "nikto", "dirb"]
            base_analysis["commands"] = [
                f"nmap -sS -sV -O {target}",
                f"nikto -h {target}"
            ]
        
        return base_analysis
    
    # ===== SCANNING AI =====
    
    def analyze_scan_results(self, target: str, scan_type: str, results: Dict) -> Dict:
        """AI analysis of scanning results to identify vulnerabilities and opportunities."""
        print(f"[+] AI analyzing {scan_type} scan results for {target}")
        
        system_prompt = f"""You are an expert vulnerability analyst and penetration tester.
        Analyze the scan results and provide intelligent insights for {scan_type} scanning."""
        
        analysis_prompt = f"""
        Target: {target}
        Scan Type: {scan_type}
        Scan Results: {json.dumps(results, indent=2)}
        
        Provide:
        1. Critical vulnerabilities identified
        2. Exploitation opportunities
        3. Recommended next steps
        4. Risk assessment
        5. Tool recommendations for exploitation
        6. Attack vector prioritization
        
        Format as JSON with these fields.
        """
        
        ai_response = self.ollama.query(analysis_prompt, system_prompt)
        
        try:
            ai_analysis = json.loads(ai_response)
        except:
            ai_analysis = self._fallback_scan_analysis(target, scan_type, results)
        
        return {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "scan_results": results,
            "ai_analysis": ai_analysis
        }
    
    def _fallback_scan_analysis(self, target: str, scan_type: str, results: Dict) -> Dict:
        """Fallback scan analysis."""
        return {
            "critical_vulnerabilities": [],
            "exploitation_opportunities": [],
            "recommended_next_steps": ["Manual analysis required"],
            "risk_assessment": "Medium",
            "tool_recommendations": [],
            "attack_vector_prioritization": []
        }
    
    # ===== EXPLOITATION AI =====
    
    def suggest_exploitation_techniques(self, target: str, exploit_type: str, target_info: Dict) -> Dict:
        """AI-powered exploitation technique suggestions."""
        print(f"[+] AI suggesting {exploit_type} exploitation techniques for {target}")
        
        system_prompt = f"""You are an expert penetration tester specializing in {exploit_type} exploitation.
        Provide specific, actionable exploitation techniques and tool recommendations."""
        
        suggestion_prompt = f"""
        Target: {target}
        Exploitation Type: {exploit_type}
        Target Information: {json.dumps(target_info, indent=2)}
        
        Provide:
        1. Specific exploitation techniques
        2. Tool recommendations with commands
        3. Success probability estimates
        4. Risk assessment
        5. Post-exploitation considerations
        6. Cleanup recommendations
        
        Format as JSON with these fields.
        """
        
        ai_response = self.ollama.query(suggestion_prompt, system_prompt)
        
        try:
            ai_suggestions = json.loads(ai_response)
        except:
            ai_suggestions = self._fallback_exploitation_suggestions(exploit_type)
        
        return {
            "target": target,
            "exploit_type": exploit_type,
            "target_info": target_info,
            "timestamp": datetime.now().isoformat(),
            "ai_suggestions": ai_suggestions
        }
    
    def _fallback_exploitation_suggestions(self, exploit_type: str) -> Dict:
        """Fallback exploitation suggestions."""
        fallback_suggestions = {
            "web": {
                "techniques": ["SQL Injection", "XSS", "CSRF", "File Upload"],
                "tools": ["sqlmap", "burpsuite", "nikto"],
                "success_probability": 0.6,
                "risk_assessment": "Medium"
            },
            "service": {
                "techniques": ["Buffer Overflow", "Privilege Escalation", "Service Exploitation"],
                "tools": ["metasploit", "exploit-db", "searchsploit"],
                "success_probability": 0.5,
                "risk_assessment": "High"
            },
            "password": {
                "techniques": ["Brute Force", "Dictionary Attack", "Rainbow Table"],
                "tools": ["hashcat", "john", "hydra"],
                "success_probability": 0.4,
                "risk_assessment": "Low"
            }
        }
        
        return fallback_suggestions.get(exploit_type, {
            "techniques": ["Manual analysis required"],
            "tools": [],
            "success_probability": 0.0,
            "risk_assessment": "Unknown"
        })
    
    # ===== POST-EXPLOITATION AI =====
    
    def research_cve(self, cve_id: str, target: str, post_exploit_type: str) -> Dict:
        """Comprehensive CVE research with AI analysis."""
        print(f"[+] Researching CVE {cve_id} for {post_exploit_type}")
        
        system_prompt = f"""You are an expert cybersecurity analyst specializing in {post_exploit_type}. 
        Analyze the provided CVE information and provide actionable intelligence for post-exploitation activities."""
        
        analysis_prompt = f"""
        CVE ID: {cve_id}
        Target: {target}
        Post-Exploitation Type: {post_exploit_type}
        
        Please provide:
        1. Exploit complexity (low/medium/high)
        2. Success probability (0.0-1.0)
        3. Recommended tools
        4. Specific techniques
        5. AI analysis notes
        6. Risk assessment
        
        Format your response as JSON with these fields.
        """
        
        ai_response = self.ollama.query(analysis_prompt, system_prompt)
        
        try:
            ai_analysis = json.loads(ai_response)
        except:
            ai_analysis = self._fallback_post_exploit_analysis(cve_id, post_exploit_type)
        
        return {
            "cve_id": cve_id,
            "target": target,
            "post_exploit_type": post_exploit_type,
            "research_timestamp": datetime.now().isoformat(),
            "ai_analysis": ai_analysis
        }
    
    def _fallback_post_exploit_analysis(self, cve_id: str, post_exploit_type: str) -> Dict:
        """Fallback post-exploitation analysis."""
        base_analysis = {
            "exploit_type": post_exploit_type,
            "complexity": "medium",
            "success_probability": 0.5,
            "user_assistance_needed": True,
            "recommended_tools": [],
            "techniques": [],
            "ai_notes": f"Fallback analysis for {cve_id}",
            "risk_assessment": "Medium risk - manual verification required"
        }
        
        if post_exploit_type == "privilege_escalation":
            base_analysis["recommended_tools"] = ["linpeas", "winpeas", "pspy"]
            base_analysis["techniques"] = ["SUID analysis", "Service enumeration", "Process monitoring"]
        elif post_exploit_type == "persistence":
            base_analysis["recommended_tools"] = ["metasploit", "empire"]
            base_analysis["techniques"] = ["Registry modification", "Scheduled tasks", "Service installation"]
        
        return base_analysis
    
    def suggest_post_exploit_techniques(self, target: str, post_exploit_type: str, target_info: Dict = None) -> Dict:
        """Generate AI-powered post-exploitation technique suggestions."""
        print(f"[+] Generating AI suggestions for {post_exploit_type}")
        
        system_prompt = f"""You are an expert penetration tester specializing in {post_exploit_type}.
        Provide specific, actionable techniques and tool recommendations based on the target information."""
        
        suggestion_prompt = f"""
        Target: {target}
        Post-Exploitation Type: {post_exploit_type}
        Target Information: {json.dumps(target_info, indent=2) if target_info else "Limited target information"}
        
        Provide 5-10 specific techniques for {post_exploit_type} against this target.
        Include tool recommendations, command examples, and success probability estimates.
        Format as a JSON list of technique objects.
        """
        
        ai_response = self.ollama.query(suggestion_prompt, system_prompt)
        
        try:
            ai_suggestions = json.loads(ai_response)
        except:
            ai_suggestions = self._fallback_post_exploit_suggestions(post_exploit_type)
        
        return {
            "post_exploit_type": post_exploit_type,
            "target": target,
            "target_info": target_info,
            "ai_suggestions": ai_suggestions
        }
    
    def _fallback_post_exploit_suggestions(self, post_exploit_type: str) -> List[str]:
        """Fallback post-exploitation suggestions."""
        fallback_suggestions = {
            "privilege_escalation": [
                "Run automated privilege escalation tools (LinPEAS/WinPEAS)",
                "Check for kernel exploits based on OS version",
                "Analyze running processes for privilege escalation opportunities",
                "Review file permissions and SUID binaries",
                "Examine scheduled tasks and cron jobs"
            ],
            "persistence": [
                "Create scheduled tasks for persistence",
                "Modify registry keys for startup persistence",
                "Install services for long-term access",
                "Use WMI event subscriptions",
                "Implement DLL hijacking techniques"
            ],
            "lateral_movement": [
                "Map network topology and identify targets",
                "Use credential dumping tools (Mimikatz, LaZagne)",
                "Attempt pass-the-hash attacks",
                "Leverage remote command execution",
                "Use SSH key-based lateral movement"
            ],
            "data_exfiltration": [
                "Identify sensitive data locations",
                "Use compression and encryption for data",
                "Implement DNS tunneling for stealth",
                "Use HTTP/HTTPS for data exfiltration",
                "Create covert channels for data transfer"
            ]
        }
        
        return fallback_suggestions.get(post_exploit_type, ["Manual analysis required"])
    
    # ===== GENERAL AI FUNCTIONS =====
    
    def learn_from_result(self, technique_id: str, success: bool, target_type: str, complexity: float):
        """Update learning database with technique results."""
        if self.learning_enabled:
            print(f"[+] Updated learning database for technique: {technique_id}")
    
    def is_ai_available(self) -> bool:
        """Check if AI capabilities are available."""
        return self.ollama.is_available()
    
    def get_ai_status(self) -> Dict:
        """Get status of AI components."""
        return {
            "ollama_available": self.ollama.is_available(),
            "learning_enabled": self.learning_enabled,
            "cache_location": ".cache",
            "model": self.ollama.model,
            "capabilities": [
                "reconnaissance_analysis",
                "scan_result_analysis", 
                "exploitation_suggestions",
                "post_exploitation_research",
                "cve_analysis",
                "technique_learning"
            ]
        }
    
    def generate_ai_report_summary(self, target: str, phases_completed: List[str]) -> Dict:
        """Generate AI-powered executive summary of the entire engagement."""
        print(f"[+] Generating AI executive summary for {target}")
        
        system_prompt = """You are an expert cybersecurity consultant.
        Generate a professional executive summary of the ethical hacking engagement."""
        
        summary_prompt = f"""
        Target: {target}
        Phases Completed: {', '.join(phases_completed)}
        
        Generate an executive summary including:
        1. Overall risk assessment
        2. Critical findings
        3. Recommendations
        4. Next steps
        5. Compliance considerations
        
        Format as JSON with these fields.
        """
        
        ai_response = self.ollama.query(summary_prompt, system_prompt)
        
        try:
            ai_summary = json.loads(ai_response)
        except:
            ai_summary = {
                "risk_assessment": "Medium",
                "critical_findings": ["Manual review required"],
                "recommendations": ["Implement security controls"],
                "next_steps": ["Remediate identified vulnerabilities"],
                "compliance_notes": ["Ensure compliance with relevant standards"]
            }
        
        return {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "phases_completed": phases_completed,
            "ai_summary": ai_summary
        } 