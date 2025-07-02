# HackingAI - AI-Powered Ethical Hacking Framework

A comprehensive, modular ethical hacking automation tool with advanced AI integration and conversational intelligence.

## 🌟 Key Features

### 🤖 **Advanced Conversational AI**
- **Natural Language Understanding**: Talk to the assistant like a real partner
- **Context-Aware Responses**: Understands what you're asking about (web services, SSH, ports, etc.)
- **Intelligent Parsing**: Handles typos, partial commands, and natural language variations
- **Conversational Patterns**: Responds to polite requests, gratitude, and uncertainty

### 🎯 **Smart Command Recognition**
The assistant understands various ways to ask for the same thing:
- `"show vuln"` → Shows vulnerabilities and scan results
- `"what's on port 80?"` → Focuses on web services
- `"any SSH issues?"` → Highlights SSH-related findings
- `"can you help me?"` → Provides contextual guidance
- `"thanks!"` → Acknowledges and continues the conversation

### 🔧 **Modular Architecture**
- **Reconnaissance**: Passive and active information gathering
- **Scanning & Enumeration**: Port scanning, service detection, vulnerability assessment
- **Exploitation**: Web exploits, service exploits, password attacks
- **Post-Exploitation**: Privilege escalation, persistence, lateral movement
- **AI Engine**: Ollama integration with multiple model support

### 📊 **Professional Reporting**
- **Final_Reports Directory**: Organized report storage
- **Markdown Format**: Professional, readable reports
- **AI Analysis**: Intelligent insights and recommendations
- **Multi-Phase Tracking**: Complete assessment workflow

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python dependency_check.py
```

### 2. Setup Ollama (Optional but Recommended)
```bash
# Follow OLLAMA_SETUP.md for detailed instructions
ollama pull llama3.2
ollama pull codellama
ollama pull mistral
```

### 3. Start the AI Assistant
```bash
python main.py ai-assistant
```

### 4. Interactive Usage
```
🤖 HackingAI Assistant > My target is example.com
🤖 HackingAI Assistant > Start scanning
🤖 HackingAI Assistant > Show vuln
🤖 HackingAI Assistant > What's on the web ports?
🤖 HackingAI Assistant > Can you help me exploit this?
```

## 🎯 Conversational Examples

### Setting Targets
```
"My target is vulnerable.com"
"I want to scan target.com"
"Let's test example.com"
```

### Viewing Results
```
"Show vuln"                    # General vulnerability overview
"What's on port 80?"           # Web service focus
"Any SSH issues?"              # SSH service focus
"Show me the web services"     # Web-specific results
"Tell me about the open ports" # Port-focused results
```

### Getting Help
```
"Can you help me?"
"What should I do next?"
"I'm not sure what to do"
"Please guide me"
```

### Natural Conversations
```
"Thanks for the help!"
"That's awesome!"
"Cool, what's next?"
"I think I found something"
```

## 📁 Project Structure

```
HackingAI/
├── main.py                    # Main CLI interface
├── ai_assistant.py           # Interactive AI assistant
├── modules/
│   ├── ai_engine.py          # Ollama AI integration
│   └── report_utils.py       # Report generation utilities
├── reconnaissance/           # Information gathering modules
├── Scan_Enum/               # Scanning and enumeration
├── Exploitation/            # Exploitation modules
├── Post_Exploitation/       # Post-exploitation modules
├── Final_Reports/           # Generated reports
├── requirements.txt         # Python dependencies
├── dependency_check.py      # Tool verification
├── README.md               # This file
└── OLLAMA_SETUP.md         # Ollama setup guide
```

## 🔧 Available Commands

### Main CLI
```bash
python main.py ai-assistant [--target TARGET]
python main.py recon [--target TARGET] [--level basic|advanced]
python main.py scan [--target TARGET] [--level basic|advanced]
python main.py exploit [--target TARGET] [--level basic|advanced]
python main.py post-exploit [--target TARGET] [--level basic|advanced]
python main.py full-assessment [--target TARGET]
```

### AI Assistant Commands
- **Target Setting**: `"My target is example.com"`
- **Reconnaissance**: `"Start reconnaissance"`, `"Begin recon"`
- **Scanning**: `"Start scanning"`, `"Scan ports"`
- **Exploitation**: `"Start exploitation"`, `"Begin exploits"`
- **Post-Exploitation**: `"Start post-exploitation"`
- **Results**: `"Show vuln"`, `"What's on port 80?"`, `"Show me the report"`
- **Help**: `"Help"`, `"What can you do?"`, `"What should I do next?"`

## 🧠 AI Integration

### Supported Models
- **llama3.2**: General purpose, good balance
- **codellama**: Code-focused analysis
- **mistral**: Fast and efficient

### AI Features
- **CVE Research**: Automatic vulnerability database queries
- **Exploit Suggestions**: AI-powered attack vector recommendations
- **Cleanup Guidance**: Post-assessment cleanup recommendations
- **Dynamic Analysis**: Context-aware security insights

## 🔒 Ethical Usage

This tool is designed for:
- ✅ **Authorized penetration testing**
- ✅ **Security research and education**
- ✅ **Vulnerability assessment with permission**
- ✅ **Red team exercises**

**Never use this tool against systems you don't own or have explicit permission to test.**

## 📚 Documentation

- **OLLAMA_SETUP.md**: Detailed Ollama installation and configuration
- **SCOPE.md**: Project scope and limitations
- **Final_Reports/**: Example reports and templates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and authorized security testing purposes only.

---

**Happy Ethical Hacking! 🎯🔒** 