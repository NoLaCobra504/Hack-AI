# Ollama Setup Guide for HackingAI

This guide will help you set up Ollama to enable the AI-powered capabilities of HackingAI.

## 🚀 Quick Start

### 1. Install Ollama

**Windows:**
1. Download from [https://ollama.ai/download](https://ollama.ai/download)
2. Run the installer
3. Restart your terminal

**Linux/macOS:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### 2. Start Ollama

```bash
ollama serve
```

### 3. Download AI Models

```bash
# Download the default model
ollama pull llama3.2

# Or try other models
ollama pull codellama    # Good for code analysis
ollama pull mistral      # Fast and efficient
ollama pull llama3.1     # Alternative to llama3.2
```

### 4. Test the Setup

```bash
# Test Ollama directly
ollama run llama3.2 "Hello, how are you?"

# Test HackingAI AI engine
python main.py ai status example.com
```

## 🔧 Configuration

### Model Selection

Edit `modules/ai_engine.py` to change the default model:

```python
class HackingAI:
    def __init__(self, ollama_url: str = "http://localhost:11434", ollama_model: str = "llama3.2"):
        # Change "llama3.2" to your preferred model
```

### Available Models

| Model | Size | Use Case | Performance |
|-------|------|----------|-------------|
| `llama3.2` | ~4GB | General purpose | Balanced |
| `codellama` | ~4GB | Code analysis | Excellent for exploits |
| `mistral` | ~4GB | Fast responses | Quick analysis |
| `llama3.1` | ~4GB | Alternative | Good balance |

### Ollama URL Configuration

If you're running Ollama on a different machine or port:

```python
# In modules/ai_engine.py
ai_engine = HackingAI(ollama_url="http://your-server:11434", ollama_model="llama3.2")
```

## 🧪 Testing AI Capabilities

### 1. Basic AI Status Check

```bash
python main.py ai status example.com
```

Expected output:
```
[+] AI Engine Status:
  - Ollama Available: True
  - Learning Enabled: True
  - Model: llama3.2
  - Capabilities: reconnaissance_analysis, scan_result_analysis, ...
```

### 2. AI Reconnaissance Analysis

```bash
python main.py ai recon-analysis example.com --recon-type passive --level advanced
```

### 3. AI Exploitation Suggestions

```bash
python main.py ai exploit-suggestions example.com --exploit-type web
```

### 4. AI CVE Research

```bash
python main.py ai cve-research example.com --cve CVE-2021-44228 --post-exploit-type privilege_escalation
```

## 🔍 Troubleshooting

### Common Issues

**1. "Ollama connection error: 404 Client Error"**
- Solution: Make sure Ollama is running (`ollama serve`)
- Check if the model is downloaded (`ollama list`)

**2. "Model not found"**
- Solution: Download the model (`ollama pull llama3.2`)

**3. "Connection refused"**
- Solution: Check if Ollama is running on the correct port (default: 11434)

**4. "Out of memory"**
- Solution: Use a smaller model or increase system RAM
- Try `mistral` instead of `llama3.2`

### Performance Optimization

**For Better Performance:**
1. Use SSD storage for models
2. Ensure sufficient RAM (8GB+ recommended)
3. Use GPU acceleration if available
4. Close other resource-intensive applications

**For Faster Responses:**
1. Use `mistral` model for quick analysis
2. Reduce model context length
3. Use local models instead of remote

## 📊 AI Capabilities

### What AI Can Do

1. **Reconnaissance Analysis**
   - Suggest optimal tools and techniques
   - Analyze target information
   - Provide risk assessments
   - Recommend next steps

2. **Scan Result Analysis**
   - Identify critical vulnerabilities
   - Prioritize attack vectors
   - Suggest exploitation techniques
   - Provide remediation recommendations

3. **Exploitation Suggestions**
   - Recommend specific tools
   - Estimate success probability
   - Suggest alternative approaches
   - Provide cleanup recommendations

4. **Post-Exploitation Intelligence**
   - Research CVEs for specific scenarios
   - Suggest privilege escalation techniques
   - Recommend persistence methods
   - Provide lateral movement strategies

### Fallback Mode

If Ollama is not available, the framework will:
- Continue with standard functionality
- Use pre-defined fallback analysis
- Provide basic recommendations
- Generate reports without AI insights

## 🔐 Security Considerations

### Privacy
- All AI processing happens locally
- No data is sent to external servers
- Models are downloaded and run locally

### Ethical Use
- AI suggestions are for authorized testing only
- Always verify AI recommendations before implementation
- Use responsibly and ethically

## 🎯 Advanced Configuration

### Custom Models

You can use custom fine-tuned models:

```bash
# Create a custom model
ollama create my-security-model -f Modelfile

# Use custom model in HackingAI
ai_engine = HackingAI(ollama_model="my-security-model")
```

### Model Fine-tuning

For specialized security analysis, consider fine-tuning models on:
- Security documentation
- Exploit techniques
- Vulnerability databases
- Penetration testing methodologies

### Integration with Other LLMs

The framework can be extended to support:
- OpenAI GPT models (with API key)
- Anthropic Claude models
- Local models via different APIs

## 📈 Performance Monitoring

### Monitor Ollama Performance

```bash
# Check model usage
ollama list

# Monitor system resources
# Use system monitoring tools to track CPU/RAM usage
```

### Optimize for Your Use Case

- **Fast Analysis**: Use `mistral` model
- **Detailed Analysis**: Use `llama3.2` or `codellama`
- **Code Focus**: Use `codellama` for exploit development
- **General Purpose**: Use `llama3.2` for comprehensive analysis

## 🆘 Support

### Getting Help

1. **Ollama Issues**: Check [Ollama documentation](https://ollama.ai/docs)
2. **Model Issues**: Try different models or reinstall
3. **Performance Issues**: Optimize system resources
4. **Framework Issues**: Check HackingAI documentation

### Community Resources

- [Ollama GitHub](https://github.com/ollama/ollama)
- [Ollama Discord](https://discord.gg/ollama)
- [HackingAI Issues](https://github.com/your-repo/issues)

---

**Happy AI-powered ethical hacking! 🤖🔒** 