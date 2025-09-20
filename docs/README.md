# AI-Powered Alert Triage System

**Next-generation security alert processing using AI agents and Coral Protocol orchestration**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![AI-Powered](https://img.shields.io/badge/AI-Powered-green.svg)](https://github.com/mumarasif/ai-alert-triage-system)

## 🎯 Overview

AI-powered security alert processing system using intelligent agents and Coral Protocol orchestration. Automatically analyzes, triages, and responds to security alerts with advanced AI capabilities.

### Key Features

- **🧠 AI-Powered Analysis**: Mistral LLM integration for intelligent alert processing
- **🔄 Multi-Agent Orchestration**: Coral Protocol for secure agent coordination
- **🎯 Smart Triage**: AI-driven false positive detection and severity assessment
- **⚡ Real-time Processing**: Webhook-based alert ingestion and processing
- **🔗 SIEM/SOAR Integration**: Native support for security platforms

## 🏗️ Architecture

AI agents work together to process security alerts:

1. **Alert Receiver** → Normalizes incoming alerts
2. **False Positive Checker** → AI analysis to identify false positives  
3. **Severity Analyzer** → AI-powered severity assessment
4. **Context Gatherer** → Enriches alerts with threat intelligence
5. **Response Coordinator** → Determines appropriate response actions
6. **Workflow Orchestrator** → Manages the entire process

All agents communicate securely through the Coral Protocol framework and use Mistral AI for intelligent analysis.

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- LLM API Key from [aimlapi.com](https://aimlapi.com/)

### Setup

```bash
# Clone the repository
git clone https://github.com/mumarasif/ai-alert-triage-system.git
cd ai-alert-triage-system

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file with your API key
echo "LLM_API_KEY=your-aimlapi-key-here" > .env

# Run the demo
python comprehensive_orchestration_demo.py
```

### Run the System

```bash
# Activate virtual environment (if not already active)
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Start the AI-powered system
python src/main.py

# Check system health
curl http://localhost:8080/health
```

## 📖 Usage

### Submit an Alert

```bash
curl -X POST http://localhost:8080/webhook/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "ALT-001",
    "type": "brute_force",
    "description": "Multiple failed login attempts detected",
    "source_ip": "203.0.113.45",
    "user_id": "admin_user"
  }'
```

### Monitor System

```bash
# Check system health
curl http://localhost:8080/health

# View metrics
curl http://localhost:8080/metrics
```

## 🔧 Configuration

Create a `.env` file in the project root:

```bash
# Required: Get your API key from https://aimlapi.com/
LLM_API_KEY=your-aimlapi-key-here

# Optional: Security settings
WEBHOOK_SECRET=your-webhook-secret
JWT_SECRET=your-jwt-secret

# Optional: External integrations
SIEM_ENDPOINT=https://your-siem-instance.com
SIEM_API_KEY=your-siem-key
SOAR_ENDPOINT=https://your-soar-instance.com
SOAR_API_KEY=your-soar-key
```

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# Test AI functionality
python -m pytest tests/unit/test_agents/ -v
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/mumarasif/ai-alert-triage-system/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mumarasif/ai-alert-triage-system/discussions)

---

**Built with ❤️ using Coral Protocol and cutting-edge AI technologies**