# LLM Integration Module

This module provides Large Language Model integration for the Alert Triage System, enabling AI-powered analysis and decision making for security alerts using Mistral via aimlapi.com.

## Components

### `llm_client.py` - LLM Client
- **LLMClient**: Main client for interacting with Mistral API via aimlapi.com
- **LLMResponse**: Response data structure
- **RateLimiter**: API call rate limiting
- **LLMCache**: Response caching for performance

### `llm_agent_base.py` - Base LLM Agent
- **LLMAgentBase**: Base class for creating LLM-powered agents
- Extends CoralAgent with LLM capabilities
- Provides prompt management, context tracking, and error handling

### `test_llm_integration.py` - Test Suite
- Comprehensive test suite for LLM integration
- Tests basic completion, structured responses, caching, rate limiting, and error handling

## Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configuration
Set your API key in environment variables:
```bash
export LLM_API_KEY="your-aimlapi-key"
```

Or update `config/default.yaml`:
```yaml
llm:
  enabled: true
  mistral:
    api_key: "your-api-key"
```

### 3. Test Integration
```bash
cd src/llm
python test_llm_integration.py
```

## Usage

### Basic LLM Client Usage
```python
from llm import LLMClient

# Initialize client
config = {
    "api_key": "your-api-key",
    "base_url": "https://api.aimlapi.com/v1",
    "model": "mistralai/Mistral-7B-Instruct-v0.2"
}
client = LLMClient(config)

# Generate completion
response = await client.generate_completion("Analyze this security alert...")
print(response.content)

# Generate structured response
response, data = await client.generate_structured_completion(
    prompt="Analyze alert...",
    response_format={"severity": "string", "confidence": "number"}
)
```

### Creating LLM-Powered Agents
```python
from llm import LLMAgentBase
from coral_protocol import AgentCapability

class MyLLMAgent(LLMAgentBase):
    def __init__(self):
        capabilities = [
            AgentCapability(name="analyze_alert", ...)
        ]
        super().__init__("my_agent", "My LLM Agent", capabilities)
        
    async def setup_llm_capabilities(self):
        # Register system prompts
        self.register_system_prompt("analyze_alert", 
            "You are a cybersecurity expert...")
        
        # Register prompt templates
        self.register_prompt_template("analyze_alert",
            "Analyze this alert: {alert_data}")
    
    async def handle_analyze_alert(self, message):
        response = await self.llm_analyze(
            "analyze_alert",
            {"alert_data": message.payload["alert"]},
            thread_id=message.thread_id
        )
        # Process response...
```

## Features

### Rate Limiting
- Configurable requests per minute and burst limits
- Automatic request queuing and delays

### Caching
- In-memory response caching
- Configurable TTL and cache size
- Automatic cache key generation

### Error Handling
- Retry logic with exponential backoff
- Token limit validation
- Comprehensive error messages

### Context Management
- Conversation context tracking
- Thread-based context isolation
- Automatic context trimming

## Configuration

### LLM Settings
```yaml
llm:
  enabled: true
  provider: "aimlapi"
  
  mistral:
    api_key: ""
    base_url: "https://api.aimlapi.com/v1"
    model: "mistralai/Mistral-7B-Instruct-v0.2"
    max_tokens: 4096
    temperature: 0.1
    timeout: 30
    max_retries: 3
    
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst_size: 10
    
  tokens:
    max_input_tokens: 8192
    max_output_tokens: 4096
    reserve_tokens: 512
    
  caching:
    enabled: true
    ttl: 3600
    max_cache_size: 1000
```

## Next Steps

This LLM integration is now ready to be used by agents. The next step would be to transform existing rule-based agents to use LLM capabilities:

1. **Transform False Positive Checker**: Replace rule-based logic with LLM analysis
2. **Transform Severity Analyzer**: Use LLM for severity assessment
3. **Transform Context Gatherer**: LLM-powered context analysis
4. **Transform Response Coordinator**: AI-driven response recommendations

Each agent can inherit from `LLMAgentBase` and define specific prompts and analysis logic using the LLM client.
