#!/usr/bin/env python3
"""
Test script for LLM integration

This script tests the Mistral LLM integration via aimlapi.com to ensure
the setup is working correctly before integrating with agents.
"""

import asyncio
import os
import json
import logging
from datetime import datetime

from llm_client import LLMClient, LLMResponse
from utils.config_loader import load_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_basic_completion():
    """Test basic completion functionality"""
    print("\n=== Testing Basic Completion ===")
    
    try:
        # Load configuration
        config = load_config()
        llm_config = config.get("llm", {})
        
        if not llm_config.get("enabled", False):
            print("❌ LLM is not enabled in configuration")
            return False
            
        # Combine all config sections
        mistral_config = llm_config.get("mistral", {})
        mistral_config.update(llm_config.get("rate_limiting", {}))
        mistral_config.update(llm_config.get("tokens", {}))
        mistral_config.update(llm_config.get("caching", {}))
        
        # Check API key
        api_key = mistral_config.get("api_key") or os.getenv("LLM_API_KEY")
        if not api_key:
            print("❌ No API key found. Set LLM_API_KEY environment variable.")
            return False
            
        # Initialize client
        client = LLMClient(mistral_config)
        print(f"✅ LLM client initialized for model: {client.model}")
        
        # Test basic completion
        prompt = "What is a security alert? Provide a brief explanation in 2-3 sentences."
        
        print(f"📤 Sending prompt: {prompt}")
        response = await client.generate_completion(prompt)
        
        print(f"📥 Response received:")
        print(f"   Content: {response.content}")
        print(f"   Model: {response.model}")
        print(f"   Response time: {response.response_time:.2f}s")
        print(f"   Tokens used: {response.usage['total_tokens']}")
        print(f"   Cached: {response.cached}")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic completion test failed: {e}")
        return False


async def test_structured_completion():
    """Test structured JSON completion"""
    print("\n=== Testing Structured Completion ===")
    
    try:
        config = load_config()
        llm_config = config.get("llm", {})
        mistral_config = llm_config.get("mistral", {})
        mistral_config.update(llm_config.get("rate_limiting", {}))
        mistral_config.update(llm_config.get("tokens", {}))
        mistral_config.update(llm_config.get("caching", {}))
        
        client = LLMClient(mistral_config)
        
        # Test structured response
        prompt = """
        Analyze this security alert and provide a structured response:
        
        Alert: "Multiple failed login attempts detected from IP 192.168.1.100 for user 'admin'"
        """
        
        response_schema = {
            "alert_type": "string",
            "severity": "string (low/medium/high/critical)",
            "is_false_positive": "boolean",
            "confidence": "number (0-1)",
            "reasoning": "array of strings",
            "recommended_actions": "array of strings"
        }
        
        print(f"📤 Sending structured prompt...")
        response, parsed_data = await client.generate_structured_completion(
            prompt=prompt,
            response_format=response_schema
        )
        
        print(f"📥 Structured response received:")
        print(f"   Raw content: {response.content}")
        print(f"   Parsed data: {json.dumps(parsed_data, indent=2)}")
        print(f"   Response time: {response.response_time:.2f}s")
        
        # Validate structure
        if isinstance(parsed_data, dict) and "alert_type" in parsed_data:
            print("✅ Structured response parsed successfully")
            return True
        else:
            print("⚠️ Structured response format may be incorrect")
            return False
            
    except Exception as e:
        print(f"❌ Structured completion test failed: {e}")
        return False


async def test_system_prompt():
    """Test system prompt functionality"""
    print("\n=== Testing System Prompt ===")
    
    try:
        config = load_config()
        llm_config = config.get("llm", {})
        mistral_config = llm_config.get("mistral", {})
        mistral_config.update(llm_config.get("rate_limiting", {}))
        mistral_config.update(llm_config.get("tokens", {}))
        mistral_config.update(llm_config.get("caching", {}))
        
        client = LLMClient(mistral_config)
        
        system_prompt = """
        You are a cybersecurity expert analyzing security alerts. 
        Always provide responses in a professional, technical tone.
        Focus on accuracy and actionable insights.
        """
        
        prompt = "What should I do about a brute force attack alert?"
        
        print(f"📤 Sending prompt with system context...")
        response = await client.generate_completion(
            prompt=prompt,
            system_prompt=system_prompt
        )
        
        print(f"📥 Response with system prompt:")
        print(f"   Content: {response.content}")
        print(f"   Response time: {response.response_time:.2f}s")
        
        return True
        
    except Exception as e:
        print(f"❌ System prompt test failed: {e}")
        return False


async def test_rate_limiting():
    """Test rate limiting functionality"""
    print("\n=== Testing Rate Limiting ===")
    
    try:
        config = load_config()
        llm_config = config.get("llm", {})
        mistral_config = llm_config.get("mistral", {})
        
        # Enable rate limiting with low limits for testing
        rate_config = {
            "enabled": True,
            "requests_per_minute": 5,
            "burst_size": 2
        }
        mistral_config.update(rate_config)
        mistral_config.update(llm_config.get("tokens", {}))
        mistral_config.update(llm_config.get("caching", {}))
        
        client = LLMClient(mistral_config)
        
        print(f"📊 Testing rate limiting (max 5 req/min, burst 2)...")
        
        # Send multiple quick requests
        start_time = datetime.now()
        for i in range(3):
            try:
                response = await client.generate_completion(f"Count to {i+1}")
                elapsed = (datetime.now() - start_time).total_seconds()
                print(f"   Request {i+1} completed in {elapsed:.2f}s")
            except Exception as e:
                print(f"   Request {i+1} failed: {e}")
                
        return True
        
    except Exception as e:
        print(f"❌ Rate limiting test failed: {e}")
        return False


async def test_caching():
    """Test response caching"""
    print("\n=== Testing Response Caching ===")
    
    try:
        config = load_config()
        llm_config = config.get("llm", {})
        mistral_config = llm_config.get("mistral", {})
        mistral_config.update(llm_config.get("rate_limiting", {}))
        mistral_config.update(llm_config.get("tokens", {}))
        
        # Enable caching
        cache_config = {
            "enabled": True,
            "ttl": 60,  # 1 minute
            "max_cache_size": 100
        }
        mistral_config.update(cache_config)
        
        client = LLMClient(mistral_config)
        
        prompt = "What is the current date and time?"
        
        # First request
        print(f"📤 Sending first request...")
        response1 = await client.generate_completion(prompt)
        print(f"   First response time: {response1.response_time:.2f}s, cached: {response1.cached}")
        
        # Second identical request (should be cached)
        print(f"📤 Sending identical request...")
        response2 = await client.generate_completion(prompt)
        print(f"   Second response time: {response2.response_time:.2f}s, cached: {response2.cached}")
        
        if response2.cached and response2.response_time < response1.response_time:
            print("✅ Caching working correctly")
            return True
        else:
            print("⚠️ Caching may not be working as expected")
            return False
            
    except Exception as e:
        print(f"❌ Caching test failed: {e}")
        return False


async def test_error_handling():
    """Test error handling"""
    print("\n=== Testing Error Handling ===")
    
    try:
        config = load_config()
        llm_config = config.get("llm", {})
        mistral_config = llm_config.get("mistral", {})
        mistral_config.update(llm_config.get("rate_limiting", {}))
        mistral_config.update(llm_config.get("tokens", {}))
        mistral_config.update(llm_config.get("caching", {}))
        
        client = LLMClient(mistral_config)
        
        # Test with very long prompt that exceeds token limit
        long_prompt = "Analyze this alert: " + "X" * 20000  # Very long prompt
        
        print(f"📤 Testing token limit validation...")
        try:
            response = await client.generate_completion(long_prompt)
            print("⚠️ Long prompt was unexpectedly accepted")
        except ValueError as e:
            print(f"✅ Token limit validation working: {e}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False


async def main():
    """Run all tests"""
    print("🚀 Starting LLM Integration Tests")
    print("=" * 50)
    
    tests = [
        ("Basic Completion", test_basic_completion),
        ("Structured Completion", test_structured_completion),
        ("System Prompt", test_system_prompt),
        ("Rate Limiting", test_rate_limiting),
        ("Caching", test_caching),
        ("Error Handling", test_error_handling)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! LLM integration is ready.")
    else:
        print("⚠️  Some tests failed. Please check configuration and API key.")


if __name__ == "__main__":
    asyncio.run(main())
