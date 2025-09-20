"""
LLM Client for Mistral API integration via aimlapi.com

This module provides a unified interface for interacting with the Mistral LLM
through the aimlapi.com API provider.
"""

import os
import json
import time
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

import requests
import tiktoken
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from openai import OpenAI

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM API"""
    content: str
    model: str
    usage: Dict[str, int]
    response_time: float
    cached: bool = False
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class RateLimiter:
    """Simple rate limiter for LLM API calls"""
    
    def __init__(self, requests_per_minute: int = 100, burst_size: int = 10):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.requests = []
        
    def can_proceed(self) -> bool:
        """Check if we can make another request"""
        now = time.time()
        minute_ago = now - 60
        
        # Remove old requests
        self.requests = [req_time for req_time in self.requests if req_time > minute_ago]
        
        # Check limits
        if len(self.requests) >= self.requests_per_minute:
            return False
            
        # Check burst limit (last 10 seconds)
        ten_seconds_ago = now - 10
        recent_requests = [req_time for req_time in self.requests if req_time > ten_seconds_ago]
        if len(recent_requests) >= self.burst_size:
            return False
            
        return True
        
    def add_request(self):
        """Record a new request"""
        self.requests.append(time.time())


class LLMCache:
    """Simple in-memory cache for LLM responses"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self.cache = {}
        
    def _generate_key(self, prompt: str, model: str, params: Dict[str, Any]) -> str:
        """Generate cache key"""
        cache_data = {
            "prompt": prompt,
            "model": model,
            "params": {k: v for k, v in params.items() if k != "stream"}
        }
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()
        
    def get(self, prompt: str, model: str, params: Dict[str, Any]) -> Optional[LLMResponse]:
        """Get cached response"""
        key = self._generate_key(prompt, model, params)
        
        if key in self.cache:
            response, timestamp = self.cache[key]
            
            # Check if expired
            if datetime.now() - timestamp > timedelta(seconds=self.ttl):
                del self.cache[key]
                return None
                
            # Mark as cached
            response.cached = True
            return response
            
        return None
        
    def set(self, prompt: str, model: str, params: Dict[str, Any], response: LLMResponse):
        """Cache response"""
        key = self._generate_key(prompt, model, params)
        
        # Clean up old entries if cache is full
        if len(self.cache) >= self.max_size:
            # Remove oldest entry
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
            
        self.cache[key] = (response, datetime.now())


class LLMClient:
    """Client for interacting with Mistral LLM via aimlapi.com"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Extract configuration
        self.api_key = config.get("api_key") or os.getenv("LLM_API_KEY")
        if not self.api_key:
            raise ValueError("LLM API key not provided. Set LLM_API_KEY environment variable or in config.")
            
        self.base_url = config.get("base_url", "https://api.aimlapi.com/v1")
        self.model = config.get("model", "mistralai/Mistral-7B-Instruct-v0.2")
        self.max_tokens = config.get("max_tokens", 4096)
        self.temperature = config.get("temperature", 0.1)
        self.timeout = config.get("timeout", 30)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 1)
        
        # Initialize OpenAI client for compatible API
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout
        )
        
        # Token management
        token_config = config.get("tokens", {})
        self.max_input_tokens = token_config.get("max_input_tokens", 8192)
        self.max_output_tokens = token_config.get("max_output_tokens", 4096)
        self.reserve_tokens = token_config.get("reserve_tokens", 512)
        
        # Rate limiting
        rate_config = config.get("rate_limiting", {})
        if rate_config.get("enabled", True):
            self.rate_limiter = RateLimiter(
                requests_per_minute=rate_config.get("requests_per_minute", 100),
                burst_size=rate_config.get("burst_size", 10)
            )
        else:
            self.rate_limiter = None
            
        # Caching
        cache_config = config.get("caching", {})
        if cache_config.get("enabled", True):
            self.cache = LLMCache(
                max_size=cache_config.get("max_cache_size", 1000),
                ttl=cache_config.get("ttl", 3600)
            )
        else:
            self.cache = None
            
        # Initialize tokenizer for token counting
        try:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        except Exception as e:
            logger.warning(f"Failed to initialize tokenizer: {e}")
            self.tokenizer = None
            
        logger.info(f"Initialized LLM client for model: {self.model}")
        
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        else:
            # Rough approximation: 1 token ≈ 4 characters
            return len(text) // 4
            
    def validate_input_tokens(self, prompt: str) -> bool:
        """Validate that prompt doesn't exceed token limits"""
        token_count = self.count_tokens(prompt)
        max_allowed = self.max_input_tokens - self.reserve_tokens
        
        if token_count > max_allowed:
            logger.warning(f"Prompt too long: {token_count} tokens > {max_allowed} limit")
            return False
            
        return True
        
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((requests.RequestException, Exception))
    )
    async def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate completion from LLM"""
        
        # Rate limiting
        if self.rate_limiter:
            while not self.rate_limiter.can_proceed():
                logger.info("Rate limit reached, waiting...")
                time.sleep(1)
            self.rate_limiter.add_request()
            
        # Validate input
        if not self.validate_input_tokens(prompt):
            raise ValueError("Prompt exceeds token limit")
            
        # Prepare parameters
        params = {
            "model": self.model,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            **kwargs
        }
        
        # Check cache
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"System: {system_prompt}\n\nUser: {prompt}"
            
        if self.cache:
            cached_response = self.cache.get(full_prompt, self.model, params)
            if cached_response:
                logger.debug("Returning cached LLM response")
                return cached_response
                
        # Prepare messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        start_time = time.time()
        
        try:
            logger.debug(f"Sending request to LLM: {len(prompt)} chars")
            
            response = self.client.chat.completions.create(
                messages=messages,
                **params
            )
            
            response_time = time.time() - start_time
            
            # Extract response data
            content = response.choices[0].message.content
            usage = {
                "prompt_tokens": getattr(response.usage, 'prompt_tokens', 0),
                "completion_tokens": getattr(response.usage, 'completion_tokens', 0),
                "total_tokens": getattr(response.usage, 'total_tokens', 0)
            }
            
            llm_response = LLMResponse(
                content=content,
                model=self.model,
                usage=usage,
                response_time=response_time
            )
            
            # Cache response
            if self.cache:
                self.cache.set(full_prompt, self.model, params, llm_response)
                
            logger.debug(f"LLM response received: {response_time:.2f}s, {usage['total_tokens']} tokens")
            
            return llm_response
            
        except Exception as e:
            logger.error(f"LLM API error: {e}")
            raise
            
    async def generate_structured_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        response_format: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[LLMResponse, Dict[str, Any]]:
        """Generate completion and parse as JSON"""
        
        # Add JSON formatting instruction if not present
        if response_format and "format" not in prompt.lower():
            prompt += f"\n\nPlease respond in valid JSON format matching this schema: {json.dumps(response_format, indent=2)}"
            
        response = await self.generate_completion(prompt, system_prompt, **kwargs)
        
        # Try to parse as JSON
        try:
            parsed_content = json.loads(response.content.strip())
            return response, parsed_content
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            # Try to extract JSON from response
            content = response.content.strip()
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                if end != -1:
                    try:
                        parsed_content = json.loads(content[start:end].strip())
                        return response, parsed_content
                    except json.JSONDecodeError:
                        pass
                        
            # Return raw content if parsing fails
            return response, {"raw_content": response.content}
            
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            "model": self.model,
            "provider": "aimlapi",
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens
        }
        
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        stats = {
            "model": self.model,
            "requests_made": len(self.rate_limiter.requests) if self.rate_limiter else 0,
        }
        
        if self.cache:
            stats["cache_size"] = len(self.cache.cache)
            stats["cache_hits"] = sum(1 for _, (resp, _) in self.cache.cache.items() if resp.cached)
            
        return stats
