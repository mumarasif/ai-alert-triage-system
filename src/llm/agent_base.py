"""
Base LLM-powered Agent Class

This module provides a base class that combines Coral Protocol agent capabilities
with LLM integration, allowing agents to leverage AI for decision making.
"""

import json
import logging
import os
from typing import Dict, Any, Optional, List
from abc import abstractmethod
from datetime import datetime

from coral_protocol import CoralAgent, AgentCapability, CoralMessage, MessageType
from utils.config_loader import load_config
from .llm_client import LLMClient, LLMResponse

logger = logging.getLogger(__name__)


class LLMAgentBase(CoralAgent):
    """
    Base class for LLM-powered agents
    
    This class extends CoralAgent with LLM capabilities, providing:
    - LLM client management
    - Prompt engineering utilities
    - Structured response handling
    - Context management
    - Error handling for LLM operations
    """
    
    def __init__(self, agent_id: str, agent_name: str, capabilities: List[AgentCapability]):
        super().__init__(agent_id, agent_name, capabilities)
        
        # Load LLM configuration
        try:
            config = load_config("config/default.yaml")
        except Exception:
            # Fallback to basic config if file not found
            config = {"llm": {"enabled": False}}
        llm_config = config.get("llm", {})
        
        # Check if LLM API key is available
        api_key = os.getenv("LLM_API_KEY")
        llm_enabled = llm_config.get("enabled", False) and bool(api_key)
        
        if not llm_enabled:
            # Allow testing mode - initialize without LLM client
            self.llm_client = None
            self.testing_mode = True
            if not api_key:
                logger.warning("LLM_API_KEY not found in environment - running in testing mode")
            else:
                logger.warning("LLM is disabled in configuration - running in testing mode")
        else:
            self.testing_mode = False
            
            # Initialize LLM client
            mistral_config = llm_config.get("mistral", {})
            mistral_config.update(llm_config.get("rate_limiting", {}))
            mistral_config.update(llm_config.get("tokens", {}))
            mistral_config.update(llm_config.get("caching", {}))
            
            # Ensure API key is set
            mistral_config["api_key"] = api_key
            
            try:
                self.llm_client = LLMClient(mistral_config)
                logger.info(f"LLM client initialized for agent: {self.name}")
            except Exception as e:
                logger.error(f"Failed to initialize LLM client: {e}")
                self.llm_client = None
                self.testing_mode = True
        
        # Agent-specific prompt templates
        self.system_prompts = {}
        self.prompt_templates = {}
        
        # Context management
        self.conversation_context = {}
        self.max_context_length = 10
        
        logger.info(f"Initialized LLM-powered agent: {agent_name}")
        
    def register_system_prompt(self, capability_name: str, system_prompt: str):
        """Register a system prompt for a specific capability"""
        self.system_prompts[capability_name] = system_prompt
        
    def register_prompt_template(self, capability_name: str, template: str):
        """Register a prompt template for a specific capability"""
        self.prompt_templates[capability_name] = template
        
    def format_prompt(self, template_name: str, **kwargs) -> str:
        """Format a prompt template with provided parameters"""
        template = self.prompt_templates.get(template_name)
        if not template:
            raise ValueError(f"No prompt template found for: {template_name}")
            
        try:
            return template.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing template parameter: {e}")
            
    def add_to_context(self, thread_id: str, role: str, content: str):
        """Add message to conversation context"""
        if thread_id not in self.conversation_context:
            self.conversation_context[thread_id] = []
            
        self.conversation_context[thread_id].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now()
        })
        
        # Trim context if too long
        if len(self.conversation_context[thread_id]) > self.max_context_length:
            self.conversation_context[thread_id] = self.conversation_context[thread_id][-self.max_context_length:]
            
    def get_context_string(self, thread_id: str) -> str:
        """Get conversation context as formatted string"""
        if thread_id not in self.conversation_context:
            return ""
            
        context_parts = []
        for msg in self.conversation_context[thread_id]:
            context_parts.append(f"{msg['role']}: {msg['content']}")
            
        return "\n".join(context_parts)
        
    async def llm_analyze(
        self,
        capability_name: str,
        prompt_data: Dict[str, Any],
        thread_id: Optional[str] = None,
        temperature: Optional[float] = None,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Perform LLM analysis for a specific capability
        
        Args:
            capability_name: Name of the capability being executed
            prompt_data: Data to format the prompt template
            thread_id: Optional thread ID for context tracking
            temperature: Optional temperature override
            **kwargs: Additional parameters for LLM
            
        Returns:
            LLM response object
        """
        # Handle testing mode
        if self.testing_mode or not self.llm_client:
            logger.warning(f"LLM analysis requested for {capability_name} but running in testing mode")
            # Return mock response for testing
            from .llm_client import LLMResponse
            response = LLMResponse(
                content="Mock response - LLM not available",
                model="mock",
                usage={"input_tokens": 0, "output_tokens": 0},
                response_time=0.0
            )
            # Add structured_data as an attribute if response_format provided
            if response_format:
                response.structured_data = {
                    "severity": "MEDIUM",
                    "confidence": 0.5,
                    "risk_score": 50,
                    "reasoning": ["Mock analysis - LLM not available"],
                    "threat_indicators": ["Mock indicator"],
                    "business_impact": "Mock business impact assessment",
                    "escalation_recommendation": "Monitor closely",
                    "time_sensitivity": "Standard",
                    "recommended_actions": ["Mock action"],
                    "analysis_summary": "Mock analysis summary"
                }
            return response
        
        try:
            # Get system prompt
            system_prompt = self.system_prompts.get(capability_name)
            
            # Format prompt
            prompt = self.format_prompt(capability_name, **prompt_data)
            
            # Add context if thread_id provided
            if thread_id:
                context = self.get_context_string(thread_id)
                if context:
                    prompt = f"Previous conversation:\n{context}\n\nCurrent request:\n{prompt}"
                    
                # Add current prompt to context
                self.add_to_context(thread_id, "user", prompt)
                
            logger.debug(f"Performing LLM analysis for capability: {capability_name}")
            
            # Generate response with structured format if provided
            if response_format:
                response, structured_data = await self.llm_client.generate_structured_completion(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response_format=response_format,
                    temperature=temperature,
                    **kwargs
                )
                # Add structured data to response object
                response.structured_data = structured_data
            else:
                response = await self.llm_client.generate_completion(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    **kwargs
                )
            
            # Add response to context
            if thread_id:
                self.add_to_context(thread_id, "assistant", response.content)
                
            return response
            
        except Exception as e:
            logger.error(f"LLM analysis failed for {capability_name}: {e}")
            raise
            
    async def llm_analyze_structured(
        self,
        capability_name: str,
        prompt_data: Dict[str, Any],
        response_schema: Dict[str, Any],
        thread_id: Optional[str] = None,
        **kwargs
    ) -> tuple[LLMResponse, Dict[str, Any]]:
        """
        Perform structured LLM analysis with JSON response
        
        Args:
            capability_name: Name of the capability being executed
            prompt_data: Data to format the prompt template
            response_schema: Expected JSON schema for response
            thread_id: Optional thread ID for context tracking
            **kwargs: Additional parameters for LLM
            
        Returns:
            Tuple of (LLM response, parsed JSON data)
        """
        try:
            # Get system prompt
            system_prompt = self.system_prompts.get(capability_name)
            
            # Format prompt
            prompt = self.format_prompt(capability_name, **prompt_data)
            
            # Add context if thread_id provided
            if thread_id:
                context = self.get_context_string(thread_id)
                if context:
                    prompt = f"Previous conversation:\n{context}\n\nCurrent request:\n{prompt}"
                    
            logger.debug(f"Performing structured LLM analysis for capability: {capability_name}")
            
            # Generate structured response
            response, parsed_data = await self.llm_client.generate_structured_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                response_format=response_schema,
                **kwargs
            )
            
            # Add to context
            if thread_id:
                self.add_to_context(thread_id, "user", prompt)
                self.add_to_context(thread_id, "assistant", response.content)
                
            return response, parsed_data
            
        except Exception as e:
            logger.error(f"Structured LLM analysis failed for {capability_name}: {e}")
            raise
            
    def create_analysis_prompt(self, alert_data: Dict[str, Any]) -> str:
        """
        Create a formatted prompt for alert analysis
        
        This method can be overridden by subclasses for custom prompt formatting
        """
        return f"""
        Analyze the following security alert:
        
        Alert ID: {alert_data.get('alert_id', 'Unknown')}
        Type: {alert_data.get('type', 'Unknown')}
        Description: {alert_data.get('description', 'No description')}
        Source System: {alert_data.get('source_system', 'Unknown')}
        Timestamp: {alert_data.get('timestamp', 'Unknown')}
        
        Additional Details:
        {json.dumps({k: v for k, v in alert_data.items() if k not in ['alert_id', 'type', 'description', 'source_system', 'timestamp']}, indent=2)}
        """
        
    async def handle_llm_error(self, error: Exception, capability_name: str, message: CoralMessage):
        """
        Handle LLM-related errors and send appropriate error responses
        
        Args:
            error: The exception that occurred
            capability_name: Name of the capability that failed
            message: Original message being processed
        """
        error_msg = f"LLM analysis failed for {capability_name}: {str(error)}"
        logger.error(error_msg)
        
        # Create error response
        error_response = CoralMessage(
            id=f"error_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            message_type=MessageType.ERROR,
            thread_id=message.thread_id,
            payload={
                "error": error_msg,
                "original_message_id": message.id,
                "capability": capability_name,
                "error_type": "llm_analysis_error"
            },
            timestamp=datetime.now()
        )
        
        await self.send_message(error_response)
        
    @abstractmethod
    async def setup_llm_capabilities(self):
        """
        Setup LLM-specific prompts and templates for this agent
        
        This method must be implemented by subclasses to define:
        - System prompts for each capability
        - Prompt templates for different analysis types
        - Any agent-specific LLM configuration
        """
        pass
        
    async def initialize_llm(self):
        """Initialize LLM capabilities for this agent"""
        await self.setup_llm_capabilities()
        logger.info(f"LLM capabilities initialized for {self.name}")
    
    async def initialize(self):
        """Initialize the LLM agent"""
        logger.info(f"Initializing LLM Agent: {self.agent_id}")
        
        # Initialize LLM capabilities if available
        await self.initialize_llm()
        
        # Set status to online
        self.status = "online"
        
        logger.info(f"LLM Agent {self.agent_id} initialized successfully")
        
    def get_llm_stats(self) -> Dict[str, Any]:
        """Get LLM client statistics"""
        if self.llm_client and hasattr(self.llm_client, 'get_stats'):
            return self.llm_client.get_stats()
        else:
            return {
                "total_requests": 0,
                "total_tokens": 0,
                "cache_hits": 0,
                "errors": 0,
                "testing_mode": True
            }
        
    def get_model_info(self) -> Dict[str, Any]:
        """Get LLM model information"""
        return self.llm_client.get_model_info()
