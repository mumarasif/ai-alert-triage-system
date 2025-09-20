"""
Unit tests for AI-powered Severity Analyzer Agent
"""

import pytest
import asyncio
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from agents.severity_analyzer import SeverityAnalyzerAgent
from models.alert_models import SecurityAlert, AlertType, AlertSeverity
from coral_protocol import CoralMessage, MessageType, CoralRegistry
from llm.llm_client import LLMResponse


class TestSeverityAnalyzerAgent:
    """Test cases for AI-powered Severity Analyzer Agent"""
    
    @pytest.fixture
    async def analyzer(self):
        """Create a severity analyzer instance for testing"""
        analyzer = SeverityAnalyzerAgent()
        await analyzer.initialize_llm()
        return analyzer
    
    @pytest.fixture
    def sample_alert(self):
        """Create a sample security alert for testing"""
        return SecurityAlert(
            alert_id="TEST-001",
            timestamp=datetime.now(),
            source_system="EDR",
            alert_type=AlertType.MALWARE,
            description="Ransomware detected on critical server",
            source_ip="203.0.113.45",
            destination_ip="10.0.0.1",
            user_id="admin_user",
            hostname="SERVER-01",
            severity=AlertSeverity.LOW
        )
    
    @pytest.fixture
    def mock_llm_response(self):
        """Create a mock LLM response"""
        response = LLMResponse(
            content="Mock AI analysis response",
            model="mock_model",
            usage={"input_tokens": 100, "output_tokens": 50},
            response_time=0.5
        )
        response.structured_data = {
            "severity": "HIGH",
            "confidence": 0.85,
            "risk_score": 75,
            "reasoning": [
                "Ransomware detected on critical infrastructure",
                "Admin user account involved",
                "High business impact potential"
            ],
            "threat_indicators": ["Known malware signature", "Critical system targeted"],
            "business_impact": "Potential business disruption and data loss",
            "escalation_recommendation": "Immediate escalation to SOC lead",
            "time_sensitivity": "Critical - immediate response required",
            "recommended_actions": ["Isolate affected system", "Initiate incident response"],
            "analysis_summary": "Critical ransomware incident requiring immediate attention"
        }
        return response
    
    def test_agent_initialization(self, analyzer):
        """Test that the agent initializes correctly"""
        assert analyzer.agent_id == "severity_analyzer_ai"
        assert analyzer.name == "AI Severity Analyzer"
        assert len(analyzer.capabilities) == 2
        assert analyzer.alerts_analyzed == 0
        assert analyzer.severity_distribution == {}
        assert analyzer.escalations_performed == 0
    
    def test_agent_capabilities(self, analyzer):
        """Test that the agent has correct capabilities"""
        capability_names = [cap.name for cap in analyzer.capabilities]
        assert "determine_severity" in capability_names
        assert "escalate_severity" in capability_names
    
    @pytest.mark.asyncio
    async def test_llm_setup(self, analyzer):
        """Test that LLM capabilities are set up correctly"""
        assert "determine_severity" in analyzer.system_prompts
        assert "escalate_severity" in analyzer.system_prompts
        assert "determine_severity" in analyzer.prompt_templates
        assert "escalate_severity" in analyzer.prompt_templates
    
    @pytest.mark.asyncio
    async def test_severity_analysis_mock_mode(self, analyzer, sample_alert, mock_llm_response):
        """Test severity analysis in mock mode (no API key)"""
        # Ensure we're in testing mode
        analyzer.testing_mode = True
        
        # Create test message
        message = CoralMessage(
            id="test_msg_001",
            sender_id="test_sender",
            receiver_id=analyzer.agent_id,
            message_type=MessageType.SEVERITY_DETERMINATION,
            thread_id="test_thread",
            payload={"alert": sample_alert.to_dict()},
            timestamp=datetime.now()
        )
        
        # Mock the send_message method to avoid Coral Protocol requirements
        analyzer.send_message = AsyncMock()
        
        # Process the message
        await analyzer._analyze_severity(message)
        
        # Verify statistics were updated
        assert analyzer.alerts_analyzed == 1
        assert len(analyzer.confidence_scores) == 1
        assert "MEDIUM" in analyzer.severity_distribution  # Mock returns MEDIUM
        
        # Verify message was sent
        analyzer.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_direct_llm_analysis(self, analyzer, sample_alert, mock_llm_response):
        """Test direct LLM analysis functionality"""
        # Mock the llm_analyze method
        analyzer.llm_analyze = AsyncMock(return_value=mock_llm_response)
        
        # Prepare analysis parameters
        analysis_params = {
            "alert_id": sample_alert.alert_id,
            "alert_type": sample_alert.alert_type.value,
            "timestamp": sample_alert.timestamp.isoformat(),
            "source_ip": sample_alert.source_ip,
            "dest_ip": sample_alert.destination_ip,
            "user_id": sample_alert.user_id,
            "hostname": sample_alert.hostname,
            "description": sample_alert.description,
            "current_severity": sample_alert.severity.value,
            "raw_data": "{}"
        }
        
        # Perform analysis
        response = await analyzer.llm_analyze(
            "determine_severity",
            analysis_params,
            response_format={
                "severity": "string",
                "confidence": "number",
                "risk_score": "number",
                "reasoning": "array"
            }
        )
        
        # Verify response
        assert response.structured_data["severity"] == "HIGH"
        assert response.structured_data["confidence"] == 0.85
        assert response.structured_data["risk_score"] == 75
        assert len(response.structured_data["reasoning"]) == 3
    
    @pytest.mark.asyncio
    async def test_escalation_analysis(self, analyzer, sample_alert, mock_llm_response):
        """Test escalation analysis functionality"""
        # Mock escalation response
        escalation_response = LLMResponse(
            content="Escalation analysis",
            model="mock_model",
            usage={"input_tokens": 50, "output_tokens": 25},
            response_time=0.3
        )
        escalation_response.structured_data = {
            "escalation_approved": True,
            "new_severity": "CRITICAL",
            "escalation_reasoning": [
                "New threat intelligence indicates advanced persistent threat",
                "Additional systems may be compromised"
            ],
            "confidence": 0.9,
            "updated_risk_score": 95,
            "escalation_summary": "Escalation approved due to new threat indicators"
        }
        
        # Mock the llm_analyze method
        analyzer.llm_analyze = AsyncMock(return_value=escalation_response)
        analyzer.send_message = AsyncMock()
        
        # Create escalation message
        escalation_message = CoralMessage(
            id="escalation_msg_001",
            sender_id="test_sender",
            receiver_id=analyzer.agent_id,
            message_type=MessageType.AGENT_RESPONSE,
            thread_id="test_thread",
            payload={
                "capability": "escalate_severity",
                "alert": sample_alert.to_dict(),
                "current_severity": "HIGH",
                "escalation_reason": "New threat intelligence received",
                "additional_context": {"threat_level": "APT"}
            },
            timestamp=datetime.now()
        )
        
        # Process escalation
        await analyzer._handle_escalation(escalation_message)
        
        # Verify escalation was processed
        assert analyzer.escalations_performed == 1
        analyzer.send_message.assert_called_once()
    
    def test_agent_metrics(self, analyzer):
        """Test agent metrics collection"""
        # Simulate some activity
        analyzer.alerts_analyzed = 5
        analyzer.severity_distribution = {"HIGH": 2, "MEDIUM": 2, "LOW": 1}
        analyzer.escalations_performed = 1
        analyzer.confidence_scores = [0.8, 0.7, 0.9, 0.6, 0.85]
        
        metrics = analyzer.get_agent_metrics()
        
        assert metrics["agent_type"] == "ai_powered"
        assert metrics["alerts_analyzed"] == 5
        assert metrics["escalations_performed"] == 1
        assert metrics["average_confidence"] == 0.76  # Average of confidence scores
        assert metrics["severity_distribution"] == {"HIGH": 2, "MEDIUM": 2, "LOW": 1}
    
    @pytest.mark.asyncio
    async def test_health_check(self, analyzer):
        """Test agent health check"""
        health = await analyzer.health_check()
        
        assert health["status"] in ["healthy", "degraded", "unhealthy"]
        assert "issues" in health
        assert "metrics" in health
        assert "llm_enabled" in health
    
    def test_severity_enum_conversion(self, analyzer):
        """Test severity string to enum conversion"""
        # Test valid severity conversion
        test_cases = [
            ("CRITICAL", AlertSeverity.CRITICAL),
            ("HIGH", AlertSeverity.HIGH),
            ("MEDIUM", AlertSeverity.MEDIUM),
            ("LOW", AlertSeverity.LOW)
        ]
        
        for severity_str, expected_enum in test_cases:
            try:
                result = AlertSeverity(severity_str.upper())
                assert result == expected_enum
            except ValueError:
                pytest.fail(f"Failed to convert {severity_str} to AlertSeverity enum")
    
    @pytest.mark.asyncio
    async def test_message_handling(self, analyzer, sample_alert):
        """Test message handling for different message types"""
        analyzer._analyze_severity = AsyncMock()
        analyzer._handle_escalation = AsyncMock()
        
        # Test severity determination message
        severity_message = CoralMessage(
            id="test_msg_severity",
            sender_id="test_sender",
            receiver_id=analyzer.agent_id,
            message_type=MessageType.SEVERITY_DETERMINATION,
            thread_id="test_thread",
            payload={"alert": sample_alert.to_dict()},
            timestamp=datetime.now()
        )
        
        await analyzer.handle_message(severity_message)
        analyzer._analyze_severity.assert_called_once_with(severity_message)
        
        # Test escalation message
        escalation_message = CoralMessage(
            id="test_msg_escalation",
            sender_id="test_sender",
            receiver_id=analyzer.agent_id,
            message_type=MessageType.AGENT_RESPONSE,
            thread_id="test_thread",
            payload={"capability": "escalate_severity"},
            timestamp=datetime.now()
        )
        
        await analyzer.handle_message(escalation_message)
        analyzer._handle_escalation.assert_called_once_with(escalation_message)
    
    @pytest.mark.asyncio
    async def test_error_handling(self, analyzer, sample_alert):
        """Test error handling in analysis"""
        # Mock send_message for error reporting
        analyzer.send_message = AsyncMock()
        
        # Create a message that will cause an error
        invalid_message = CoralMessage(
            id="invalid_msg",
            sender_id="test_sender",
            receiver_id=analyzer.agent_id,
            message_type=MessageType.SEVERITY_DETERMINATION,
            thread_id="test_thread",
            payload={"invalid": "data"},  # Missing required 'alert' field
            timestamp=datetime.now()
        )
        
        # Process the invalid message
        await analyzer._analyze_severity(invalid_message)
        
        # Verify error message was sent
        analyzer.send_message.assert_called_once()
        call_args = analyzer.send_message.call_args[0][0]
        assert call_args.message_type == MessageType.ERROR
        assert "analysis failed" in call_args.payload["error"].lower()


# Run the tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
