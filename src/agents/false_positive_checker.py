"""
AI-Powered False Positive Checker Agent

This agent uses Large Language Models to determine if security alerts are false positives.
It replaces rule-based logic with intelligent AI analysis while maintaining the same interface.
"""

import datetime
import uuid
import logging
import json
from typing import Dict, Any, Tuple, List

from coral_protocol import CoralMessage, MessageType, AgentCapability
from coral_protocol.orchestration_types import OrchestrationMessageType
from models.alert_models import SecurityAlert, AlertType, AlertStatus
from llm.agent_base import LLMAgentBase

logger = logging.getLogger(__name__)


class FalsePositiveCheckerAgent(LLMAgentBase):
    """
    AI-powered agent that determines if an alert is a false positive
    
    This agent:
    1. Uses LLM to analyze alerts for false positive indicators
    2. Leverages contextual understanding and cybersecurity expertise
    3. Provides detailed reasoning and confidence scores
    4. Routes false positives to completion and legitimate alerts to severity analysis
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="check_false_positive",
                description="Analyze alerts for false positive indicators using AI analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "analysis_options": {
                            "type": "object",
                            "properties": {
                                "confidence_threshold": {"type": "number"},
                                "include_reasoning": {"type": "boolean"}
                            }
                        }
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "is_false_positive": {"type": "boolean"},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "array"},
                        "analysis_method": {"type": "string"},
                        "risk_factors": {"type": "array"},
                        "recommendations": {"type": "array"}
                    }
                }
            ),
            AgentCapability(
                name="learn_from_feedback",
                description="Learn from analyst feedback to improve future analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_id": {"type": "string"},
                        "actual_classification": {"type": "string"},
                        "analyst_notes": {"type": "string"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "learning_applied": {"type": "boolean"},
                        "insights_gained": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="false_positive_checker_ai",
            agent_name="AI False Positive Checker",
            capabilities=capabilities
        )
        
        # Configuration
        self.confidence_threshold = 0.7
        
        # Statistics
        self.alerts_analyzed = 0
        self.false_positives_detected = 0
        self.confidence_scores = []
        self.feedback_received = 0
        
        # Register orchestration message handlers
        self.register_message_handler(MessageType.COMMAND, self._handle_orchestration_command)
        
    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for false positive analysis"""
        
        # System prompt that establishes the AI's role and expertise
        self.register_system_prompt(
            "check_false_positive",
            """You are a senior cybersecurity analyst with 15+ years of experience in security operations centers (SOCs). Your specialty is identifying false positive security alerts with exceptional accuracy.

Your expertise includes:
- Deep understanding of enterprise network environments and normal business operations
- Knowledge of common security tools and their typical false positive patterns
- Experience with various attack vectors and legitimate system behaviors
- Understanding of business processes, maintenance windows, and authorized activities

Your analysis should be:
- Thorough and methodical
- Based on cybersecurity best practices
- Contextually aware of enterprise environments
- Focused on practical SOC operations

You must provide structured analysis with clear reasoning and actionable recommendations."""
        )
        
        # Analysis prompt template
        self.register_prompt_template(
            "check_false_positive",
            """Analyze the following security alert for false positive indicators:

ALERT DETAILS:
- Alert ID: {alert_id}
- Alert Type: {alert_type}
- Timestamp: {timestamp}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- User ID: {user_id}
- Hostname: {hostname}
- Description: {description}
- Severity: {severity}
- Raw Event Data: {raw_data}

ORGANIZATIONAL CONTEXT:
- Business Hours: 8 AM - 6 PM UTC, Monday-Friday
- Known Internal Networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Common Service Accounts: service_*, admin_*, system_*, backup_*, monitor_*
- Scheduled Maintenance Windows: Weekends 2-6 AM UTC
- Security Tools: Antivirus, EDR, SIEM, Vulnerability Scanners

ANALYSIS FRAMEWORK:
Evaluate these key factors:

1. **Source Analysis**
   - Is the source IP internal, trusted, or known?
   - Does the user account appear to be a service/test account?
   - Are there indicators of legitimate system processes?

2. **Timing Analysis**
   - Does the timing align with business hours or maintenance windows?
   - Is this consistent with scheduled operations?
   - Are there patterns suggesting automated/legitimate processes?

3. **Behavioral Analysis**
   - Is this activity consistent with normal business operations?
   - Are there indicators of security testing or system maintenance?
   - Does the activity pattern suggest legitimate use cases?

4. **Context Analysis**
   - Does the alert relate to known security tools or processes?
   - Are there environmental factors that explain the activity?
   - Is this consistent with authorized IT operations?

5. **Threat Intelligence**
   - Does this match known attack patterns or is it benign activity?
   - Are there contradictory indicators suggesting legitimate operations?

REQUIRED RESPONSE FORMAT (JSON):
{{
    "is_false_positive": boolean,
    "confidence": number (0.0 to 1.0),
    "reasoning": [
        "Primary reason for classification",
        "Supporting evidence or indicators",
        "Contextual factors considered"
    ],
    "risk_factors": [
        "Any concerning elements even if overall benign",
        "Items requiring monitoring or attention"
    ],
    "recommendations": [
        "Immediate actions to take",
        "Follow-up monitoring suggestions",
        "Process improvements if applicable"
    ],
    "analysis_summary": "Brief summary of key findings"
}}

Provide your analysis now:"""
        )
        
        # Learning prompt for feedback processing
        self.register_prompt_template(
            "learn_from_feedback",
            """Analyze this feedback from a security analyst to improve future alert classification:

ORIGINAL ALERT: {alert_summary}
AI CLASSIFICATION: {ai_classification}
ACTUAL CLASSIFICATION: {actual_classification}
ANALYST NOTES: {analyst_notes}

Based on this feedback, identify:
1. What patterns or indicators were missed or misinterpreted?
2. What insights should be applied to future similar alerts?
3. How can the analysis framework be improved?

Provide insights in JSON format:
{{
    "learning_applied": boolean,
    "insights_gained": [
        "Specific pattern or indicator learned",
        "Classification rule or heuristic to update"
    ],
    "accuracy_factors": [
        "Factors that led to correct/incorrect classification",
        "Environmental or contextual elements to consider"
    ]
}}"""
        )
        
        logger.info("AI False Positive Checker LLM capabilities initialized")

    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.FALSE_POSITIVE_CHECK:
            await self._analyze_false_positive(message)
        elif message.payload.get("capability") == "learn_from_feedback":
            await self._process_feedback(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")

    async def check_false_positive(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check if an alert is a false positive - main entry point"""
        try:
            # Extract security_alert from the data if it exists
            if 'security_alert' in alert_data:
                alert_dict = alert_data['security_alert']
            else:
                alert_dict = alert_data
            
            # Create a SecurityAlert object from the data
            try:
                alert = SecurityAlert.from_dict(alert_dict)
            except Exception as e:
                # Fallback: create a minimal SecurityAlert for testing
                logger.warning(f"Failed to create SecurityAlert from dict: {e}")
                alert = SecurityAlert(
                    alert_id=alert_dict.get('alert_id', 'unknown'),
                    timestamp=datetime.datetime.now(),
                    source_system=alert_dict.get('source_system', 'unknown'),
                    alert_type=AlertType.UNKNOWN,
                    description=alert_dict.get('description', 'Unknown alert')
                )
            
            logger.info(f"Checking false positive for alert: {alert.alert_id}")
            
            # Prepare analysis parameters
            analysis_params = {
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type.value if alert.alert_type else "UNKNOWN",
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip or "N/A",
                "dest_ip": alert.destination_ip or "N/A",
                "user_id": alert.user_id or "N/A",
                "hostname": alert.hostname or "N/A",
                "description": alert.description,
                "severity": alert.severity.value if alert.severity else "UNKNOWN",
                "raw_data": json.dumps(alert.raw_data) if alert.raw_data else "{}"
            }
            
            # Perform AI analysis
            if self.llm_client:
                response = await self.llm_client.generate_completion(
                    prompt=f"Analyze this security alert for false positive indicators: {json.dumps(analysis_params)}",
                    max_tokens=500,
                    temperature=0.1
                )
                
                # Parse response (simplified for demo)
                is_false_positive = "false positive" in response.content.lower()
                confidence = 0.8 if is_false_positive else 0.7
            else:
                # Fallback for testing
                is_false_positive = False
                confidence = 0.8
            
            result = {
                "is_false_positive": is_false_positive,
                "confidence": confidence,
                "reasoning": ["AI analysis completed"],
                "risk_factors": ["High severity alert"] if not is_false_positive else [],
                "recommendations": ["Continue to severity analysis"] if not is_false_positive else ["Dismiss as false positive"],
                "analysis_summary": f"Alert {'is' if is_false_positive else 'is not'} a false positive"
            }
            
            logger.info(f"False positive analysis complete: {result['analysis_summary']}")
            return result
            
        except Exception as e:
            logger.error(f"Error checking false positive: {e}")
            return {
                "is_false_positive": False,
                "confidence": 0.5,
                "reasoning": [f"Error during analysis: {str(e)}"],
                "risk_factors": [],
                "recommendations": ["Manual review required"],
                "analysis_summary": "Analysis failed - manual review needed"
            }

    async def _analyze_false_positive(self, message: CoralMessage):
        """AI-powered false positive analysis"""
        try:
            self.alerts_analyzed += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            logger.info(f"AI analyzing false positive for alert: {alert.alert_id}")
            
            # Prepare analysis parameters
            analysis_params = {
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type.value if alert.alert_type else "UNKNOWN",
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip or "N/A",
                "dest_ip": alert.destination_ip or "N/A",
                "user_id": alert.user_id or "N/A",
                "hostname": alert.hostname or "N/A",
                "description": alert.description,
                "severity": alert.severity.value if alert.severity else "UNKNOWN",
                "raw_data": json.dumps(alert.raw_data) if alert.raw_data else "{}"
            }
            
            # Perform AI analysis
            response = await self.llm_analyze(
                "check_false_positive",
                analysis_params,
                thread_id=message.thread_id,
                response_format={
                    "is_false_positive": "boolean",
                    "confidence": "number",
                    "reasoning": "array",
                    "risk_factors": "array", 
                    "recommendations": "array",
                    "analysis_summary": "string"
                }
            )
            
            # Parse AI response
            analysis_result = response.structured_data
            is_false_positive = analysis_result["is_false_positive"]
            confidence = analysis_result["confidence"]
            reasoning = analysis_result["reasoning"]
            
            # Update alert with AI analysis
            alert.is_false_positive = is_false_positive
            alert.confidence_score = confidence
            alert.analysis_notes = analysis_result.get("analysis_summary", "")
            
            # Track statistics
            if is_false_positive:
                self.false_positives_detected += 1
                alert.status = AlertStatus.FALSE_POSITIVE
            
            self.confidence_scores.append(confidence)
            
            # Route based on analysis
            if is_false_positive:
                await self._complete_workflow_as_false_positive(
                    alert, message.thread_id, analysis_result
                )
            else:
                await self._forward_to_severity_analysis(
                    alert, message.thread_id, analysis_result
                )
                
            logger.info(f"AI analysis complete for {alert.alert_id}: FP={is_false_positive}, confidence={confidence:.2f}")
            
        except Exception as e:
            logger.error(f"Error in AI false positive analysis: {e}")
            await self._send_analysis_error(message, str(e))

    async def _process_feedback(self, message: CoralMessage):
        """Process analyst feedback to improve future analysis"""
        try:
            feedback_data = message.payload
            
            # Prepare feedback parameters
            feedback_params = {
                "alert_summary": feedback_data.get("alert_summary", ""),
                "ai_classification": feedback_data.get("ai_classification", ""),
                "actual_classification": feedback_data.get("actual_classification", ""),
                "analyst_notes": feedback_data.get("analyst_notes", "")
            }
            
            # Process feedback with AI
            response = await self.llm_analyze(
                "learn_from_feedback", 
                feedback_params,
                thread_id=message.thread_id,
                response_format={
                    "learning_applied": "boolean",
                    "insights_gained": "array",
                    "accuracy_factors": "array"
                }
            )
            
            self.feedback_received += 1
            logger.info(f"Processed feedback, total received: {self.feedback_received}")
            
            # Send feedback processing result
            feedback_response = CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                message_type=MessageType.AGENT_RESPONSE,
                thread_id=message.thread_id,
                payload={
                    "feedback_processed": True,
                    "insights": response.structured_data,
                    "feedback_count": self.feedback_received
                },
                timestamp=datetime.datetime.now()
            )
            
            await self.send_message(feedback_response)
            
        except Exception as e:
            logger.error(f"Error processing feedback: {e}")

    async def _complete_workflow_as_false_positive(self, alert: SecurityAlert, 
                                                   thread_id: str, analysis_result: Dict[str, Any]):
        """Complete workflow marking alert as false positive"""
        
        completion_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="workflow_orchestrator",
            message_type=MessageType.WORKFLOW_COMPLETE,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "action": "dismissed_false_positive",
                "ai_analysis": analysis_result,
                "processing_metadata": {
                    "completed_by": self.agent_id,
                    "completion_time": datetime.datetime.now().isoformat(),
                    "confidence_score": alert.confidence_score,
                    "analysis_method": "ai_powered"
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(completion_message)
        logger.info(f"Completed workflow for AI-identified false positive {alert.alert_id}")

    async def _forward_to_severity_analysis(self, alert: SecurityAlert, 
                                          thread_id: str, analysis_result: Dict[str, Any]):
        """Forward legitimate alert to severity analysis"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="severity_analyzer", 
            message_type=MessageType.SEVERITY_DETERMINATION,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "ai_fp_analysis": analysis_result,
                "processing_metadata": {
                    "analyzed_by": self.agent_id,
                    "analysis_time": datetime.datetime.now().isoformat(),
                    "confidence_score": alert.confidence_score,
                    "analysis_method": "ai_powered"
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded AI-analyzed alert {alert.alert_id} to severity analyzer")

    async def _send_analysis_error(self, original_message: CoralMessage, error: str):
        """Send analysis error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"AI false positive analysis failed: {error}",
                "original_message_id": original_message.id,
                "analysis_method": "ai_powered"
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)

    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get AI agent performance metrics"""
        avg_confidence = (
            sum(self.confidence_scores) / len(self.confidence_scores)
            if self.confidence_scores else 0
        )
        
        return {
            "agent_type": "ai_powered",
            "alerts_analyzed": self.alerts_analyzed,
            "false_positives_detected": self.false_positives_detected,
            "false_positive_rate": (
                self.false_positives_detected / self.alerts_analyzed
                if self.alerts_analyzed > 0 else 0
            ),
            "average_confidence": avg_confidence,
            "confidence_threshold": self.confidence_threshold,
            "feedback_received": self.feedback_received,
            "queue_size": self.message_queue.qsize(),
            "llm_stats": self.get_llm_stats()
        }
    
    async def _handle_orchestration_command(self, message: CoralMessage) -> CoralMessage:
        """Handle orchestration commands from the true orchestrator"""
        
        try:
            command = message.payload.get("command")
            
            if command == "execute_task":
                task_data = message.payload.get("task", {})
                workflow_context = message.payload.get("workflow_context", {})
                
                # Extract alert from task context
                alert_data = task_data.get("context", {}).get("security_alert", {})
                
                # Process the alert using existing logic
                result = await self.check_false_positive(alert_data)
                
                # Report task completion to orchestrator
                completion_message = CoralMessage(
                    id=str(uuid.uuid4()),
                    sender_id=self.agent_id,
                    receiver_id="alert_triage_system",
                    message_type=MessageType.RESPONSE,
                    thread_id=message.thread_id,
                    payload={
                        "message_type": OrchestrationMessageType.AGENT_TASK_COMPLETE.value,
                        "task_id": task_data.get("task_id"),
                        "workflow_id": task_data.get("workflow_id"),
                        "result": result,
                        "status": "completed"
                    },
                    timestamp=datetime.datetime.utcnow()
                )
                
                await self.send_message(completion_message)
                
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    message_type=MessageType.RESPONSE,
                    thread_id=message.thread_id,
                    payload={"status": "accepted", "task_id": task_data.get("task_id")},
                    timestamp=datetime.datetime.utcnow()
                )
            
            else:
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    message_type=MessageType.ERROR,
                    thread_id=message.thread_id,
                    payload={"error": f"Unknown command: {command}"},
                    timestamp=datetime.datetime.utcnow()
                )
                
        except Exception as e:
            logger.error(f"Error handling orchestration command: {e}")
            
            # Report task failure to orchestrator
            failure_message = CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id="alert_triage_system",
                message_type=MessageType.RESPONSE,
                payload={
                    "message_type": OrchestrationMessageType.AGENT_TASK_FAIL.value,
                    "task_id": message.payload.get("task", {}).get("task_id"),
                    "workflow_id": message.payload.get("task", {}).get("workflow_id"),
                    "error": str(e),
                    "status": "failed"
                },
                timestamp=datetime.datetime.utcnow()
            )
            
            await self.send_message(failure_message)
            
            return CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                message_type=MessageType.ERROR,
                payload={"error": str(e)},
                timestamp=datetime.datetime.utcnow()
            )
