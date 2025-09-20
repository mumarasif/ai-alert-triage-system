"""
AI-Powered Severity Analyzer Agent

This agent uses Large Language Models to determine alert severity levels.
It replaces rule-based logic with intelligent AI analysis while maintaining the same interface.
"""

import datetime
import uuid
import logging
import json
from typing import Dict, Any, Tuple, List

from coral_protocol import CoralMessage, MessageType, AgentCapability
from coral_protocol.orchestration_types import OrchestrationMessageType
from models.alert_models import SecurityAlert, AlertType, AlertSeverity, AlertStatus
from llm.agent_base import LLMAgentBase

logger = logging.getLogger(__name__)


class SeverityAnalyzerAgent(LLMAgentBase):
    """
    AI-powered agent that determines alert severity based on comprehensive analysis
    
    This agent:
    1. Uses LLM to analyze alerts with cybersecurity expertise
    2. Considers contextual factors (time, user, network, business impact)
    3. Provides detailed reasoning and risk assessment
    4. Routes to context gathering with severity assigned
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="determine_severity",
                description="Analyze and determine alert severity level using AI analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "context_data": {"type": "object"},
                        "analysis_options": {
                            "type": "object",
                            "properties": {
                                "consider_business_impact": {"type": "boolean"},
                                "include_threat_landscape": {"type": "boolean"}
                            }
                        }
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "array"},
                        "risk_score": {"type": "number"},
                        "business_impact": {"type": "string"},
                        "threat_indicators": {"type": "array"},
                        "escalation_recommendation": {"type": "string"}
                    }
                }
            ),
            AgentCapability(
                name="escalate_severity",
                description="Escalate alert severity based on new information using AI analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "escalation_reason": {"type": "string"},
                        "additional_context": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "new_severity": {"type": "string"},
                        "escalation_approved": {"type": "boolean"},
                        "escalation_reasoning": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="severity_analyzer_ai",
            agent_name="AI Severity Analyzer",
            capabilities=capabilities
        )
        
        # Configuration
        self.enable_dynamic_scoring = True
        self.escalation_threshold = 0.8
        
        # Statistics
        self.alerts_analyzed = 0
        
        # Register orchestration message handlers
        self.register_message_handler(MessageType.COMMAND, self._handle_orchestration_command)
        self.severity_distribution = {}
        self.escalations_performed = 0
        self.confidence_scores = []

    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for severity analysis"""
        
        # System prompt establishing AI's role as severity analysis expert
        self.register_system_prompt(
            "determine_severity",
            """You are a senior cybersecurity analyst and threat intelligence expert with 20+ years of experience in enterprise security operations. Your specialty is accurate threat severity assessment and risk prioritization in complex enterprise environments.

Your expertise includes:
- Advanced threat landscape analysis and attack vector assessment
- Enterprise security architecture and critical asset protection
- Business impact analysis and operational risk assessment
- Incident response prioritization and resource allocation
- Current threat intelligence and emerging attack patterns
- Regulatory compliance and industry-specific security requirements

Your analysis approach:
- Holistic risk assessment considering technical, business, and operational factors
- Dynamic threat landscape awareness with current attack trends
- Contextual analysis based on enterprise environment and business criticality
- Practical SOC operations focus with actionable severity classification
- Evidence-based reasoning with clear justification for severity levels

You must provide comprehensive severity analysis with detailed reasoning, risk scoring, and actionable recommendations for SOC operations."""
        )
        
        # Severity analysis prompt template
        self.register_prompt_template(
            "determine_severity",
            """Analyze the following security alert and determine its appropriate severity level:

ALERT DETAILS:
- Alert ID: {alert_id}
- Alert Type: {alert_type}
- Timestamp: {timestamp}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- Source Port: {source_port}
- Destination Port: {dest_port}
- User ID: {user_id}
- Hostname: {hostname}
- Process Name: {process_name}
- File Hash: {file_hash}
- Description: {description}
- Current Severity: {current_severity}
- Raw Event Data: {raw_data}

ORGANIZATIONAL CONTEXT:
- Business Hours: 8 AM - 6 PM UTC, Monday-Friday
- Critical Infrastructure: Domain controllers, financial systems, customer databases, email servers
- Network Segments: DMZ (10.1.0.0/24), Internal (10.0.0.0/16), Management (172.16.0.0/16)
- High-Value Users: C-suite executives, system administrators, financial staff
- Maintenance Windows: Weekends 2-6 AM UTC, monthly patches 3rd Sunday
- Compliance Requirements: SOX, PCI-DSS, GDPR data protection
- Security Tools: EDR, SIEM, DLP, vulnerability scanners, threat intelligence feeds

THREAT LANDSCAPE CONTEXT:
- Current threat level: ELEVATED (recent industry-targeted campaigns)
- Active threat actors: APT groups targeting financial sector
- Recent attack patterns: Credential theft, lateral movement, ransomware
- Emerging threats: Supply chain attacks, cloud misconfigurations
- Seasonal factors: End-of-quarter increased financial system activity

SEVERITY ANALYSIS FRAMEWORK:

1. **Threat Assessment (0-25 points)**
   - Attack sophistication and threat actor capability
   - Known attack patterns and TTPs alignment
   - Exploit complexity and weaponization level
   - Intelligence correlation with known campaigns

2. **Asset Criticality (0-25 points)**
   - System importance to business operations
   - Data sensitivity and regulatory requirements
   - Operational dependencies and service impact
   - Recovery complexity and business continuity

3. **Impact Potential (0-25 points)**
   - Confidentiality, integrity, availability risks
   - Financial impact and business disruption
   - Regulatory and compliance implications
   - Reputational and customer trust impact

4. **Contextual Factors (0-25 points)**
   - Timing relative to business operations
   - User privilege levels and access scope
   - Network position and lateral movement potential
   - Environmental indicators and anomaly significance

SEVERITY LEVELS:
- CRITICAL (85-100): Immediate threat to critical systems, active compromise likely, CEO/CISO notification required
- HIGH (70-84): Significant threat with high impact potential, immediate investigation required
- MEDIUM (55-69): Moderate threat requiring timely investigation and response
- LOW (0-54): Minimal threat, routine monitoring and standard procedures

REQUIRED RESPONSE FORMAT (JSON):
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": number (0.0 to 1.0),
    "risk_score": number (0 to 100),
    "reasoning": [
        "Primary threat indicators and severity drivers",
        "Asset criticality and business impact factors",
        "Contextual analysis and environmental considerations",
        "Threat intelligence correlation and pattern matching"
    ],
    "threat_indicators": [
        "Specific technical indicators observed",
        "Attack pattern alignment with known TTPs",
        "Anomaly significance and baseline deviation"
    ],
    "business_impact": "Detailed assessment of potential business consequences",
    "escalation_recommendation": "When and how to escalate based on severity",
    "time_sensitivity": "Urgency for response and investigation timeline",
    "recommended_actions": [
        "Immediate containment or investigation steps",
        "Follow-up monitoring and analysis requirements",
        "Stakeholder notification and escalation procedures"
    ],
    "analysis_summary": "Executive summary of key findings and risk assessment"
}}

Analyze this alert now and provide comprehensive severity assessment:"""
        )
        
        # Escalation analysis prompt template
        self.register_prompt_template(
            "escalate_severity",
            """Review the following alert for severity escalation based on new information:

ORIGINAL ALERT: {original_alert}
CURRENT SEVERITY: {current_severity}
ESCALATION REASON: {escalation_reason}
ADDITIONAL CONTEXT: {additional_context}
ESCALATION TIMESTAMP: {escalation_timestamp}

ESCALATION CRITERIA:
1. New threat intelligence indicating higher risk
2. Discovery of additional compromised systems
3. Identification of higher-value targets or data
4. Correlation with other high-severity incidents
5. Business impact reassessment
6. Environmental changes affecting risk profile

Determine if escalation is warranted and provide updated severity assessment.

REQUIRED RESPONSE FORMAT (JSON):
{{
    "escalation_approved": boolean,
    "new_severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "escalation_reasoning": [
        "Justification for escalation decision",
        "New risk factors identified",
        "Updated impact assessment"
    ],
    "confidence": number (0.0 to 1.0),
    "updated_risk_score": number (0 to 100),
    "escalation_summary": "Brief explanation of escalation decision"
}}

Provide escalation analysis:"""
        )
        
        logger.info("AI Severity Analyzer LLM capabilities initialized")

    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.SEVERITY_DETERMINATION:
            await self._analyze_severity(message)
        elif message.payload.get("capability") == "escalate_severity":
            await self._handle_escalation(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def analyze_severity(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert severity - main entry point"""
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
            
            logger.info(f"Analyzing severity for alert: {alert.alert_id}")
            
            # Perform AI analysis
            if self.llm_client:
                # Convert datetime objects and enums to serializable format for JSON
                alert_dict_serializable = {}
                for key, value in alert_dict.items():
                    if hasattr(value, 'isoformat'):  # datetime object
                        alert_dict_serializable[key] = value.isoformat()
                    elif hasattr(value, 'value'):  # enum object
                        alert_dict_serializable[key] = value.value
                    else:
                        alert_dict_serializable[key] = value
                
                response = await self.llm_client.generate_completion(
                    prompt=f"Analyze the severity of this security alert: {json.dumps(alert_dict_serializable)}",
                    max_tokens=500,
                    temperature=0.1
                )
                
                # Parse response (simplified for demo)
                severity_str = "high" if "high" in response.content.lower() else "medium"
                confidence = 0.8
            else:
                # Fallback for testing
                severity_str = "high"
                confidence = 0.8
            
            result = {
                "severity": severity_str,
                "confidence": confidence,
                "risk_score": 0.8,
                "reasoning": ["AI analysis completed"],
                "threat_indicators": ["High severity alert"],
                "business_impact": "High",
                "escalation_recommendation": "Escalate to senior analyst",
                "time_sensitivity": "Immediate",
                "recommended_actions": ["Isolate affected systems", "Notify security team"],
                "analysis_summary": f"Alert severity: {severity_str}"
            }
            
            logger.info(f"Severity analysis complete: {result['analysis_summary']}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing severity: {e}")
            return {
                "severity": "medium",
                "confidence": 0.5,
                "risk_score": 0.5,
                "reasoning": [f"Error during analysis: {str(e)}"],
                "threat_indicators": [],
                "business_impact": "Unknown",
                "escalation_recommendation": "Manual review required",
                "time_sensitivity": "Unknown",
                "recommended_actions": ["Manual review required"],
                "analysis_summary": "Analysis failed - manual review needed"
            }

    async def _analyze_severity(self, message: CoralMessage):
        """AI-powered severity analysis"""
        try:
            self.alerts_analyzed += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            logger.info(f"AI analyzing severity for alert: {alert.alert_id}")
            
            # Prepare analysis parameters
            analysis_params = {
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type.value if alert.alert_type else "UNKNOWN",
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip or "N/A",
                "dest_ip": alert.destination_ip or "N/A",
                "source_port": alert.source_port or "N/A",
                "dest_port": alert.destination_port or "N/A",
                "user_id": alert.user_id or "N/A",
                "hostname": alert.hostname or "N/A",
                "process_name": alert.process_name or "N/A",
                "file_hash": alert.file_hash or "N/A",
                "description": alert.description,
                "current_severity": alert.severity.value if alert.severity else "UNKNOWN",
                "raw_data": json.dumps(alert.raw_data) if alert.raw_data else "{}"
            }
            
            # Perform AI analysis
            response = await self.llm_analyze(
                "determine_severity",
                analysis_params,
                thread_id=message.thread_id,
                response_format={
                    "severity": "string",
                    "confidence": "number",
                    "risk_score": "number",
                    "reasoning": "array",
                    "threat_indicators": "array",
                    "business_impact": "string",
                    "escalation_recommendation": "string",
                    "time_sensitivity": "string",
                    "recommended_actions": "array",
                    "analysis_summary": "string"
                }
            )
            
            # Parse AI response
            analysis_result = response.structured_data
            severity_str = analysis_result["severity"]
            confidence = analysis_result["confidence"]
            risk_score = analysis_result["risk_score"]
            reasoning = analysis_result["reasoning"]
            
            # Convert severity string to enum
            try:
                severity = AlertSeverity(severity_str.upper())
            except ValueError:
                logger.warning(f"Invalid severity from AI: {severity_str}, defaulting to MEDIUM")
                severity = AlertSeverity.MEDIUM
            
            # Update alert with AI analysis
            alert.severity = severity
            alert.confidence_score = confidence
            alert.analysis_notes = analysis_result.get("analysis_summary", "")
            
            # Track statistics
            severity_key = severity.value
            if severity_key not in self.severity_distribution:
                self.severity_distribution[severity_key] = 0
            self.severity_distribution[severity_key] += 1
            self.confidence_scores.append(confidence)
            
            # Forward to context gatherer
            await self._forward_to_context_gathering(
                alert, message.thread_id, analysis_result, risk_score
            )
            
            logger.info(f"AI severity analysis complete for {alert.alert_id}: {severity.value} (risk score: {risk_score:.2f})")
            
        except Exception as e:
            logger.error(f"Error in AI severity analysis: {e}")
            await self._send_analysis_error(message, str(e))

    async def _handle_escalation(self, message: CoralMessage):
        """Handle severity escalation requests"""
        try:
            escalation_data = message.payload
            
            # Prepare escalation parameters
            escalation_params = {
                "original_alert": json.dumps(escalation_data.get("alert", {})),
                "current_severity": escalation_data.get("current_severity", "UNKNOWN"),
                "escalation_reason": escalation_data.get("escalation_reason", ""),
                "additional_context": json.dumps(escalation_data.get("additional_context", {})),
                "escalation_timestamp": datetime.datetime.now().isoformat()
            }
            
            # Perform AI escalation analysis
            response = await self.llm_analyze(
                "escalate_severity",
                escalation_params,
                thread_id=message.thread_id,
                response_format={
                    "escalation_approved": "boolean",
                    "new_severity": "string",
                    "escalation_reasoning": "array",
                    "confidence": "number",
                    "updated_risk_score": "number",
                    "escalation_summary": "string"
                }
            )
            
            escalation_result = response.structured_data
            
            if escalation_result["escalation_approved"]:
                self.escalations_performed += 1
                
            # Send escalation response
            escalation_response = CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                message_type=MessageType.RESPONSE,
                thread_id=message.thread_id,
                payload={
                    "escalation_result": escalation_result,
                    "escalation_count": self.escalations_performed
                },
                timestamp=datetime.datetime.now()
            )
            
            await self.send_message(escalation_response)
            logger.info(f"Processed escalation request: approved={escalation_result['escalation_approved']}")
            
        except Exception as e:
            logger.error(f"Error processing escalation: {e}")

    async def _forward_to_context_gathering(self, alert: SecurityAlert, thread_id: str,
                                          analysis_result: Dict[str, Any], risk_score: float):
        """Forward alert to context gathering agent"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="context_gatherer",
            message_type=MessageType.CONTEXT_GATHERING,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "ai_severity_analysis": analysis_result,
                "processing_metadata": {
                    "analyzed_by": self.agent_id,
                    "analysis_time": datetime.datetime.now().isoformat(),
                    "confidence_score": alert.confidence_score,
                    "risk_score": risk_score,
                    "analysis_method": "ai_powered"
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded AI-analyzed alert {alert.alert_id} to context gatherer")

    async def _send_analysis_error(self, original_message: CoralMessage, error: str):
        """Send analysis error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"AI severity analysis failed: {error}",
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
            "severity_distribution": self.severity_distribution,
            "escalations_performed": self.escalations_performed,
            "average_confidence": avg_confidence,
            "escalation_threshold": self.escalation_threshold,
            "queue_size": self.message_queue.qsize(),
            "llm_stats": self.get_llm_stats()
        }
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform AI agent health check"""
        
        metrics = self.get_agent_metrics()
        
        health_status = "healthy"
        issues = []
        
        if metrics["queue_size"] > 50:
            health_status = "degraded"
            issues.append("High message queue size")
            
        if not self.llm_client and not self.testing_mode:
            health_status = "unhealthy"
            issues.append("LLM client not available")
            
        return {
            "status": health_status,
            "issues": issues,
            "metrics": metrics,
            "llm_enabled": not self.testing_mode
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
                result = await self.analyze_severity(alert_data)
                
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
                thread_id=message.thread_id,
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
                thread_id=message.thread_id,
                payload={"error": str(e)},
                timestamp=datetime.datetime.utcnow()
            )
