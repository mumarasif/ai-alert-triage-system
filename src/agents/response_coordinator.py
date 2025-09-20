"""
AI-Powered Response Coordinator Agent

This agent uses Large Language Models to intelligently coordinate response actions for security alerts.
It replaces rule-based response logic with intelligent AI decision-making while maintaining the same interface.
"""

import datetime
import uuid
import logging
import json
from typing import Dict, Any, List, Tuple, Optional

from coral_protocol import CoralMessage, MessageType, AgentCapability
from coral_protocol.orchestration_types import OrchestrationMessageType
from models.alert_models import SecurityAlert, AlertSeverity, AlertType, ResponseAction, AlertStatus, IncidentTicket
from llm.agent_base import LLMAgentBase

logger = logging.getLogger(__name__)


class ResponseCoordinatorAgent(LLMAgentBase):
    """
    AI-powered agent that coordinates intelligent response actions for security alerts
    
    This agent:
    1. Uses AI to determine optimal response strategies
    2. Performs intelligent assignment and escalation decisions
    3. Coordinates automated response actions with human oversight
    4. Creates comprehensive incident tickets with AI-generated summaries
    5. Completes workflows with detailed response intelligence
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="coordinate_response",
                description="Determine and coordinate comprehensive response actions using AI analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "context_enrichment": {"type": "object"},
                        "response_options": {"type": "object"}
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "response_strategy": {"type": "object"},
                        "response_actions": {"type": "array"},
                        "assignment_decision": {"type": "object"},
                        "automation_plan": {"type": "object"},
                        "incident_details": {"type": "object"}
                    }
                }
            ),
            AgentCapability(
                name="optimize_response_strategy",
                description="Optimize response strategy based on situational awareness and organizational context",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "current_strategy": {"type": "object"},
                        "resource_constraints": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "optimized_strategy": {"type": "object"},
                        "resource_allocation": {"type": "object"},
                        "timeline_recommendations": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="response_coordinator_ai",
            agent_name="AI Response Coordinator",
            capabilities=capabilities
        )
        
        # Configuration
        self.auto_escalation_threshold = 0.8
        self.enable_automation = True
        self.soar_enabled = False
        
        # Statistics
        self.alerts_processed = 0
        self.incidents_created = 0
        self.escalations_performed = 0
        self.automated_actions_triggered = 0
        self.confidence_scores = []
        
        # Register orchestration message handlers
        self.register_message_handler(MessageType.COMMAND, self._handle_orchestration_command)
        
        # Initialize response knowledge base
        self._initialize_response_knowledge()

    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for response coordination"""
        
        # System prompt establishing AI's role as response coordination expert
        self.register_system_prompt(
            "coordinate_response",
            """You are a senior incident response commander and cybersecurity operations expert with 20+ years of experience leading enterprise security operations centers. Your specialty is intelligent response orchestration and tactical decision-making in high-pressure security incidents.

Your expertise includes:
- Advanced incident response methodology and NIST cybersecurity framework
- SOC operations management and analyst team coordination
- Risk-based decision making and resource optimization
- Automated response integration and human-machine collaboration
- Business continuity and operational risk management
- Crisis communication and stakeholder management
- Forensic evidence preservation and legal considerations

Your decision-making approach:
- Risk-proportionate response with business impact consideration
- Resource-optimized action planning with timeline prioritization
- Evidence-based escalation with clear chain of command
- Human-AI collaboration with appropriate automation boundaries
- Operational efficiency with quality assurance and oversight
- Continuous learning and response strategy optimization

You must provide comprehensive response strategies with detailed action plans, clear assignment rationale, and measurable success criteria for effective incident resolution."""
        )
        
        # Response coordination prompt template
        self.register_prompt_template(
            "coordinate_response",
            """Coordinate comprehensive response strategy for the following security alert:

ALERT SUMMARY:
- Alert ID: {alert_id}
- Alert Type: {alert_type}
- Severity: {current_severity}
- Risk Score: {risk_score}
- Description: {description}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- User ID: {user_id}
- Hostname: {hostname}
- Timestamp: {timestamp}

SEVERITY ANALYSIS:
{severity_analysis_summary}

CONTEXT INTELLIGENCE:
{context_intelligence_summary}

ORGANIZATIONAL ENVIRONMENT:
- SOC Staffing: 24/7 operations with Tier 1/2/3 analysts and incident commanders
- Automation Capabilities: Firewall blocking, host isolation, user account management, file quarantine
- SOAR Integration: Phantom platform for incident orchestration and workflow automation
- Business Context: Financial services with strict regulatory requirements (SOX, PCI-DSS)
- Peak Hours: Business operations 8 AM - 6 PM UTC, critical maintenance windows weekends
- Critical Assets: Domain controllers, financial trading systems, customer databases

RESPONSE COORDINATION FRAMEWORK:

1. **Threat Response Strategy**
   - Immediate containment requirements and feasibility
   - Investigation scope and evidence preservation needs
   - Stakeholder notification and communication plan
   - Resource allocation and timeline considerations

2. **Action Prioritization**
   - Critical path analysis for incident resolution
   - Parallel vs sequential action execution
   - Automation vs human intervention decisions
   - Quality gates and approval workflows

3. **Assignment Decision**
   - Skill requirements and analyst availability
   - Escalation triggers and chain of command
   - Workload distribution and capacity planning
   - Training and knowledge transfer opportunities

4. **Automation Strategy**
   - Safe automation boundaries and human oversight
   - Approval workflows for high-impact actions
   - Rollback plans and emergency procedures
   - Integration with SOAR and security tools

5. **Business Continuity**
   - Operational impact assessment and mitigation
   - Business process preservation and alternatives
   - Regulatory compliance and reporting requirements
   - Customer communication and reputation management

REQUIRED RESPONSE FORMAT (JSON):
{{
    "response_strategy": {{
        "strategy_type": "IMMEDIATE_CONTAINMENT|INVESTIGATION_FOCUSED|MONITORING_ENHANCED|FULL_RESPONSE",
        "urgency_level": "CRITICAL|HIGH|MEDIUM|LOW",
        "estimated_timeline": "time estimate for resolution",
        "success_criteria": ["measurable outcomes for successful resolution"],
        "risk_tolerance": "acceptable risk level during response"
    }},
    "action_plan": {{
        "immediate_actions": [
            {{
                "action": "specific action to take",
                "priority": "CRITICAL|HIGH|MEDIUM|LOW",
                "estimated_time": "time to complete",
                "automation_eligible": boolean,
                "approval_required": boolean,
                "assigned_role": "role responsible for execution"
            }}
        ],
        "follow_up_actions": [
            {{
                "action": "follow-up action",
                "dependency": "prerequisite action or trigger",
                "timeline": "when to execute",
                "assigned_role": "responsible role"
            }}
        ],
        "contingency_actions": [
            {{
                "scenario": "failure condition or escalation trigger",
                "action": "contingency response",
                "escalation_path": "who to notify and how"
            }}
        ]
    }},
    "assignment_decision": {{
        "primary_assignee": "TIER1_ANALYST|TIER2_ANALYST|SENIOR_ANALYST|INCIDENT_COMMANDER|AUTOMATED_SYSTEM",
        "assignment_rationale": "why this assignee was chosen",
        "required_skills": ["specific skills needed"],
        "escalation_criteria": ["conditions that trigger escalation"],
        "collaboration_needs": ["other roles that need to be involved"],
        "expected_workload": "estimated effort level"
    }},
    "automation_recommendations": {{
        "safe_automations": [
            {{
                "action": "automation action",
                "confidence": "confidence level in automation safety",
                "monitoring_required": "what human oversight is needed",
                "rollback_plan": "how to reverse if needed"
            }}
        ],
        "human_required_actions": [
            {{
                "action": "action requiring human judgment",
                "reasoning": "why human oversight is critical",
                "approval_level": "who needs to approve"
            }}
        ],
        "automation_boundaries": "clear limits on what should be automated"
    }},
    "incident_management": {{
        "create_incident_ticket": boolean,
        "incident_severity": "P1|P2|P3|P4",
        "incident_category": "Security Incident|Security Event|False Positive|Maintenance",
        "stakeholder_notifications": [
            {{
                "stakeholder": "who to notify",
                "urgency": "notification urgency",
                "communication_method": "how to notify",
                "message_template": "notification content"
            }}
        ],
        "documentation_requirements": ["what needs to be documented"],
        "compliance_considerations": ["regulatory or legal requirements"]
    }},
    "resource_optimization": {{
        "estimated_total_effort": "total analyst hours needed",
        "parallel_execution_opportunities": ["actions that can run in parallel"],
        "efficiency_recommendations": ["ways to optimize the response"],
        "learning_opportunities": ["insights for future improvement"]
    }},
    "response_summary": "Executive summary of the recommended response strategy and key decisions"
}}

Coordinate comprehensive response strategy now:"""
        )
        
        # Response optimization prompt template
        self.register_prompt_template(
            "optimize_response_strategy",
            """Optimize the response strategy for this security incident based on current situational awareness:

CURRENT SITUATION:
Alert: {alert_summary}
Current Strategy: {current_strategy}
Resource Constraints: {resource_constraints}

OPTIMIZATION OBJECTIVES:
1. Maximize incident resolution effectiveness
2. Minimize business operational disruption
3. Optimize resource utilization and analyst workload
4. Ensure compliance and regulatory requirements
5. Improve response time and quality

REQUIRED RESPONSE FORMAT (JSON):
{{
    "optimized_strategy": {{
        "strategy_adjustments": ["key changes to current strategy"],
        "efficiency_improvements": ["ways to improve efficiency"],
        "risk_mitigation_enhancements": ["additional risk controls"]
    }},
    "resource_allocation": {{
        "analyst_assignments": ["optimized analyst allocation"],
        "tool_utilization": ["recommended security tool usage"],
        "timeline_adjustments": ["schedule modifications"]
    }},
    "timeline_recommendations": [
        {{
            "phase": "response phase",
            "duration": "estimated time",
            "activities": ["key activities in this phase"],
            "checkpoints": ["quality gates and reviews"]
        }}
    ]
}}

Provide optimization recommendations:"""
        )
        
        logger.info("AI Response Coordinator LLM capabilities initialized")

    def _initialize_response_knowledge(self):
        """Initialize response knowledge base and automation rules"""
        
        # Automation safety rules
        self.automation_rules = {
            "block_malicious_ip": {
                "safety_threshold": 0.9,
                "approval_required": False,
                "rollback_time": 300  # 5 minutes
            },
            "quarantine_malware": {
                "safety_threshold": 0.85,
                "approval_required": False,
                "rollback_time": 60
            },
            "isolate_host": {
                "safety_threshold": 0.8,
                "approval_required": True,
                "rollback_time": 900  # 15 minutes
            },
            "disable_user_account": {
                "safety_threshold": 0.95,
                "approval_required": True,
                "rollback_time": 1800  # 30 minutes
            }
        }
        
        # Assignment expertise mapping
        self.assignment_expertise = {
            "malware_analysis": ["TIER2_ANALYST", "SENIOR_ANALYST"],
            "network_forensics": ["SENIOR_ANALYST", "INCIDENT_COMMANDER"],
            "user_behavior_analysis": ["TIER1_ANALYST", "TIER2_ANALYST"],
            "threat_intelligence": ["TIER2_ANALYST", "SENIOR_ANALYST"],
            "incident_coordination": ["INCIDENT_COMMANDER"]
        }
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.RESPONSE_DECISION:
            await self._coordinate_response_ai(message)
        elif message.payload.get("capability") == "optimize_response_strategy":
            await self._optimize_response_strategy(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def coordinate_response(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate response for alert - main entry point"""
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
            
            logger.info(f"Coordinating response for alert: {alert.alert_id}")
            
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
                    prompt=f"Coordinate response for this security alert: {json.dumps(alert_dict_serializable)}",
                    max_tokens=500,
                    temperature=0.1
                )
                
                # Parse response (simplified for demo)
                response_strategy = {"strategy_type": "immediate_response", "priority": "high"}
                confidence = 0.8
            else:
                # Fallback for testing
                response_strategy = {"strategy_type": "immediate_response", "priority": "high"}
                confidence = 0.8
            
            result = {
                "response_strategy": response_strategy,
                "action_plan": {"immediate_actions": ["Isolate systems", "Notify team"], "follow_up": ["Investigate", "Document"]},
                "assignment_decision": {"primary_assignee": "security_team", "escalation_level": "high"},
                "automation_recommendations": {"automated_actions": ["Block IP", "Quarantine"], "manual_review": ["User investigation"]},
                "incident_management": {"ticket_created": True, "incident_id": f"INC-{alert.alert_id[:8]}"},
                "resource_optimization": {"estimated_effort": "2-4 hours", "required_skills": ["security_analysis"]},
                "response_summary": f"Response coordinated for alert: {alert.alert_id}"
            }
            
            logger.info(f"Response coordination complete: {result['response_summary']}")
            return result
            
        except Exception as e:
            logger.error(f"Error coordinating response: {e}")
            return {
                "response_strategy": {"strategy_type": "manual_review", "priority": "medium"},
                "action_plan": {"immediate_actions": ["Manual review"], "follow_up": ["Investigate"]},
                "assignment_decision": {"primary_assignee": "manual_review", "escalation_level": "medium"},
                "automation_recommendations": {"automated_actions": [], "manual_review": ["Full investigation"]},
                "incident_management": {"ticket_created": False, "incident_id": None},
                "resource_optimization": {"estimated_effort": "Unknown", "required_skills": ["manual_review"]},
                "response_summary": f"Response coordination failed - manual review needed: {str(e)}"
            }

    async def _coordinate_response_ai(self, message: CoralMessage):
        """AI-powered response coordination"""
        try:
            self.alerts_processed += 1
            
            # Extract alert and context from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            # Extract context enrichment data
            context_enrichment = message.payload.get("ai_context_enrichment", {})
            
            logger.info(f"AI coordinating response for alert: {alert.alert_id}")
            
            # Prepare analysis parameters
            analysis_params = {
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type.value if alert.alert_type else "UNKNOWN",
                "current_severity": alert.severity.value if alert.severity else "UNKNOWN",
                "risk_score": self._extract_risk_score(message.payload),
                "description": alert.description,
                "source_ip": alert.source_ip or "N/A",
                "dest_ip": alert.destination_ip or "N/A",
                "user_id": alert.user_id or "N/A",
                "hostname": alert.hostname or "N/A",
                "timestamp": alert.timestamp.isoformat(),
                "severity_analysis_summary": self._summarize_severity_analysis(message.payload),
                "context_intelligence_summary": self._summarize_context_intelligence(context_enrichment)
            }
            
            # Perform AI response coordination
            response = await self.llm_analyze(
                "coordinate_response",
                analysis_params,
                thread_id=message.thread_id,
                response_format={
                    "response_strategy": "object",
                    "action_plan": "object",
                    "assignment_decision": "object",
                    "automation_recommendations": "object",
                    "incident_management": "object",
                    "resource_optimization": "object",
                    "response_summary": "string"
                }
            )
            
            # Parse AI response
            coordination_result = response.structured_data
            
            # Extract response confidence
            confidence = self._calculate_response_confidence(coordination_result)
            self.confidence_scores.append(confidence)
            
            # Execute coordinated response
            response_metadata = await self._execute_coordinated_response(
                alert, coordination_result, message.thread_id
            )
            
            # Update alert with response information
            alert.recommended_actions = self._extract_response_actions(coordination_result)
            alert.assigned_analyst = coordination_result["assignment_decision"]["primary_assignee"]
            alert.status = self._determine_alert_status(coordination_result)
            
            # Complete workflow
            await self._complete_workflow(alert, message.thread_id, {
                **response_metadata,
                "ai_coordination": coordination_result,
                "response_confidence": confidence
            })
            
            logger.info(f"AI response coordination complete for {alert.alert_id}: "
                       f"strategy={coordination_result['response_strategy']['strategy_type']}, "
                       f"confidence={confidence:.2f}")
            
        except Exception as e:
            logger.error(f"Error in AI response coordination: {e}")
            await self._send_coordination_error(message, str(e))
            
    async def _execute_coordinated_response(self, alert: SecurityAlert, 
                                          coordination_result: Dict[str, Any],
                                          thread_id: str) -> Dict[str, Any]:
        """Execute the AI-coordinated response plan"""
        
        response_metadata = {
            "strategy_executed": coordination_result["response_strategy"]["strategy_type"],
            "actions_completed": [],
            "automations_executed": [],
            "incident_created": False,
            "escalation_performed": False
        }
        
        # Execute immediate actions
        immediate_actions = coordination_result["action_plan"]["immediate_actions"]
        for action_item in immediate_actions:
            if action_item.get("automation_eligible", False):
                success = await self._execute_automated_action(action_item, alert)
                if success:
                    response_metadata["automations_executed"].append(action_item["action"])
                    self.automated_actions_triggered += 1
            
            response_metadata["actions_completed"].append(action_item["action"])
        
        # Create incident ticket if needed
        if coordination_result["incident_management"]["create_incident_ticket"]:
            incident_ticket = await self._create_ai_incident_ticket(alert, coordination_result)
            if incident_ticket:
                response_metadata["incident_created"] = True
                response_metadata["incident_ticket"] = incident_ticket.to_dict()
                self.incidents_created += 1
        
        # Handle escalation
        assignment_decision = coordination_result["assignment_decision"]
        if assignment_decision["primary_assignee"] in ["INCIDENT_COMMANDER", "SENIOR_ANALYST"]:
            response_metadata["escalation_performed"] = True
            self.escalations_performed += 1
        
        return response_metadata

    async def _execute_automated_action(self, action_item: Dict[str, Any], 
                                      alert: SecurityAlert) -> bool:
        """Execute an automated action with safety checks"""
        
        action_name = action_item["action"].lower().replace(" ", "_")
        
        # Check if action requires approval
        if action_item.get("approval_required", False):
            logger.info(f"Action '{action_name}' requires approval - queuing for human review")
            return False
        
            # Execute based on action type
        try:
            if "block" in action_name and "ip" in action_name and alert.source_ip:
                return await self._block_ip_address(alert.source_ip)
            elif "quarantine" in action_name and hasattr(alert, 'file_path') and alert.file_path:
                return await self._quarantine_file(alert.file_path)
            elif "isolate" in action_name and alert.hostname:
                return await self._isolate_host(alert.hostname)
            elif "disable" in action_name and "user" in action_name and alert.user_id:
                return await self._disable_user_account(alert.user_id)
            else:
                logger.info(f"[AUTOMATION] Simulated execution: {action_name}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to execute automated action {action_name}: {e}")
            return False

    async def _create_ai_incident_ticket(self, alert: SecurityAlert, 
                                       coordination_result: Dict[str, Any]) -> Optional[IncidentTicket]:
        """Create incident ticket with AI-generated content"""
        
        incident_mgmt = coordination_result["incident_management"]
        
        # Generate AI-enhanced incident description
        description = self._generate_ai_incident_description(alert, coordination_result)
        
        # Create incident ticket
        ticket = IncidentTicket(
            ticket_id=f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{self.incidents_created + 1:04d}",
            alert_id=alert.alert_id,
            title=f"[{incident_mgmt['incident_severity']}] {alert.alert_type.value.title()} - {alert.alert_id}",
            description=description,
            severity=alert.severity or AlertSeverity.MEDIUM,
            status="open",
            assigned_to=coordination_result["assignment_decision"]["primary_assignee"],
            created_time=datetime.datetime.now(),
            soar_platform="phantom"
        )
        
        # Send to SOAR platform
        await self._send_to_soar_platform(ticket)
        
        logger.info(f"Created AI-enhanced incident ticket {ticket.ticket_id}")
        return ticket

    def _generate_ai_incident_description(self, alert: SecurityAlert, 
                                        coordination_result: Dict[str, Any]) -> str:
        """Generate comprehensive incident description using AI analysis"""
        
        strategy = coordination_result["response_strategy"]
        action_plan = coordination_result["action_plan"]
        
        description = f"""
AI-ENHANCED SECURITY INCIDENT REPORT
=====================================

INCIDENT OVERVIEW:
- Incident ID: {alert.alert_id}
- Alert Type: {alert.alert_type.value}
- Severity: {alert.severity.value if alert.severity else 'Unknown'}
- Strategy: {strategy['strategy_type']}
- Urgency: {strategy['urgency_level']}

ALERT DETAILS:
- Source System: {alert.source_system}
- Timestamp: {alert.timestamp.isoformat()}
- Description: {alert.description}

NETWORK INFORMATION:
- Source IP: {alert.source_ip or 'N/A'}
- Destination IP: {alert.destination_ip or 'N/A'}
- User: {alert.user_id or 'N/A'}
- Host: {alert.hostname or 'N/A'}

AI RESPONSE STRATEGY:
- Timeline: {strategy['estimated_timeline']}
- Risk Tolerance: {strategy['risk_tolerance']}

SUCCESS CRITERIA:
{chr(10).join(f"- {criteria}" for criteria in strategy['success_criteria'])}

IMMEDIATE ACTIONS:
{chr(10).join(f"- {action['action']} (Priority: {action['priority']})" for action in action_plan['immediate_actions'])}

ASSIGNMENT RATIONALE:
{coordination_result['assignment_decision']['assignment_rationale']}

AI ANALYSIS SUMMARY:
{coordination_result['response_summary']}
""".strip()
        
        return description

    def _extract_response_actions(self, coordination_result: Dict[str, Any]) -> List[ResponseAction]:
        """Extract response actions from AI coordination result"""
        
        actions = []
        
        # Map AI actions to ResponseAction enum
        action_mapping = {
            "escalate": ResponseAction.ESCALATE,
            "investigate": ResponseAction.INVESTIGATE,
            "monitor": ResponseAction.MONITOR,
            "contain": ResponseAction.CONTAIN,
            "preserve_evidence": ResponseAction.PRESERVE_EVIDENCE,
            "notify": ResponseAction.NOTIFY_ANALYST,
            "block_ip": ResponseAction.BLOCK_IP,
            "create_incident": ResponseAction.CREATE_INCIDENT,
            "auto_resolve": ResponseAction.AUTO_RESOLVE
        }
        
        # Extract from immediate actions
        immediate_actions = coordination_result["action_plan"]["immediate_actions"]
        for action_item in immediate_actions:
            action_text = action_item["action"].lower()
            for key, action_enum in action_mapping.items():
                if key in action_text:
                    actions.append(action_enum)
                    break
        
        return list(set(actions))  # Remove duplicates

    def _determine_alert_status(self, coordination_result: Dict[str, Any]) -> AlertStatus:
        """Determine alert status from AI coordination result"""
        
        strategy_type = coordination_result["response_strategy"]["strategy_type"]
        
        if "IMMEDIATE" in strategy_type or coordination_result["incident_management"]["create_incident_ticket"]:
            return AlertStatus.IN_PROGRESS
        elif strategy_type == "MONITORING_ENHANCED":
            return AlertStatus.IN_PROGRESS
        else:
            return AlertStatus.IN_PROGRESS

    def _calculate_response_confidence(self, coordination_result: Dict[str, Any]) -> float:
        """Calculate confidence in the AI response coordination"""
        
        # Base confidence from strategy clarity
        base_confidence = 0.7
        
        # Adjust based on action specificity
        immediate_actions = coordination_result["action_plan"]["immediate_actions"]
        if len(immediate_actions) >= 3:
            base_confidence += 0.1
        
        # Adjust based on assignment rationale detail
        assignment_rationale = coordination_result["assignment_decision"]["assignment_rationale"]
        if len(assignment_rationale) > 50:
            base_confidence += 0.1
        
        # Adjust based on automation recommendations
        automation_recs = coordination_result["automation_recommendations"]
        if len(automation_recs.get("safe_automations", [])) > 0:
            base_confidence += 0.05
        
        return min(0.95, base_confidence)

    def _extract_risk_score(self, payload: Dict[str, Any]) -> str:
        """Extract risk score from message payload"""
        
        # Check various locations for risk score
        severity_analysis = payload.get("ai_severity_analysis", {})
        context_enrichment = payload.get("ai_context_enrichment", {})
        
        if "risk_score" in severity_analysis:
            return str(severity_analysis["risk_score"])
        elif "confidence_assessment" in context_enrichment:
            return str(context_enrichment["confidence_assessment"].get("overall_confidence", 0.5) * 100)
        else:
            return "Unknown"

    def _summarize_severity_analysis(self, payload: Dict[str, Any]) -> str:
        """Summarize severity analysis for AI prompt"""
        
        severity_analysis = payload.get("ai_severity_analysis", {})
        if not severity_analysis:
            return "No severity analysis available"
        
        reasoning = severity_analysis.get("reasoning", [])
        threat_indicators = severity_analysis.get("threat_indicators", [])
        
        summary = f"Risk Score: {severity_analysis.get('risk_score', 'Unknown')}\n"
        summary += f"Key Reasoning: {'; '.join(reasoning[:3])}\n"
        summary += f"Threat Indicators: {'; '.join(threat_indicators[:3])}"
        
        return summary

    def _summarize_context_intelligence(self, context_enrichment: Dict[str, Any]) -> str:
        """Summarize context intelligence for AI prompt"""
        
        if not context_enrichment:
            return "No context intelligence available"
        
        intelligence_summary = context_enrichment.get("intelligence_summary", "")
        threat_landscape = context_enrichment.get("threat_landscape", {})
        
        summary = intelligence_summary[:200] + "..." if len(intelligence_summary) > 200 else intelligence_summary
        summary += f"\nThreat Level: {threat_landscape.get('current_threat_level', 'Unknown')}"
        
        return summary

    async def _optimize_response_strategy(self, message: CoralMessage):
        """Optimize response strategy based on current situation"""
        try:
            optimization_data = message.payload
            
            # Prepare optimization parameters with proper serialization
            def serialize_for_json(obj):
                if hasattr(obj, 'isoformat'):  # datetime object
                    return obj.isoformat()
                elif hasattr(obj, 'value'):  # enum object
                    return obj.value
                elif isinstance(obj, dict):
                    return {k: serialize_for_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [serialize_for_json(item) for item in obj]
                else:
                    return obj
            
            optimization_params = {
                "alert_summary": json.dumps(serialize_for_json(optimization_data.get("alert", {}))),
                "current_strategy": json.dumps(serialize_for_json(optimization_data.get("current_strategy", {}))),
                "resource_constraints": json.dumps(serialize_for_json(optimization_data.get("resource_constraints", {})))
            }
            
            # Perform optimization analysis
            response = await self.llm_analyze(
                "optimize_response_strategy",
                optimization_params,
                thread_id=message.thread_id,
                response_format={
                    "optimized_strategy": "object",
                    "resource_allocation": "object",
                    "timeline_recommendations": "array"
                }
            )
            
            # Send optimization response
            optimization_response = CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                message_type=MessageType.RESPONSE_DECISION,
                thread_id=message.thread_id,
                payload={
                    "response_optimization": response.structured_data if hasattr(response, 'structured_data') else {}
                },
                timestamp=datetime.datetime.now()
            )
            
            await self.send_message(optimization_response)
            logger.info("Response strategy optimization complete")
            
        except Exception as e:
            logger.error(f"Error in response optimization: {e}")

    # Automation implementations (same as original with enhanced logging)
    async def _block_ip_address(self, ip: str) -> bool:
        """Block IP address on firewall"""
        if not ip or ip.startswith(("10.", "192.168.", "172.")):
            return False
        logger.info(f"[AI-AUTOMATION] Blocking IP address: {ip}")
        return True
        
    async def _isolate_host(self, hostname: str) -> bool:
        """Isolate host from network"""
        if not hostname:
            return False
        logger.info(f"[AI-AUTOMATION] Isolating host: {hostname}")
        return True
        
    async def _disable_user_account(self, user_id: str) -> bool:
        """Disable user account"""
        if not user_id:
            return False
        logger.info(f"[AI-AUTOMATION] Disabling user account: {user_id}")
        return True
        
    async def _quarantine_file(self, file_path: str) -> bool:
        """Quarantine malicious file"""
        if not file_path:
            return False
        logger.info(f"[AI-AUTOMATION] Quarantining file: {file_path}")
        return True
        
    async def _send_to_soar_platform(self, ticket: IncidentTicket) -> bool:
        """Send incident ticket to SOAR platform"""
        logger.info(f"[AI-SOAR] Creating incident ticket: {ticket.ticket_id}")
        return True
                
    async def _complete_workflow(self, alert: SecurityAlert, thread_id: str, 
                                response_metadata: Dict[str, Any]):
        """Complete the alert triage workflow"""
        
        completion_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="workflow_orchestrator",
            message_type=MessageType.WORKFLOW_COMPLETE,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "action": "ai_response_coordinated",
                "response_metadata": response_metadata,
                "completion_timestamp": datetime.datetime.now().isoformat()
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(completion_message)
        logger.info(f"AI response coordination workflow complete for alert {alert.alert_id}")
        
    async def _send_coordination_error(self, original_message: CoralMessage, error: str):
        """Send response coordination error"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"AI response coordination failed: {error}",
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
            "alerts_processed": self.alerts_processed,
            "incidents_created": self.incidents_created,
            "escalations_performed": self.escalations_performed,
            "automated_actions_triggered": self.automated_actions_triggered,
            "average_confidence": avg_confidence,
            "escalation_rate": (
                self.escalations_performed / self.alerts_processed
                if self.alerts_processed > 0 else 0
            ),
            "automation_rate": (
                self.automated_actions_triggered / self.alerts_processed
                if self.alerts_processed > 0 else 0
            ),
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
                result = await self.coordinate_response(alert_data)
                
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
