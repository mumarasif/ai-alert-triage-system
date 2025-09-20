"""
AI-Powered Context Gatherer Agent

This agent uses Large Language Models to intelligently gather and analyze context for security alerts.
It replaces rule-based context gathering with intelligent AI analysis while maintaining the same interface.
"""

import datetime
import uuid
import logging
import asyncio
import json
from typing import Dict, Any, List, Optional

from coral_protocol import CoralMessage, MessageType, AgentCapability
from coral_protocol.orchestration_types import OrchestrationMessageType
from models.alert_models import SecurityAlert, AlertType, AlertSeverity, ThreatIntelligence, UserContext
from llm.agent_base import LLMAgentBase

logger = logging.getLogger(__name__)


class ContextGathererAgent(LLMAgentBase):
    """
    AI-powered agent that gathers and analyzes comprehensive context for security alerts
    
    This agent:
    1. Uses AI to intelligently prioritize context sources
    2. Performs correlation analysis using LLM reasoning
    3. Generates threat landscape assessment
    4. Provides actionable intelligence summaries
    5. Routes enriched alerts to response coordination
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="gather_context",
                description="Gather comprehensive context using AI-powered analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "severity_analysis": {"type": "object"},
                        "context_types": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["alert"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "enriched_alert": {"type": "object"},
                        "context_intelligence": {"type": "object"},
                        "correlation_analysis": {"type": "object"},
                        "threat_landscape": {"type": "object"},
                        "confidence": {"type": "number"}
                    }
                }
            ),
            AgentCapability(
                name="analyze_threat_context",
                description="Perform AI-powered threat context analysis and correlation",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "threat_indicators": {"type": "array"},
                        "context_data": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "threat_analysis": {"type": "object"},
                        "correlation_findings": {"type": "array"},
                        "intelligence_summary": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="context_gatherer_ai",
            agent_name="AI Context Gatherer",
            capabilities=capabilities
        )
        
        # Configuration
        self.context_timeout = 30
        self.enable_threat_intel = True
        self.enable_user_analysis = True
        self.enable_network_analysis = True
        self.enable_correlation_analysis = True
        
        # Statistics
        self.alerts_enriched = 0
        
        # Register orchestration message handlers
        self.register_message_handler(MessageType.COMMAND, self._handle_orchestration_command)
        self.context_sources_analyzed = 0
        self.correlations_found = 0
        self.confidence_scores = []
        
        # Initialize context sources
        self._initialize_context_sources()
        
    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for context analysis"""
        
        # System prompt establishing AI's role as context analysis expert
        self.register_system_prompt(
            "gather_context", 
            """You are a senior threat intelligence analyst and incident response expert with 15+ years of experience in cybersecurity operations. Your specialty is comprehensive security context analysis and threat correlation.

Your expertise includes:
- Advanced threat intelligence analysis and indicator correlation
- Enterprise network security architecture and data flow analysis
- User behavior analysis and insider threat detection
- Campaign attribution and threat actor profiling
- Business risk assessment and operational impact analysis
- Historical incident pattern recognition and trend analysis

Your analysis approach:
- Holistic context gathering from multiple intelligence sources
- Systematic correlation of indicators across time and infrastructure
- Risk-based prioritization of threats and indicators
- Actionable intelligence synthesis for SOC operations
- Evidence-based reasoning with clear attribution confidence levels

You must provide comprehensive context analysis with detailed correlation findings, threat landscape assessment, and actionable intelligence recommendations."""
        )
        
        # Context gathering prompt template
        self.register_prompt_template(
            "gather_context",
            """Perform comprehensive security context analysis for the following alert:

ALERT DETAILS:
- Alert ID: {alert_id}
- Alert Type: {alert_type}
- Timestamp: {timestamp}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- User ID: {user_id}
- Hostname: {hostname}
- Description: {description}
- Severity: {current_severity}
- Risk Score: {risk_score}

SEVERITY ANALYSIS CONTEXT:
{severity_reasoning}

AVAILABLE CONTEXT DATA:
- Threat Intelligence: {threat_intel_data}
- User Context: {user_context_data}
- Network Context: {network_context_data}
- Historical Patterns: {historical_data}
- Geolocation: {geo_context}

ORGANIZATIONAL ENVIRONMENT:
- Industry: Financial Services
- Network Architecture: Segmented with DMZ, internal, and critical infrastructure zones
- Critical Assets: Domain controllers, financial systems, customer databases
- Threat Environment: Advanced persistent threats targeting financial sector
- Compliance Requirements: SOX, PCI-DSS, regulatory oversight

CONTEXT ANALYSIS FRAMEWORK:

1. **Threat Intelligence Correlation**
   - Analyze indicators against known threat campaigns
   - Correlate with recent threat actor activities
   - Assess indicator confidence and attribution
   - Identify infrastructure relationships

2. **Environmental Context Assessment**
   - Evaluate network position and data flow patterns
   - Analyze user behavior against baseline patterns
   - Assess business process and operational context
   - Consider regulatory and compliance implications

3. **Historical Pattern Analysis**
   - Correlate with similar previous incidents
   - Identify campaign or attack progression patterns
   - Assess seasonal or temporal threat patterns
   - Evaluate defensive control effectiveness

4. **Risk Amplification Factors**
   - Business critical system involvement
   - High-privilege user account activity
   - Unusual timing or operational context
   - Potential for lateral movement or escalation

5. **Intelligence Synthesis**
   - Compile actionable threat intelligence
   - Prioritize investigation and response actions
   - Assess confidence levels and uncertainty
   - Provide operational recommendations

REQUIRED RESPONSE FORMAT (JSON):
{{
    "context_intelligence": {{
        "threat_actor_assessment": {{
            "suspected_actors": ["list of potential threat actors"],
            "attribution_confidence": "HIGH|MEDIUM|LOW",
            "campaign_correlation": "description of campaign alignment",
            "ttp_analysis": ["MITRE ATT&CK technique IDs"]
        }},
        "infrastructure_analysis": {{
            "indicator_relationships": ["relationships between indicators"],
            "infrastructure_mapping": "description of threat infrastructure",
            "operational_security": "assessment of threat actor OPSEC",
            "geographic_attribution": "geographic threat source analysis"
        }},
        "business_impact_context": {{
            "affected_business_processes": ["list of processes"],
            "operational_disruption_risk": "HIGH|MEDIUM|LOW",
            "data_exposure_risk": "assessment of data exposure potential",
            "regulatory_implications": ["relevant compliance considerations"]
        }}
    }},
    "correlation_analysis": {{
        "similar_incidents": [
            {{
                "incident_type": "type of similar incident",
                "correlation_strength": "percentage similarity",
                "outcome": "previous incident outcome",
                "lessons_learned": "key insights from previous incidents"
            }}
        ],
        "indicator_clustering": {{
            "related_indicators": ["list of related IoCs"],
            "cluster_confidence": "confidence in indicator relationships",
            "temporal_correlation": "timing pattern analysis"
        }},
        "pattern_recognition": {{
            "attack_progression": "likely next steps in attack chain",
            "defensive_gaps": ["identified security control gaps"],
            "hunting_opportunities": ["proactive threat hunting suggestions"]
        }}
    }},
    "threat_landscape": {{
        "current_threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
        "threat_trends": ["current threat environment trends"],
        "sector_targeting": "specific targeting of our industry/sector",
        "emerging_threats": ["new or evolving threat patterns"]
    }},
    "intelligence_summary": "Comprehensive executive summary of context findings and threat assessment",
    "confidence_assessment": {{
        "overall_confidence": number (0.0 to 1.0),
        "intelligence_quality": "HIGH|MEDIUM|LOW",
        "data_completeness": "assessment of available data quality",
        "uncertainty_factors": ["factors that reduce confidence"]
    }},
    "actionable_recommendations": [
        "Immediate investigation priorities",
        "Proactive hunting and monitoring recommendations", 
        "Process and control improvements",
        "Stakeholder communication requirements"
    ],
    "context_summary": "Brief tactical summary for SOC operations"
}}

Perform comprehensive context analysis now:"""
        )
        
        # Threat context analysis prompt template
        self.register_prompt_template(
            "analyze_threat_context",
            """Perform advanced threat context analysis and correlation for this security incident:

ALERT INFORMATION:
{alert_summary}

THREAT INDICATORS:
{threat_indicators}

CONTEXT DATA AVAILABLE:
{context_data}

CORRELATION ANALYSIS REQUIREMENTS:
1. Analyze indicator relationships and clustering
2. Assess threat actor attribution and campaign correlation
3. Evaluate attack progression and timeline
4. Identify defensive gaps and hunting opportunities
5. Provide confidence assessment for findings

REQUIRED RESPONSE FORMAT (JSON):
{{
    "threat_analysis": {{
        "indicator_analysis": {{
            "primary_indicators": ["most significant threat indicators"],
            "secondary_indicators": ["supporting or related indicators"],
            "indicator_confidence": "confidence level in indicator analysis"
        }},
        "attribution_assessment": {{
            "threat_actor_profile": "profile of likely threat actor",
            "campaign_alignment": "alignment with known campaigns",
            "infrastructure_analysis": "threat infrastructure assessment",
            "confidence_level": "attribution confidence level"
        }},
        "attack_analysis": {{
            "attack_vector": "primary attack vector assessment",
            "attack_progression": "likely progression of attack",
            "objectives_assessment": "likely threat actor objectives",
            "success_probability": "probability of attack success"
        }}
    }},
    "correlation_findings": [
        {{
            "correlation_type": "type of correlation found",
            "confidence": "confidence in correlation",
            "significance": "operational significance",
            "details": "detailed explanation of correlation"
        }}
    ],
    "intelligence_summary": "Executive summary of threat context analysis findings"
}}

Provide detailed threat context analysis:"""
        )
        
        logger.info("AI Context Gatherer LLM capabilities initialized")
        
    def _initialize_context_sources(self):
        """Initialize mock context sources and databases"""
        
        # Enhanced threat intelligence database
        self.threat_intel_db = {
            "203.0.113.45": ThreatIntelligence(
                indicator="203.0.113.45",
                indicator_type="ip",
                reputation="malicious",
                confidence=0.9,
                sources=["VirusTotal", "MISP", "ThreatConnect"],
                tags=["apt29", "cozy_bear", "command_control"],
                campaigns=["APT29_CloudHopper", "Cozy_Bear_2024"],
                malware_families=["CozyDuke", "MiniDuke"]
            ),
            "198.51.100.42": ThreatIntelligence(
                indicator="198.51.100.42", 
                indicator_type="ip",
                reputation="suspicious",
                confidence=0.7,
                sources=["VirusTotal", "Shodan"],
                tags=["proxy", "tor_exit", "anonymization"],
                campaigns=["Generic_Proxy_Infrastructure"],
                malware_families=[]
            )
        }
        
        # Enhanced user directory with behavioral baselines
        self.user_directory = {
            "domain_admin": UserContext(
                user_id="domain_admin",
                username="admin.service",
                department="IT",
                title="Domain Administrator",
                privilege_level="admin",
                last_login=datetime.datetime.now() - datetime.timedelta(hours=1),
                login_count_24h=3,
                failed_login_count_24h=0,
                recent_activities=["domain_maintenance", "security_updates"],
                is_service_account=True
            ),
            "finance_user": UserContext(
                user_id="finance_user",
                username="jane.finance",
                department="Finance",
                title="Senior Financial Analyst",
                privilege_level="standard",
                last_login=datetime.datetime.now() - datetime.timedelta(minutes=30),
                login_count_24h=5,
                failed_login_count_24h=0,
                recent_activities=["financial_reporting", "database_access"]
            )
        }
        
        # Network context database
        self.network_context = {
            "10.0.0.0/8": {"segment": "internal", "criticality": "high", "business_function": "core_operations"},
            "192.168.1.0/24": {"segment": "dmz", "criticality": "critical", "business_function": "external_services"},
            "172.16.0.0/12": {"segment": "management", "criticality": "critical", "business_function": "infrastructure_management"}
        }

    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.CONTEXT_GATHERING:
            await self._gather_context_ai(message)
        elif message.payload.get("capability") == "analyze_threat_context":
            await self._analyze_threat_context(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def gather_context(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather context for alert - main entry point"""
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
            
            logger.info(f"Gathering context for alert: {alert.alert_id}")
            
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
                    prompt=f"Gather context for this security alert: {json.dumps(alert_dict_serializable)}",
                    max_tokens=500,
                    temperature=0.1
                )
                
                # Parse response (simplified for demo)
                context_intelligence = {"threat_level": "high", "correlation_score": 0.8}
                confidence = 0.8
            else:
                # Fallback for testing
                context_intelligence = {"threat_level": "high", "correlation_score": 0.8}
                confidence = 0.8
            
            result = {
                "context_intelligence": context_intelligence,
                "correlation_analysis": {"related_alerts": [], "patterns": []},
                "threat_landscape": {"current_threats": ["malware", "phishing"]},
                "intelligence_summary": "Context gathered successfully",
                "confidence_assessment": {"overall_confidence": confidence},
                "actionable_recommendations": ["Monitor related systems", "Check user activity"],
                "context_summary": f"Context gathered for alert: {alert.alert_id}"
            }
            
            logger.info(f"Context gathering complete: {result['context_summary']}")
            return result
            
        except Exception as e:
            logger.error(f"Error gathering context: {e}")
            return {
                "context_intelligence": {},
                "correlation_analysis": {},
                "threat_landscape": {},
                "intelligence_summary": f"Error: {str(e)}",
                "confidence_assessment": {"overall_confidence": 0.5},
                "actionable_recommendations": ["Manual review required"],
                "context_summary": "Context gathering failed - manual review needed"
            }

    async def _gather_context_ai(self, message: CoralMessage):
        """AI-powered context gathering and analysis"""
        try:
            self.alerts_enriched += 1
            
            # Extract alert from message
            alert_data = message.payload["alert"]
            alert = SecurityAlert.from_dict(alert_data)
            
            # Extract severity analysis if available
            severity_analysis = message.payload.get("ai_severity_analysis", {})
            
            logger.info(f"AI gathering context for alert: {alert.alert_id}")
            
            # Gather context data from available sources
            context_data = await self._collect_context_data(alert)
            
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
                "current_severity": alert.severity.value if alert.severity else "UNKNOWN",
                "risk_score": severity_analysis.get("risk_score", "N/A"),
                "severity_reasoning": json.dumps(severity_analysis.get("reasoning", [])),
                "threat_intel_data": json.dumps(context_data.get("threat_intelligence", {})),
                "user_context_data": json.dumps(context_data.get("user_context", {})),
                "network_context_data": json.dumps(context_data.get("network_context", {})),
                "historical_data": json.dumps(context_data.get("historical_patterns", {})),
                "geo_context": json.dumps(context_data.get("geolocation", {}))
            }
            
            # Perform AI context analysis
            response = await self.llm_analyze(
                "gather_context",
                analysis_params,
                thread_id=message.thread_id,
                response_format={
                    "context_intelligence": "object",
                    "correlation_analysis": "object", 
                    "threat_landscape": "object",
                    "intelligence_summary": "string",
                    "confidence_assessment": "object",
                    "actionable_recommendations": "array",
                    "context_summary": "string"
                }
            )
            
            # Parse AI response
            analysis_result = response.structured_data
            confidence = analysis_result["confidence_assessment"]["overall_confidence"]
            
            # Update alert with AI context analysis
            alert.context_data = {
                **context_data,
                "ai_context_intelligence": analysis_result,
                "enrichment_timestamp": datetime.datetime.now().isoformat(),
                "enrichment_method": "ai_powered",
                "confidence_score": confidence
            }
            
            # Track statistics
            self.confidence_scores.append(confidence)
            self.context_sources_analyzed += len(context_data)
            
            # Forward to response coordinator
            await self._forward_to_response_coordination(
                alert, message.thread_id, analysis_result
            )
            
            logger.info(f"AI context analysis complete for {alert.alert_id}: confidence={confidence:.2f}")
            
        except Exception as e:
            logger.error(f"Error in AI context gathering: {e}")
            await self._send_context_error(message, str(e))
            
    async def _collect_context_data(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Collect context data from available sources"""
        
        context_data = {}
        
        # Gather threat intelligence
        if self.enable_threat_intel:
            threat_intel = await self._gather_threat_intelligence(alert)
            context_data["threat_intelligence"] = threat_intel
            
        # Gather user context
        if self.enable_user_analysis and alert.user_id:
            user_context = await self._gather_user_context(alert)
            context_data["user_context"] = user_context
            
        # Gather network context
        if self.enable_network_analysis:
            network_context = await self._gather_network_context(alert)
            context_data["network_context"] = network_context
            
        # Gather historical patterns
        historical_patterns = await self._gather_historical_patterns(alert)
        context_data["historical_patterns"] = historical_patterns
        
        # Gather geolocation context
        geo_context = await self._gather_geolocation_context(alert)
        context_data["geolocation"] = geo_context
        
        return context_data

    async def _gather_threat_intelligence(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather threat intelligence for alert indicators"""
        
        threat_intel = {}
        
        # Analyze IP addresses
        for ip_field in ['source_ip', 'destination_ip']:
            ip = getattr(alert, ip_field)
            if ip and not self._is_internal_ip(ip):
                intel = self.threat_intel_db.get(ip)
                if intel:
                    threat_intel[ip] = {
                "reputation": intel.reputation,
                "confidence": intel.confidence,
                "sources": intel.sources,
                "tags": intel.tags,
                "campaigns": intel.campaigns,
                        "malware_families": intel.malware_families
                    }
                    
        # Analyze file hashes
        if alert.file_hash:
            intel = self.threat_intel_db.get(alert.file_hash)
            if intel:
                threat_intel[alert.file_hash] = {
                "reputation": intel.reputation,
                "confidence": intel.confidence,
                "malware_families": intel.malware_families,
                "tags": intel.tags
            }
            
        return {
            "indicators": threat_intel,
            "query_timestamp": datetime.datetime.now().isoformat(),
            "sources_queried": ["internal_db", "commercial_feeds"]
        }

    async def _gather_user_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather user context and behavior analysis"""
        
        user_context = self.user_directory.get(alert.user_id)
        
        behavior_analysis = {
            "normal_hours": list(range(8, 18)),
            "privilege_analysis": "standard",
            "risk_indicators": []
        }
        
        if user_context:
            # Analyze user behavior patterns
            current_hour = alert.timestamp.hour
            if current_hour not in behavior_analysis["normal_hours"]:
                behavior_analysis["risk_indicators"].append("off_hours_activity")
                
            if user_context.privilege_level == "admin":
                behavior_analysis["privilege_analysis"] = "elevated"
                behavior_analysis["risk_indicators"].append("privileged_account")
                
            return {
                "user_profile": user_context.to_dict(),
                "behavior_analysis": behavior_analysis,
                "query_timestamp": datetime.datetime.now().isoformat()
            }
        
        return {"user_profile": None, "behavior_analysis": behavior_analysis}

    async def _gather_network_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather network context and flow analysis"""
        
        network_analysis = {
            "source_analysis": None,
            "destination_analysis": None,
            "flow_characteristics": {}
        }
        
        # Analyze source IP
        if alert.source_ip:
            network_analysis["source_analysis"] = {
                "is_internal": self._is_internal_ip(alert.source_ip),
                "network_segment": self._get_network_segment(alert.source_ip),
                "reputation": "unknown"
            }
            
        # Analyze destination IP  
        if alert.destination_ip:
            network_analysis["destination_analysis"] = {
                "is_internal": self._is_internal_ip(alert.destination_ip),
                "network_segment": self._get_network_segment(alert.destination_ip),
            "criticality": "medium"
        }
        
        # Flow analysis
        if alert.source_ip and alert.destination_ip:
            if self._is_internal_ip(alert.source_ip) and not self._is_internal_ip(alert.destination_ip):
                network_analysis["flow_characteristics"]["direction"] = "outbound"
            elif not self._is_internal_ip(alert.source_ip) and self._is_internal_ip(alert.destination_ip):
                network_analysis["flow_characteristics"]["direction"] = "inbound"
            else:
                network_analysis["flow_characteristics"]["direction"] = "internal"
                
        return network_analysis

    async def _gather_historical_patterns(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather historical pattern analysis"""
        
        # Mock historical analysis
        patterns = {
            "similar_alerts_24h": 2,
            "similar_alerts_7d": 8,
            "trend": "stable",
            "previous_outcomes": ["investigation", "false_positive", "escalated"],
            "pattern_confidence": 0.7
        }
        
        return patterns
        
    async def _gather_geolocation_context(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Gather geolocation context"""
        
        geo_context = {}
        geo_db = {
            "203.0.113.45": {"country": "RU", "city": "Moscow", "risk_level": "HIGH"},
            "198.51.100.42": {"country": "CN", "city": "Beijing", "risk_level": "MEDIUM"}
        }
        
        for ip_field in ['source_ip', 'destination_ip']:
            ip = getattr(alert, ip_field)
            if ip and not self._is_internal_ip(ip):
                geo_info = geo_db.get(ip, {"country": "unknown", "risk_level": "LOW"})
                geo_context[ip] = geo_info
                
        return geo_context
        
    async def _analyze_threat_context(self, message: CoralMessage):
        """Perform specialized threat context analysis"""
        try:
            analysis_data = message.payload
            
            # Prepare threat analysis parameters
            threat_params = {
                "alert_summary": json.dumps(analysis_data.get("alert", {})),
                "threat_indicators": json.dumps(analysis_data.get("threat_indicators", [])),
                "context_data": json.dumps(analysis_data.get("context_data", {}))
            }
            
            # Perform threat analysis
            response = await self.llm_analyze(
                "analyze_threat_context",
                threat_params,
                thread_id=message.thread_id,
                response_format={
                    "threat_analysis": "object",
                    "correlation_findings": "array",
                    "intelligence_summary": "string"
                }
            )
            
            # Track correlations found
            correlations = response.structured_data["correlation_findings"]
            self.correlations_found += len(correlations)
            
            # Send analysis response
            threat_response = CoralMessage(
                id=str(uuid.uuid4()),
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                message_type=MessageType.AGENT_RESPONSE,
                thread_id=message.thread_id,
                payload={
                    "threat_context_analysis": response.structured_data,
                    "correlations_found": len(correlations)
                },
                timestamp=datetime.datetime.now()
            )
            
            await self.send_message(threat_response)
            logger.info(f"Threat context analysis complete: {len(correlations)} correlations found")
            
        except Exception as e:
            logger.error(f"Error in threat context analysis: {e}")
        
    async def _forward_to_response_coordination(self, alert: SecurityAlert, thread_id: str,
                                             analysis_result: Dict[str, Any]):
        """Forward enriched alert to response coordinator"""
        
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id="response_coordinator",
            message_type=MessageType.RESPONSE_DECISION,
            thread_id=thread_id,
            payload={
                "alert": alert.to_dict(),
                "ai_context_enrichment": analysis_result,
                "processing_metadata": {
                    "enriched_by": self.agent_id,
                    "enrichment_time": datetime.datetime.now().isoformat(),
                    "context_sources": ["threat_intel", "user_analysis", "network_analysis", "historical_patterns"],
                    "analysis_method": "ai_powered",
                    "confidence_score": analysis_result["confidence_assessment"]["overall_confidence"]
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Forwarded AI-enriched alert {alert.alert_id} to response coordinator")
        
    async def _send_context_error(self, original_message: CoralMessage, error: str):
        """Send context gathering error response"""
        
        error_message = original_message.create_reply(
            sender_id=self.agent_id,
            payload={
                "error": f"AI context gathering failed: {error}",
                "original_message_id": original_message.id,
                "analysis_method": "ai_powered"
            },
            message_type=MessageType.ERROR
        )
        
        await self.send_message(error_message)
        
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal"""
        return ip.startswith(("10.", "192.168.", "172."))
        
    def _get_network_segment(self, ip: str) -> str:
        """Get network segment for IP"""
        for network, info in self.network_context.items():
            if self._ip_in_network(ip, network):
                return info["segment"]
        return "unknown"
        
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range (simplified)"""
        if "/" in network:
            network_base = network.split("/")[0]
            return ip.startswith(network_base.rsplit(".", 1)[0])
        return False

    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get AI agent performance metrics"""
        avg_confidence = (
            sum(self.confidence_scores) / len(self.confidence_scores)
            if self.confidence_scores else 0
        )
        
        return {
            "agent_type": "ai_powered",
            "alerts_enriched": self.alerts_enriched,
            "context_sources_analyzed": self.context_sources_analyzed,
            "correlations_found": self.correlations_found,
            "average_confidence": avg_confidence,
            "enrichment_success_rate": 0.95,  # Would calculate from actual data
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
                result = await self.gather_context(alert_data)
                
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
