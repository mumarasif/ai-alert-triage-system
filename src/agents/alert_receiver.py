"""
AI-Powered Alert Receiver Agent - Orchestrated Version

This agent uses Large Language Models to intelligently normalize and process incoming security alerts
in an orchestrated workflow environment. It inherits from TaskExecutorBase to work with the
True Orchestrator Agent.
"""

import datetime
import uuid
import logging
import json
from typing import Dict, Any, List, Optional, Tuple

from coral_protocol import CoralMessage, MessageType, AgentCapability
from models.alert_models import SecurityAlert, AlertType, AlertStatus
from agents.task_executor_base import TaskExecutorBase
from coral_protocol.orchestration_types import AgentTask
from services.database_service import db_service

logger = logging.getLogger(__name__)


class AlertReceiverAgent(TaskExecutorBase):
    """
    AI-powered agent that receives and intelligently processes incoming security alerts
    in an orchestrated workflow environment
    
    This agent:
    1. Uses AI to normalize disparate alert formats intelligently
    2. Performs intelligent alert validation and quality assessment
    3. Enriches alerts with initial AI-based insights
    4. Works as a task executor in orchestrated workflows
    5. Provides adaptive alert processing optimization
    """
    
    def __init__(self, agent_id: str = "alert_receiver_ai", **kwargs):
        super().__init__(agent_id=agent_id, **kwargs)
        
        # Set agent capabilities
        self.agent_status.capabilities = [
            "receive_alert",
            "normalize_alert",
            "validate_alert",
            "enrich_alert",
            "route_alert"
        ]
        
        # AI processing configuration
        self.normalization_prompts = {
            "extract_fields": """
            You are a security alert normalization expert. Extract and standardize the following fields from the raw alert data:
            
            Required fields:
            - alert_id: Unique identifier for the alert
            - title: Clear, descriptive title
            - description: Detailed description of the security event
            - severity: Critical, High, Medium, Low, or Info
            - alert_type: Malware, Intrusion, Data_Exfiltration, etc.
            - source_ip: Source IP address if available
            - destination_ip: Destination IP address if available
            - timestamp: When the event occurred
            - source_system: Which security system generated this alert
            
            Raw alert data: {alert_data}
            
            Return a JSON object with the normalized fields.
            """,
            
            "validate_quality": """
            You are a security alert quality assessor. Evaluate the alert data quality and completeness:
            
            Assess:
            1. Data completeness (0-100 score)
            2. Data accuracy (0-100 score) 
            3. Alert relevance (0-100 score)
            4. False positive likelihood (0-100 score)
            5. Processing confidence (0-100 score)
            
            Alert data: {normalized_alert}
            
            Return a JSON object with quality scores and recommendations.
            """,
            
            "enrich_insights": """
            You are a security analyst. Provide initial insights and context for this alert:
            
            Analyze:
            1. Potential attack vectors
            2. Risk assessment
            3. Recommended immediate actions
            4. Related threat indicators
            5. Contextual information
            
            Alert data: {normalized_alert}
            
            Return a JSON object with insights and recommendations.
            """
        }
    
    async def _execute_task_logic(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute the alert processing task logic
        
        Args:
            task: The task containing alert data and context
            
        Returns:
            Dict containing the processed alert and results
        """
        
        try:
            # Extract alert data from task payload (context is stored in payload)
            alert_data = task.payload.get("context", {}).get("alert_data", {})
            source_metadata = task.payload.get("context", {}).get("source_metadata", {})
            
            logger.info(f"Processing alert task: {task.task_id}")
            
            # Step 1: Normalize alert data using AI
            normalized_alert = await self._normalize_alert_data(alert_data, source_metadata)
            
            # Step 2: Validate alert quality using AI
            quality_assessment = await self._assess_alert_quality(normalized_alert)
            
            # Step 3: Enrich with AI insights
            ai_insights = await self._generate_ai_insights(normalized_alert)
            
            # Step 4: Create final SecurityAlert object
            security_alert = self._create_security_alert(normalized_alert, quality_assessment, ai_insights)
            
            # Step 5: Determine next workflow steps
            workflow_recommendations = await self._recommend_workflow_steps(security_alert)
            
            # Save AI analysis to database
            try:
                analysis_data = {
                    "false_positive_probability": quality_assessment.get("false_positive_likelihood", 0) / 100.0,
                    "severity_score": self._calculate_severity_score(security_alert.severity),
                    "context_data": {
                        "normalized_data": normalized_alert,
                        "quality_assessment": quality_assessment,
                        "ai_insights": ai_insights
                    },
                    "recommended_actions": workflow_recommendations.get("immediate_actions", []),
                    "agent_results": {
                        "agent_id": self.agent_id,
                        "processing_metadata": {
                            "processed_at": datetime.datetime.utcnow().isoformat(),
                            "task_id": task.task_id,
                            "processing_time_ms": (datetime.datetime.utcnow() - task.started_at).total_seconds() * 1000
                        }
                    },
                    "confidence_score": quality_assessment.get("processing_confidence", 0) / 100.0,
                    "processing_time_ms": (datetime.datetime.utcnow() - task.started_at).total_seconds() * 1000
                }
                
                await db_service.save_ai_analysis(security_alert.alert_id, analysis_data)
                logger.info(f"AI analysis saved to database for alert: {security_alert.alert_id}")
                
            except Exception as db_error:
                logger.error(f"Failed to save AI analysis to database: {db_error}")
                # Continue processing even if database save fails
            
            # Update agent status
            try:
                await db_service.update_agent_status(self.agent_id, {
                    "status": "active",
                    "last_activity": datetime.datetime.utcnow().isoformat(),
                    "last_processed_alert": security_alert.alert_id,
                    "processing_count": 1  # This would be incremented in a real implementation
                })
            except Exception as status_error:
                logger.error(f"Failed to update agent status: {status_error}")
            
            # Prepare result
            result = {
                "security_alert": security_alert.to_dict(),
                "normalized_data": normalized_alert,
                "quality_assessment": quality_assessment,
                "ai_insights": ai_insights,
                "workflow_recommendations": workflow_recommendations,
                "processing_metadata": {
                    "processed_at": datetime.datetime.utcnow().isoformat(),
                    "agent_id": self.agent_id,
                    "task_id": task.task_id,
                    "processing_time_ms": (datetime.datetime.utcnow() - task.started_at).total_seconds() * 1000
                }
            }
            
            logger.info(f"Successfully processed alert: {security_alert.alert_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error processing alert task {task.task_id}: {e}")
            raise
    
    async def _normalize_alert_data(self, alert_data: Dict[str, Any], source_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw alert data using AI analysis"""
        
        try:
            # Prepare prompt with alert data
            prompt = self.normalization_prompts["extract_fields"].format(
                alert_data=json.dumps(alert_data, indent=2)
            )
            
            # Get AI response
            if self.llm_client:
                llm_response = await self.llm_client.generate_completion(
                    prompt=prompt,
                    max_tokens=1000,
                    temperature=0.1
                )
                response = llm_response.content
            else:
                # Fallback for testing mode
                response = '{"alert_id": "' + alert_data.get("alert_id", "unknown") + '", "normalized_type": "malware", "confidence": 0.8}'
            
            # Parse AI response
            if response and response.strip():
                try:
                    normalized_data = json.loads(response.strip())
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM response as JSON: {e}")
                    normalized_data = {
                        "alert_id": alert_data.get("alert_id", str(uuid.uuid4())),
                        "normalized_type": "malware",
                        "confidence": 0.8,
                        "reasoning": ["LLM response parsing failed, using fallback"]
                    }
            else:
                # Fallback if LLM returns empty response
                normalized_data = {
                    "alert_id": alert_data.get("alert_id", str(uuid.uuid4())),
                    "normalized_type": "malware",
                    "confidence": 0.8,
                    "description": alert_data.get("description", "Unknown alert")
                }
            
            # Add source metadata
            normalized_data["source_metadata"] = source_metadata
            normalized_data["original_data"] = alert_data
            
            return normalized_data
            
        except Exception as e:
            logger.error(f"Error normalizing alert data: {e}")
            # Fallback to basic normalization
            return self._fallback_normalization(alert_data, source_metadata)
    
    async def _assess_alert_quality(self, normalized_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Assess alert data quality using AI analysis"""
        
        try:
            # Prepare prompt with normalized alert
            prompt = self.normalization_prompts["validate_quality"].format(
                normalized_alert=json.dumps(normalized_alert, indent=2)
            )
            
            # Get AI response
            if self.llm_client:
                llm_response = await self.llm_client.generate_completion(
                    prompt=prompt,
                    max_tokens=500,
                    temperature=0.1
                )
                response = llm_response.content
            else:
                # Fallback for testing mode
                response = '{"quality_score": 0.8, "completeness": 0.9, "reliability": 0.7}'
            
            # Parse AI response
            if response and response.strip():
                try:
                    quality_data = json.loads(response.strip())
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM quality response as JSON: {e}")
                    quality_data = {
                        "data_completeness": 80,
                        "data_accuracy": 70,
                        "alert_relevance": 75,
                        "false_positive_likelihood": 30,
                        "processing_confidence": 80,
                        "recommendations": ["LLM response parsing failed, using fallback"]
                    }
            else:
                # Fallback if LLM returns empty response
                quality_data = {
                    "quality_score": 0.8,
                    "completeness": 0.9,
                    "reliability": 0.7
                }
            
            return quality_data
            
        except Exception as e:
            logger.error(f"Error assessing alert quality: {e}")
            # Fallback to basic quality assessment
            return self._fallback_quality_assessment(normalized_alert)
    
    async def _generate_ai_insights(self, normalized_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI insights for the alert"""
        
        try:
            # Prepare prompt with normalized alert
            prompt = self.normalization_prompts["enrich_insights"].format(
                normalized_alert=json.dumps(normalized_alert, indent=2)
            )
            
            # Get AI response
            if self.llm_client:
                llm_response = await self.llm_client.generate_completion(
                    prompt=prompt,
                    max_tokens=800,
                    temperature=0.2
                )
                response = llm_response.content
            else:
                # Fallback for testing mode
                response = '{"threat_level": "high", "recommended_actions": ["isolate_host", "block_ip"], "confidence": 0.85}'
            
            # Parse AI response
            if response and response.strip():
                try:
                    insights = json.loads(response.strip())
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse LLM insights response as JSON: {e}")
                    insights = {
                        "potential_attack_vectors": ["Unknown"],
                        "risk_assessment": {"impact": "Medium", "likelihood": "Medium"},
                        "recommended_immediate_actions": ["Manual review required"],
                        "related_threat_indicators": ["Unknown"],
                        "contextual_information": ["LLM response parsing failed"]
                    }
            else:
                # Fallback if LLM returns empty response
                insights = {
                    "threat_level": "high",
                    "recommended_actions": ["isolate_host", "block_ip"],
                    "confidence": 0.85
                }
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating AI insights: {e}")
            # Fallback to basic insights
            return self._fallback_insights(normalized_alert)
    
    def _create_security_alert(self, normalized_data: Dict[str, Any], quality_assessment: Dict[str, Any], ai_insights: Dict[str, Any]) -> SecurityAlert:
        """Create a SecurityAlert object from normalized data"""
        
        try:
            # Map severity string to enum
            severity_mapping = {
                "critical": "Critical",
                "high": "High", 
                "medium": "Medium",
                "low": "Low",
                "info": "Info"
            }
            
            severity_str = normalized_data.get("severity", "Medium").lower()
            severity = severity_mapping.get(severity_str, "Medium")
            
            # Map alert type string to enum
            alert_type_mapping = {
                "malware": "Malware",
                "intrusion": "Intrusion",
                "data_exfiltration": "Data_Exfiltration",
                "ddos": "DDoS",
                "phishing": "Phishing",
                "insider_threat": "Insider_Threat"
            }
            
            alert_type_str = normalized_data.get("alert_type", "Unknown").lower()
            alert_type = alert_type_mapping.get(alert_type_str, "Unknown")
            
            # Create SecurityAlert object
            security_alert = SecurityAlert(
                alert_id=normalized_data.get("alert_id", str(uuid.uuid4())),
                description=normalized_data.get("description", "Unknown Alert"),
                severity=severity,
                alert_type=alert_type,
                source_ip=normalized_data.get("source_ip"),
                destination_ip=normalized_data.get("destination_ip"),
                timestamp=datetime.datetime.fromisoformat(
                    normalized_data.get("timestamp", datetime.datetime.utcnow().isoformat())
                ),
                source_system=normalized_data.get("source_system", "Unknown"),
                user_id=normalized_data.get("user_id"),
                hostname=normalized_data.get("hostname"),
                raw_data={
                    "normalized_data": normalized_data,
                    "quality_assessment": quality_assessment,
                    "ai_insights": ai_insights,
                    "processing_agent": self.agent_id,
                    "processed_at": datetime.datetime.utcnow().isoformat()
                }
            )
            
            return security_alert
            
        except Exception as e:
            logger.error(f"Error creating SecurityAlert object: {e}")
            # Create minimal SecurityAlert as fallback
            return SecurityAlert(
                alert_id=str(uuid.uuid4()),
                description=f"Error processing alert: {str(e)}",
                severity=AlertSeverity.MEDIUM,
                alert_type=AlertType.UNKNOWN,
                timestamp=datetime.datetime.utcnow(),
                source_system="error"
            )
    
    async def _recommend_workflow_steps(self, security_alert: SecurityAlert) -> Dict[str, Any]:
        """Recommend next workflow steps based on alert analysis"""
        
        try:
            # Analyze alert characteristics to recommend workflow steps
            recommendations = {
                "immediate_actions": [],
                "next_agents": [],
                "priority_level": "normal",
                "estimated_processing_time": "5-10 minutes"
            }
            
            # High severity alerts need immediate attention
            if security_alert.severity in ["Critical", "High"]:
                recommendations["immediate_actions"].append("Escalate to senior analyst")
                recommendations["priority_level"] = "high"
                recommendations["estimated_processing_time"] = "2-5 minutes"
            
            # Malware alerts need false positive checking
            if security_alert.alert_type == "Malware":
                recommendations["next_agents"].append("FalsePositiveCheckerAgentAI")
                recommendations["immediate_actions"].append("Run malware analysis")
            
            # Intrusion alerts need context gathering
            if security_alert.alert_type == "Intrusion":
                recommendations["next_agents"].append("ContextGathererAgentAI")
                recommendations["immediate_actions"].append("Gather network context")
            
            # Data exfiltration needs immediate response
            if security_alert.alert_type == "Data_Exfiltration":
                recommendations["next_agents"].append("ResponseCoordinatorAgentAI")
                recommendations["immediate_actions"].append("Initiate incident response")
                recommendations["priority_level"] = "critical"
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating workflow recommendations: {e}")
            return {
                "immediate_actions": ["Manual review required"],
                "next_agents": ["SeverityAnalyzerAgentAI"],
                "priority_level": "normal",
                "estimated_processing_time": "10-15 minutes"
            }
    
    def _fallback_normalization(self, alert_data: Dict[str, Any], source_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback normalization when AI processing fails"""
        
        return {
            "alert_id": str(uuid.uuid4()),
            "title": alert_data.get("title", "Unknown Alert"),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", "Medium"),
            "alert_type": alert_data.get("type", "Unknown"),
            "source_ip": alert_data.get("source_ip"),
            "destination_ip": alert_data.get("destination_ip"),
            "timestamp": alert_data.get("timestamp", datetime.datetime.utcnow().isoformat()),
            "source_system": source_metadata.get("system_name", "Unknown"),
            "source_metadata": source_metadata,
            "original_data": alert_data
        }
    
    def _fallback_quality_assessment(self, normalized_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback quality assessment when AI processing fails"""
        
        return {
            "completeness_score": 50,
            "accuracy_score": 50,
            "relevance_score": 50,
            "false_positive_likelihood": 50,
            "processing_confidence": 30,
            "recommendations": ["Manual review recommended"]
        }
    
    def _fallback_insights(self, normalized_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback insights when AI processing fails"""
        
        return {
            "attack_vectors": ["Unknown"],
            "risk_assessment": "Medium",
            "recommended_actions": ["Manual analysis required"],
            "threat_indicators": [],
            "contextual_info": "Limited context available"
        }
    
    def _calculate_severity_score(self, severity: str) -> float:
        """Calculate numeric severity score from severity string"""
        
        severity_mapping = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.4,
            "Info": 0.2
        }
        
        return severity_mapping.get(severity, 0.5)
    
    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for alert normalization"""
        
        # System prompt establishing AI's role as alert processing expert
        self.register_system_prompt(
            "receive_alert",
            """You are a senior security operations engineer and alert processing expert with 15+ years of experience in enterprise SIEM and security tool integration. Your specialty is intelligent alert normalization and workflow optimization.

Your expertise includes:
- Multi-vendor security tool integration and data normalization
- Alert quality assessment and enrichment strategies  
- SOC workflow optimization and process improvement
- False positive pattern recognition and mitigation
- Security alert taxonomy and classification standards
- Performance optimization and scalability engineering

Your normalization approach:
- Intelligent field mapping with context preservation
- Quality-driven data enhancement and validation
- Source-aware processing with vendor-specific knowledge
- Pattern-based workflow routing and optimization
- Confidence-based processing decisions
- Continuous learning and adaptation from processing outcomes

You must provide comprehensive alert normalization with quality assessment, workflow recommendations, and processing insights for optimal SOC operations."""
        )
        
        # Alert normalization prompt template
        self.register_prompt_template(
            "receive_alert",
            """Intelligently normalize and process the following security alert:

RAW ALERT DATA:
{raw_alert_data}

SOURCE SYSTEM INFORMATION:
- Source Type: {source_system}
- Data Format: {data_format}
- Vendor: {vendor_info}
- Integration Method: {integration_method}

NORMALIZATION REQUIREMENTS:
1. Intelligent field mapping and data extraction
2. Alert type classification and categorization
3. Severity assessment and priority assignment
4. Quality evaluation and confidence scoring
5. Workflow routing recommendation

ORGANIZATIONAL CONTEXT:
- Alert Processing Standards: Common Event Format (CEF) + STIX/TAXII
- Supported Alert Types: malware, data_exfiltration, brute_force, phishing, etc.
- Network Architecture: Segmented enterprise with DMZ, internal, and critical zones
- Business Operations: Financial services with 24/7 SOC operations
- Compliance Requirements: SOX, PCI-DSS, regulatory reporting

NORMALIZATION FRAMEWORK:

1. **Field Extraction and Mapping**
   - Extract and normalize timestamp to ISO format
   - Map source system fields to standard alert schema
   - Identify and extract network indicators (IPs, ports, protocols)
   - Extract user and asset information with context preservation
   - Preserve original data integrity and traceability

2. **Alert Classification**
   - Determine alert type based on content analysis
   - Assess initial severity based on indicators and context
   - Identify alert category and subcategory
   - Map to threat taxonomy (MITRE ATT&CK if applicable)
   - Evaluate business impact and operational priority

3. **Quality Assessment**
   - Evaluate data completeness and quality
   - Assess confidence in field extraction and mapping
   - Identify missing or low-quality data elements
   - Recommend data enrichment opportunities
   - Score overall alert quality and actionability

4. **Workflow Optimization**
   - Recommend optimal processing workflow
   - Assess automation potential and safety
   - Identify fast-track vs. enhanced analysis needs
   - Consider resource allocation and SOC capacity
   - Optimize for both efficiency and effectiveness

REQUIRED RESPONSE FORMAT (JSON):
{{
    "normalized_alert": {{
        "alert_id": "unique alert identifier",
        "timestamp": "ISO format timestamp",
        "source_system": "normalized source system name",
        "alert_type": "malware|data_exfiltration|brute_force|phishing|etc",
        "severity": "critical|high|medium|low",
        "description": "normalized and enhanced description",
        "source_ip": "source IP address if available",
        "destination_ip": "destination IP address if available",
        "source_port": "source port if available",
        "destination_port": "destination port if available",
        "protocol": "network protocol if available",
        "user_id": "user identifier if available",
        "hostname": "hostname if available",
        "process_name": "process name if available",
        "file_path": "file path if available",
        "file_hash": "file hash if available",
        "additional_indicators": ["additional IoCs or indicators"],
        "normalized_fields": {{
            "extracted_fields": ["list of successfully extracted fields"],
            "mapping_confidence": "confidence level in field mapping",
            "data_quality_score": "score from 0.0 to 1.0"
        }}
    }},
    "ai_insights": {{
        "initial_assessment": {{
            "threat_indicators": ["key threat indicators identified"],
            "business_impact": "potential business impact assessment",
            "urgency_factors": ["factors affecting response urgency"],
            "automation_potential": "assessment of automation applicability"
        }},
        "quality_analysis": {{
            "data_completeness": "assessment of data completeness",
            "confidence_factors": ["factors affecting confidence"],
            "enrichment_opportunities": ["recommended data enrichment"],
            "validation_status": "passed|warning|failed"
        }},
        "pattern_recognition": {{
            "similar_alert_patterns": ["patterns matching historical alerts"],
            "anomaly_indicators": ["unusual or anomalous elements"],
            "campaign_indicators": ["potential campaign or attack pattern markers"]
        }}
    }},
    "workflow_recommendation": {{
        "recommended_workflow": "standard_triage|fast_track|critical_enhanced|custom",
        "reasoning": "explanation for workflow recommendation",
        "priority_level": "1|2|3|4 (1=highest)",
        "estimated_processing_time": "estimated time in minutes",
        "resource_requirements": ["required analyst skills or tools"],
        "automation_opportunities": ["steps suitable for automation"]
    }},
    "processing_metadata": {{
        "normalization_confidence": "confidence in normalization quality",
        "extraction_accuracy": "accuracy of field extraction",
        "enhancement_applied": ["enhancements applied to original data"],
        "quality_score": "overall alert quality score 0.0-1.0",
        "confidence_score": "confidence in analysis 0.0-1.0"
    }}
}}

Provide a comprehensive, intelligent normalization of the alert data with detailed insights and recommendations for optimal SOC processing."""
        )
        
        logger.info("AI Alert Receiver LLM capabilities initialized")
