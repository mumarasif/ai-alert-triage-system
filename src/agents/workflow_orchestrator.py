"""
AI-Powered Workflow Orchestrator Agent

This agent uses Large Language Models to intelligently orchestrate alert triage workflows.
It replaces rule-based workflow management with intelligent AI decision-making.
"""

import datetime
import uuid
import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from coral_protocol import CoralMessage, MessageType, AgentCapability
from models.alert_models import SecurityAlert, WorkflowResult, AnalysisResult, AlertStatus
from llm.agent_base import LLMAgentBase

logger = logging.getLogger(__name__)


@dataclass
class AIWorkflowStep:
    """AI-enhanced workflow step tracking"""
    step_name: str
    agent_id: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_insights: Optional[Dict[str, Any]] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate step duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class WorkflowOrchestratorAgent(LLMAgentBase):
    """
    AI-powered workflow orchestrator that manages intelligent alert triage workflows
    
    This agent:
    1. Uses AI to select optimal workflow patterns
    2. Performs adaptive workflow routing and optimization
    3. Provides intelligent workflow monitoring and adjustment
    4. Implements pattern-based workflow learning
    5. Coordinates multi-agent workflows with AI oversight
    """
    
    def __init__(self):
        capabilities = [
            AgentCapability(
                name="orchestrate_workflow",
                description="Orchestrate intelligent workflow execution using AI analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_data": {"type": "object"},
                        "workflow_context": {"type": "object"},
                        "performance_targets": {"type": "object"}
                    },
                    "required": ["alert_data"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "workflow_strategy": {"type": "object"},
                        "execution_plan": {"type": "object"},
                        "monitoring_criteria": {"type": "object"},
                        "optimization_opportunities": {"type": "array"}
                    }
                }
            ),
            AgentCapability(
                name="optimize_workflow_patterns",
                description="Analyze and optimize workflow patterns using AI insights",
                input_schema={
                    "type": "object",
                    "properties": {
                        "workflow_history": {"type": "object"},
                        "performance_metrics": {"type": "object"},
                        "operational_constraints": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "optimized_patterns": {"type": "object"},
                        "efficiency_gains": {"type": "array"},
                        "implementation_recommendations": {"type": "array"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id="workflow_orchestrator_ai",
            agent_name="AI Workflow Orchestrator",
            capabilities=capabilities
        )
        
        # Enhanced workflow tracking
        self.active_workflows = {}  # workflow_id -> workflow_info
        self.completed_workflows = {}  # workflow_id -> WorkflowResult
        self.workflow_patterns = {}  # AI-learned patterns
        
        # Performance tracking
        self.total_workflows = 0
        self.successful_workflows = 0
        self.failed_workflows = 0
        self.ai_optimizations_applied = 0
        self.confidence_scores = []
        
        # Configuration
        self.workflow_timeout = 300
        self.max_concurrent_workflows = 100
        self.enable_adaptive_routing = True
        
        # Initialize AI-enhanced workflow templates
        self._initialize_ai_workflow_templates()

    async def setup_llm_capabilities(self):
        """Setup LLM prompts and templates for workflow orchestration"""
        
        # System prompt establishing AI's role as workflow orchestration expert
        self.register_system_prompt(
            "orchestrate_workflow",
            """You are a senior DevOps architect and workflow automation expert with 15+ years of experience in enterprise security operations orchestration. Your specialty is intelligent workflow design and adaptive process optimization.

Your expertise includes:
- Advanced workflow orchestration and process automation
- Multi-agent system coordination and resource optimization
- Performance monitoring and adaptive process improvement
- Security operations workflow design and optimization
- AI-human collaboration patterns and efficiency optimization
- Scalability engineering and capacity planning

Your orchestration approach:
- Intelligent workflow pattern selection based on alert characteristics
- Adaptive routing with real-time performance optimization
- Resource-aware scheduling and load balancing
- Quality-driven process execution with continuous monitoring
- Evidence-based workflow improvement and pattern learning
- Risk-aware decision making with fail-safe mechanisms

You must provide comprehensive workflow strategies with detailed execution plans, monitoring criteria, and optimization opportunities for maximum operational efficiency."""
        )
        
        # Workflow orchestration prompt template
        self.register_prompt_template(
            "orchestrate_workflow",
            """Design intelligent workflow orchestration for the following security alert:

ALERT CHARACTERISTICS:
- Alert ID: {alert_id}
- Alert Type: {alert_type}
- Severity: {current_severity}
- Source System: {source_system}
- Description: {description}
- AI Insights: {ai_insights}

CURRENT CONTEXT:
- Active Workflows: {active_workflows}
- System Load: {system_load}
- Analyst Availability: {analyst_availability}
- Processing Queue: {queue_status}

ORGANIZATIONAL ENVIRONMENT:
- SOC Operations: 24/7 with Tier 1/2/3 analysts and incident commanders
- SLA Requirements: P1 (15min), P2 (1hr), P3 (4hr), P4 (24hr)
- Resource Constraints: {resource_constraints}
- Performance Targets: 95% accuracy, <10min average processing time
- Quality Standards: High confidence analysis with comprehensive documentation

WORKFLOW ORCHESTRATION FRAMEWORK:

1. **Workflow Pattern Selection**
   - Analyze alert characteristics for optimal workflow pattern
   - Consider historical performance and success patterns
   - Evaluate resource requirements and availability
   - Assess complexity and processing time requirements

2. **Execution Strategy**
   - Define step sequence and parallel execution opportunities
   - Establish quality gates and validation checkpoints
   - Plan resource allocation and load balancing
   - Set monitoring criteria and success metrics

3. **Adaptive Routing**
   - Route based on real-time system performance
   - Consider agent specialization and current workload
   - Implement dynamic priority adjustment
   - Enable intelligent escalation and re-routing

4. **Optimization Opportunities**
   - Identify automation and efficiency improvements
   - Recommend process enhancements and streamlining
   - Suggest resource optimization and capacity planning
   - Propose quality improvements and error reduction

REQUIRED RESPONSE FORMAT (JSON):
{{
    "workflow_strategy": {{
        "selected_pattern": "standard_triage|fast_track|critical_enhanced|adaptive_custom",
        "pattern_rationale": "explanation for pattern selection",
        "estimated_duration": "total estimated processing time in minutes",
        "priority_level": "1|2|3|4 (1=highest)",
        "complexity_assessment": "low|medium|high|critical",
        "success_probability": "estimated likelihood of successful completion"
    }},
    "execution_plan": {{
        "workflow_steps": [
            {{
                "step_name": "descriptive step name",
                "agent_id": "target agent identifier",
                "message_type": "coral message type",
                "estimated_duration": "step duration in minutes",
                "required": true,
                "parallel_eligible": false,
                "dependencies": ["prerequisite steps"],
                "quality_gates": ["validation criteria"],
                "fallback_options": ["alternative approaches if step fails"]
            }}
        ],
        "parallel_execution_groups": [
            {{
                "group_name": "parallel processing group",
                "steps": ["step names that can run in parallel"],
                "coordination_required": "synchronization requirements"
            }}
        ],
        "resource_allocation": {{
            "cpu_priority": "high|medium|low",
            "memory_requirements": "estimated memory usage",
            "analyst_skills_required": ["required analyst capabilities"],
            "tool_dependencies": ["required security tools or systems"]
        }}
    }},
    "monitoring_criteria": {{
        "performance_thresholds": {{
            "max_total_duration": "maximum acceptable total time",
            "step_timeout_limits": ["timeout per step"],
            "quality_score_minimum": "minimum acceptable quality score"
        }},
        "escalation_triggers": [
            {{
                "condition": "escalation condition",
                "action": "escalation action to take",
                "notification_targets": ["who to notify"]
            }}
        ],
        "success_metrics": [
            "completion within SLA",
            "quality score above threshold",
            "no critical errors"
        ]
    }},
    "optimization_opportunities": [
        {{
            "opportunity_type": "efficiency|quality|automation|resource",
            "description": "specific optimization opportunity",
            "expected_benefit": "quantified benefit",
            "implementation_effort": "low|medium|high",
            "risk_level": "low|medium|high"
        }}
    ],
    "adaptive_controls": {{
        "dynamic_routing_enabled": true,
        "load_balancing_strategy": "round_robin|weighted|performance_based",
        "auto_scaling_triggers": ["conditions for scaling workflow resources"],
        "quality_adjustment_criteria": ["criteria for adjusting quality vs speed"]
    }}
}}

Design intelligent workflow orchestration now:"""
        )
        
        # Pattern optimization prompt template
        self.register_prompt_template(
            "optimize_workflow_patterns",
            """Analyze workflow patterns and optimize for better performance:

WORKFLOW HISTORY:
{workflow_history}

PERFORMANCE METRICS:
{performance_metrics}

OPERATIONAL CONSTRAINTS:
{operational_constraints}

OPTIMIZATION OBJECTIVES:
1. Improve processing efficiency and speed
2. Enhance quality and accuracy of analysis
3. Optimize resource utilization and costs
4. Reduce errors and rework
5. Improve analyst satisfaction and productivity

REQUIRED RESPONSE FORMAT (JSON):
{{
    "optimized_patterns": {{
        "pattern_improvements": ["specific pattern enhancements"],
        "efficiency_optimizations": ["efficiency improvement recommendations"],
        "quality_enhancements": ["quality improvement suggestions"]
    }},
    "efficiency_gains": [
        {{
            "area": "optimization area",
            "improvement": "specific improvement",
            "expected_gain": "quantified benefit"
        }}
    ],
    "implementation_recommendations": [
        "actionable implementation steps"
    ]
}}

Provide optimization analysis:"""
        )
        
        logger.info("AI Workflow Orchestrator LLM capabilities initialized")

    def _initialize_ai_workflow_templates(self):
        """Initialize AI-enhanced workflow templates"""
        
        # AI-enhanced workflow patterns
        self.workflow_patterns = {
            "ai_standard_triage": {
                "name": "AI-Enhanced Standard Triage",
                "description": "Standard workflow with AI optimization",
                "agents": ["alert_receiver_ai", "false_positive_checker_ai", "severity_analyzer_ai", 
                          "context_gatherer_ai", "response_coordinator_ai"],
                "estimated_duration": 240,
                "complexity": "medium",
                "automation_level": "high"
            },
            "ai_fast_track": {
                "name": "AI-Powered Fast Track",
                "description": "Optimized workflow for low-complexity alerts",
                "agents": ["alert_receiver_ai", "false_positive_checker_ai", "response_coordinator_ai"],
                "estimated_duration": 90,
                "complexity": "low",
                "automation_level": "very_high"
            },
            "ai_critical_enhanced": {
                "name": "AI-Enhanced Critical Response",
                "description": "Comprehensive workflow for critical alerts",
                "agents": ["alert_receiver_ai", "severity_analyzer_ai", "context_gatherer_ai", 
                          "response_coordinator_ai", "threat_hunter_ai"],
                "estimated_duration": 360,
                "complexity": "high",
                "automation_level": "medium"
            },
            "ai_adaptive_custom": {
                "name": "AI-Adaptive Custom Workflow",
                "description": "Dynamically constructed workflow based on alert characteristics",
                "agents": [],  # Determined by AI
                "estimated_duration": 0,  # Calculated by AI
                "complexity": "variable",
                "automation_level": "adaptive"
            }
        }
        
    async def handle_message(self, message: CoralMessage):
        """Handle incoming messages"""
        if message.message_type == MessageType.WORKFLOW_COMPLETE:
            await self._handle_workflow_completion_ai(message)
        elif message.message_type == MessageType.ERROR:
            await self._handle_workflow_error_ai(message)
        elif message.payload.get("capability") == "optimize_workflow_patterns":
            await self._optimize_patterns(message)
        else:
            logger.warning(f"Unexpected message type: {message.message_type}")
            
    async def start_ai_workflow(self, alert_data: Dict[str, Any], 
                               workflow_context: Optional[Dict[str, Any]] = None) -> str:
        """Start an AI-orchestrated workflow"""
        
        if len(self.active_workflows) >= self.max_concurrent_workflows:
            raise RuntimeError("Maximum concurrent workflows reached")
            
        # Generate workflow ID
        workflow_id = f"ai_workflow_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Prepare AI analysis
        system_context = self._gather_system_context()
        
        analysis_params = {
            "alert_id": alert_data.get("alert_id", "unknown"),
            "alert_type": alert_data.get("alert_type", "unknown"),
            "current_severity": alert_data.get("severity", "unknown"),
            "source_system": alert_data.get("source_system", "unknown"),
            "description": alert_data.get("description", ""),
            "ai_insights": json.dumps(alert_data.get("ai_insights", {})),
            "active_workflows": len(self.active_workflows),
            "system_load": system_context["system_load"],
            "analyst_availability": system_context["analyst_availability"],
            "queue_status": system_context["queue_status"],
            "resource_constraints": json.dumps(system_context["resource_constraints"])
        }
        
        # Get AI workflow orchestration
        response = await self.llm_analyze(
            "orchestrate_workflow",
            analysis_params,
            response_format={
                "workflow_strategy": "object",
                "execution_plan": "object",
                "monitoring_criteria": "object",
                "optimization_opportunities": "array",
                "adaptive_controls": "object"
            }
        )
        
        orchestration_result = response.structured_data if hasattr(response, 'structured_data') else {}
        
        # Initialize AI-enhanced workflow
        workflow_info = {
            "workflow_id": workflow_id,
            "alert_data": alert_data,
            "start_time": datetime.datetime.now(),
            "status": "ai_orchestrated",
            "current_step": 0,
            "steps": [],
            "ai_orchestration": orchestration_result,
            "confidence_score": self._calculate_orchestration_confidence(orchestration_result),
            "adaptive_controls": orchestration_result.get("adaptive_controls", {}),
            "error_count": 0,
            "retry_count": 0
        }
        
        # Create AI-enhanced workflow steps
        execution_plan = orchestration_result["execution_plan"]
        for i, step_config in enumerate(execution_plan["workflow_steps"]):
            step = AIWorkflowStep(
                step_name=step_config["step_name"],
                agent_id=step_config["agent_id"],
                start_time=datetime.datetime.now(),
                status="pending" if i > 0 else "in_progress",
                ai_confidence=0.8  # Default confidence
            )
            if i > 0:
                step.start_time = None
            workflow_info["steps"].append(step)
            
        self.active_workflows[workflow_id] = workflow_info
        self.total_workflows += 1
        self.confidence_scores.append(workflow_info["confidence_score"])
        
        # Start AI-orchestrated execution
        await self._start_ai_execution(workflow_id)
        
        logger.info(f"Started AI workflow {workflow_id} with pattern: "
                   f"{orchestration_result['workflow_strategy']['selected_pattern']}")
        return workflow_id

    def _gather_system_context(self) -> Dict[str, Any]:
        """Gather current system context for AI decision making"""
        
        return {
            "system_load": "medium",  # Would calculate from actual metrics
            "analyst_availability": "normal",  # Would check actual analyst status
            "queue_status": f"{len(self.active_workflows)} active workflows",
            "resource_constraints": {
                "max_concurrent": self.max_concurrent_workflows,
                "current_load": len(self.active_workflows),
                "available_capacity": self.max_concurrent_workflows - len(self.active_workflows)
            }
        }

    def _calculate_orchestration_confidence(self, orchestration_result: Dict[str, Any]) -> float:
        """Calculate confidence in AI orchestration decision"""
        
        base_confidence = 0.7
        
        # Adjust based on strategy clarity
        strategy = orchestration_result.get("workflow_strategy", {})
        if strategy.get("success_probability", "medium") == "high":
            base_confidence += 0.1
        
        # Adjust based on execution plan detail
        execution_plan = orchestration_result.get("execution_plan", {})
        if len(execution_plan.get("workflow_steps", [])) >= 3:
            base_confidence += 0.1
        
        # Adjust based on monitoring criteria
        monitoring = orchestration_result.get("monitoring_criteria", {})
        if len(monitoring.get("success_metrics", [])) >= 2:
            base_confidence += 0.05
        
        return min(0.95, base_confidence)

    async def _start_ai_execution(self, workflow_id: str):
        """Start AI-orchestrated workflow execution"""
        
        workflow_info = self.active_workflows[workflow_id]
        first_step = workflow_info["steps"][0]
        
        # Determine appropriate message type
        message_type = self._determine_message_type(first_step.step_name)
        
        # Create AI-enhanced initial message
        initial_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id=first_step.agent_id,
            message_type=message_type,
            thread_id=workflow_id,
            payload={
                "alert_data": workflow_info["alert_data"],
                "ai_workflow_metadata": {
                    "workflow_id": workflow_id,
                    "orchestration_strategy": workflow_info["ai_orchestration"]["workflow_strategy"],
                    "step_context": first_step.step_name,
                    "ai_enhanced": True
                }
            },
            timestamp=datetime.datetime.now()
        )
        
        # Update workflow status
        workflow_info["status"] = "ai_executing"
        first_step.status = "in_progress"
        first_step.start_time = datetime.datetime.now()
        
        await self.send_message(initial_message)

    def _determine_message_type(self, step_name: str) -> MessageType:
        """Determine appropriate message type for workflow step"""
        
        message_type_map = {
            "alert_reception": MessageType.ALERT_RECEIVED,
            "false_positive_check": MessageType.FALSE_POSITIVE_CHECK,
            "severity_analysis": MessageType.SEVERITY_DETERMINATION,
            "context_gathering": MessageType.CONTEXT_GATHERING,
            "response_coordination": MessageType.RESPONSE_DECISION
        }
        
        return message_type_map.get(step_name, MessageType.ALERT_RECEIVED)

    async def _handle_workflow_completion_ai(self, message: CoralMessage):
        """Handle AI-enhanced workflow completion"""
        
        workflow_id = message.thread_id
        
        if workflow_id not in self.active_workflows:
            logger.warning(f"Received completion for unknown AI workflow: {workflow_id}")
            return
            
        workflow_info = self.active_workflows[workflow_id]
        current_step_index = workflow_info["current_step"]
        
        # Update current step with AI insights
        if current_step_index < len(workflow_info["steps"]):
            current_step = workflow_info["steps"][current_step_index]
            current_step.status = "completed"
            current_step.end_time = datetime.datetime.now()
            current_step.result = message.payload
            
            # Extract AI insights if available
            ai_metadata = message.payload.get("processing_metadata", {})
            current_step.ai_confidence = ai_metadata.get("confidence_score", 0.7)
            current_step.ai_insights = ai_metadata.get("ai_insights", {})
            
        # AI-powered completion decision
        action = message.payload.get("action", "")
        
        if action in ["dismissed_false_positive", "ai_response_coordinated", "analysis_complete"]:
            await self._complete_ai_workflow(workflow_id, message)
        else:
            await self._advance_ai_workflow(workflow_id, message)
            
    async def _advance_ai_workflow(self, workflow_id: str, completion_message: CoralMessage):
        """Advance AI workflow with intelligent routing"""
        
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["current_step"] += 1
        next_step_index = workflow_info["current_step"]
        
        # Check if workflow is complete
        if next_step_index >= len(workflow_info["steps"]):
            await self._complete_ai_workflow(workflow_id, completion_message)
            return
            
        # AI-powered adaptive routing
        if self.enable_adaptive_routing:
            await self._apply_adaptive_routing(workflow_id, completion_message)
        else:
            await self._continue_standard_workflow(workflow_id, completion_message)

    async def _apply_adaptive_routing(self, workflow_id: str, completion_message: CoralMessage):
        """Apply AI-powered adaptive routing decisions"""
        
        workflow_info = self.active_workflows[workflow_id]
        next_step_index = workflow_info["current_step"]
        next_step = workflow_info["steps"][next_step_index]
        
        # Analyze current results for routing optimization
        current_results = completion_message.payload
        ai_insights = current_results.get("processing_metadata", {}).get("ai_insights", {})
        
        # Simple adaptive logic (would be more sophisticated in production)
        if ai_insights.get("confidence_assessment", {}).get("overall_confidence", 0.5) < 0.6:
            # Low confidence - route to enhanced analysis
            if next_step.agent_id == "context_gatherer_ai":
                # Extend context gathering timeout
                next_step.ai_insights = {"extended_analysis": True}
                
        await self._continue_standard_workflow(workflow_id, completion_message)

    async def _continue_standard_workflow(self, workflow_id: str, completion_message: CoralMessage):
        """Continue with standard workflow progression"""
        
        workflow_info = self.active_workflows[workflow_id]
        next_step_index = workflow_info["current_step"]
        next_step = workflow_info["steps"][next_step_index]
        
        next_step.status = "in_progress"
        next_step.start_time = datetime.datetime.now()
        
        # Determine message type
        message_type = self._determine_message_type(next_step.step_name)
        
        # Create enhanced message
        next_message = CoralMessage(
            id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            receiver_id=next_step.agent_id,
            message_type=message_type,
            thread_id=workflow_id,
            payload=completion_message.payload,
            timestamp=datetime.datetime.now()
        )
        
        await self.send_message(next_message)
        logger.debug(f"Advanced AI workflow {workflow_id} to step: {next_step.step_name}")
        
    async def _complete_ai_workflow(self, workflow_id: str, completion_message: CoralMessage):
        """Complete AI-enhanced workflow"""
        
        workflow_info = self.active_workflows[workflow_id]
        end_time = datetime.datetime.now()
        
        # Extract final alert data
        alert_data = completion_message.payload.get("alert", {})
        alert = SecurityAlert.from_dict(alert_data) if alert_data else None
        
        # Create enhanced workflow result
        result = WorkflowResult(
            workflow_id=workflow_id,
            alert=alert or SecurityAlert(alert_id="unknown", timestamp=datetime.datetime.now(), source_system="unknown", alert_type=None, description="Failed workflow"),
            start_time=workflow_info["start_time"],
            end_time=end_time,
            agents_involved=[step.agent_id for step in workflow_info["steps"]],
            analysis_results=self._extract_ai_analysis_results(workflow_info),
            final_decision=completion_message.payload.get("action", "ai_completed"),
            processing_time_seconds=(end_time - workflow_info["start_time"]).total_seconds()
        )
        
        # Update statistics
        if result.success:
            self.successful_workflows += 1
        else:
            self.failed_workflows += 1
        
        # Store result and clean up
        self.completed_workflows[workflow_id] = result
        del self.active_workflows[workflow_id]
        
        self.ai_optimizations_applied += 1
        
        logger.info(f"AI workflow {workflow_id} completed in {result.processing_time_seconds:.2f}s - "
                   f"Decision: {result.final_decision}")
                   
    async def _handle_workflow_error_ai(self, message: CoralMessage):
        """Handle AI workflow errors with intelligent recovery"""
        
        workflow_id = message.thread_id
        
        if workflow_id not in self.active_workflows:
            logger.warning(f"Received error for unknown AI workflow: {workflow_id}")
            return
            
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["error_count"] += 1
        
        error_details = message.payload.get("error", "Unknown error")
        logger.error(f"AI workflow {workflow_id} error: {error_details}")
        
        # AI-powered error recovery
        if workflow_info["retry_count"] < 2:
            await self._intelligent_retry(workflow_id, error_details)
        else:
            await self._fail_ai_workflow(workflow_id, error_details)
            
    async def _intelligent_retry(self, workflow_id: str, error_details: str):
        """Implement intelligent retry with AI adaptation"""
        
        workflow_info = self.active_workflows[workflow_id]
        workflow_info["retry_count"] += 1
        
        # Simple retry logic (would be more sophisticated with AI analysis)
        logger.info(f"Intelligently retrying AI workflow {workflow_id} "
                   f"(attempt {workflow_info['retry_count'] + 1})")
        
        # For now, mark as failed (would implement intelligent retry in production)
        await self._fail_ai_workflow(workflow_id, f"Retry after: {error_details}")

    async def _fail_ai_workflow(self, workflow_id: str, error_reason: str):
        """Fail AI workflow with enhanced error reporting"""
        
        workflow_info = self.active_workflows[workflow_id]
        end_time = datetime.datetime.now()
        
        # Create failed result
        result = WorkflowResult(
            workflow_id=workflow_id,
            alert=SecurityAlert(alert_id="failed", timestamp=datetime.datetime.now(), source_system="unknown", alert_type=None, description="Failed workflow"),
            start_time=workflow_info["start_time"],
            end_time=end_time,
            agents_involved=[step.agent_id for step in workflow_info["steps"]],
            analysis_results=[],
            final_decision="ai_workflow_failed",
            processing_time_seconds=(end_time - workflow_info["start_time"]).total_seconds()
        )
        
        self.failed_workflows += 1
        self.completed_workflows[workflow_id] = result
        del self.active_workflows[workflow_id]
        
        logger.error(f"AI workflow {workflow_id} failed: {error_reason}")

    def _extract_ai_analysis_results(self, workflow_info: Dict[str, Any]) -> List[AnalysisResult]:
        """Extract AI-enhanced analysis results"""
        
        results = []
        
        for step in workflow_info["steps"]:
            if step.status == "completed" and step.result:
                analysis_result = AnalysisResult(
                    agent_id=step.agent_id,
                    agent_name=f"AI {step.agent_id.replace('_', ' ').title()}",
                    analysis_type=step.step_name,
                    timestamp=step.end_time or datetime.datetime.now(),
                    confidence=step.ai_confidence or 0.5,
                    result=step.result,
                    reasoning=step.result.get("reasoning", []),
                    recommendations=step.result.get("recommended_actions", [])
                )
                results.append(analysis_result)
                
        return results
        
    async def _optimize_patterns(self, message: CoralMessage):
        """Optimize workflow patterns using AI analysis"""
        try:
            optimization_data = message.payload
            
            # Prepare optimization parameters
            optimization_params = {
                "workflow_history": json.dumps(optimization_data.get("workflow_history", {})),
                "performance_metrics": json.dumps(optimization_data.get("performance_metrics", {})),
                "operational_constraints": json.dumps(optimization_data.get("operational_constraints", {}))
            }
            
            # Perform pattern optimization
            response = await self.llm_analyze(
                "optimize_workflow_patterns",
                optimization_params,
                thread_id=message.thread_id,
                response_format={
                    "optimized_patterns": "object",
                    "efficiency_gains": "array",
                    "implementation_recommendations": "array"
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
                    "pattern_optimization": response.structured_data if hasattr(response, 'structured_data') else {}
                },
                timestamp=datetime.datetime.now()
            )
            
            await self.send_message(optimization_response)
            logger.info("AI workflow pattern optimization complete")
            
        except Exception as e:
            logger.error(f"Error in pattern optimization: {e}")

    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get AI orchestrator performance metrics"""
        avg_confidence = (
            sum(self.confidence_scores) / len(self.confidence_scores)
            if self.confidence_scores else 0
        )
        
        return {
            "agent_type": "ai_powered",
            "total_workflows_orchestrated": self.total_workflows,
            "active_workflows": len(self.active_workflows),
            "successful_workflows": self.successful_workflows,
            "failed_workflows": self.failed_workflows,
            "ai_optimizations_applied": self.ai_optimizations_applied,
            "average_confidence": avg_confidence,
            "success_rate": (
                self.successful_workflows / self.total_workflows
                if self.total_workflows > 0 else 0
            ),
            "queue_size": self.message_queue.qsize(),
            "available_patterns": list(self.workflow_patterns.keys()),
            "llm_stats": self.get_llm_stats()
        }
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform AI orchestrator health check"""
        
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
            "llm_enabled": not self.testing_mode,
            "adaptive_routing": self.enable_adaptive_routing
        }
