"""
True Orchestrator Agent - Central workflow management and coordination
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass

from coral_protocol.agent_base import CoralAgent
from coral_protocol.message_types import CoralMessage, MessageType, MessagePriority, AgentCapability
from coral_protocol.orchestration_types import (
    OrchestrationMessageType, WorkflowState, AgentTask, WorkflowDefinition,
    WorkflowStep, AgentStatus, OrchestrationCommand, AgentTaskType, TaskStatus
)
from llm.agent_base import LLMAgentBase
from utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class WorkflowExecution:
    """Represents an active workflow execution"""
    workflow_id: str
    workflow_definition: WorkflowDefinition
    current_step: int
    status: WorkflowState
    agent_tasks: Dict[str, AgentTask]
    context: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class OrchestratorAgent(LLMAgentBase):
    """
    True Orchestrator Agent - Central workflow management and coordination
    
    This agent:
    1. Receives workflow initiation requests
    2. Manages workflow state and execution
    3. Assigns tasks to appropriate agents
    4. Monitors agent progress and status
    5. Handles workflow routing and decision making
    6. Coordinates multi-agent collaboration
    """
    
    def __init__(self, agent_id: str = "alert_triage_system", **kwargs):
        # Define capabilities for the orchestrator
        capabilities = [
            AgentCapability(
                name="orchestrate_workflow",
                description="Orchestrate and manage workflow execution",
                input_schema={
                    "type": "object",
                    "properties": {
                        "workflow_type": {"type": "string"},
                        "context": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "workflow_id": {"type": "string"},
                        "status": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id=agent_id,
            agent_name="True Orchestrator AI",
            capabilities=capabilities,
            **kwargs
        )
        
        # Workflow management
        self.active_workflows: Dict[str, WorkflowExecution] = {}
        self.agent_registry: Dict[str, AgentStatus] = {}
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        
        # Initialize default workflow definitions
        self._initialize_default_workflows()
        
        # Register message handlers
        self._register_message_handlers()
    
    async def setup_llm_capabilities(self):
        """Setup LLM capabilities for the orchestrator"""
        # Orchestrator doesn't need specific LLM prompts as it coordinates tasks
        pass
    
    async def handle_message(self, message: CoralMessage) -> CoralMessage:
        """Handle incoming messages"""
        # This method is called by the base class for message processing
        # The specific handlers are registered in _register_message_handlers
        
        # Check if we have a specific handler for this message type
        if message.message_type in self._message_handlers:
            return await self._message_handlers[message.message_type](message)
        else:
            # Default handling - create a response
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.RESPONSE,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={
                    "status": "received",
                    "message": "Message received by orchestrator"
                },
                priority=MessagePriority.NORMAL,
                timestamp=datetime.utcnow()
            )
    
    def _initialize_default_workflows(self):
        """Initialize default workflow definitions for alert triage"""
        
        # Alert Triage Workflow
        alert_triage_workflow = WorkflowDefinition(
            workflow_id="alert_triage",
            name="Alert Triage Workflow",
            description="Complete alert triage and response workflow",
            steps=[
                WorkflowStep(
                    step_id="alert_reception",
                    agent_type="alert_receiver_ai",
                    task_name="process_alert",
                    description="Receive and normalize incoming alert",
                    dependencies=[],
                    timeout_seconds=30
                ),
                WorkflowStep(
                    step_id="false_positive_check",
                    agent_type="false_positive_checker_ai", 
                    task_name="check_false_positive",
                    description="Check if alert is false positive",
                    dependencies=["alert_reception"],
                    timeout_seconds=60
                ),
                WorkflowStep(
                    step_id="severity_analysis",
                    agent_type="severity_analyzer_ai",
                    task_name="analyze_severity",
                    description="Analyze alert severity and priority",
                    dependencies=["false_positive_check"],
                    timeout_seconds=45
                ),
                WorkflowStep(
                    step_id="context_gathering",
                    agent_type="context_gatherer_ai",
                    task_name="gather_context",
                    description="Gather additional context and intelligence",
                    dependencies=["severity_analysis"],
                    timeout_seconds=90
                ),
                WorkflowStep(
                    step_id="response_coordination",
                    agent_type="response_coordinator_ai",
                    task_name="coordinate_response",
                    description="Coordinate appropriate response actions",
                    dependencies=["context_gathering"],
                    timeout_seconds=120
                )
            ],
            max_parallel_steps=2,
            retry_policy={
                "max_retries": 3,
                "retry_delay": 5,
                "exponential_backoff": True
            }
        )
        
        self.workflow_definitions["alert_triage"] = alert_triage_workflow
    
    async def initialize(self):
        """Initialize the orchestrator agent"""
        logger.info("Initializing True Orchestrator Agent AI...")
        
        # Initialize LLM capabilities if available
        await self.initialize_llm()
        
        # Set status to online
        self.status = "online"
        
        logger.info("True Orchestrator Agent AI initialized successfully")
    
    def _register_message_handlers(self):
        """Register message handlers for orchestration commands"""
        
        # Register handler for COMMAND messages (which contain orchestration commands)
        self.register_message_handler(
            MessageType.COMMAND,
            self._handle_command_message
        )
        
        # Register handler for RESPONSE messages (which contain task completion notifications)
        self.register_message_handler(
            MessageType.RESPONSE,
            self._handle_response_message
        )
        
        # Store orchestration handlers in a separate dictionary
        self._orchestration_handlers = {
            OrchestrationMessageType.ORCHESTRATE_WORKFLOW: self._handle_orchestrate_workflow,
            OrchestrationMessageType.WORKFLOW_PAUSE: self._handle_workflow_pause,
            OrchestrationMessageType.WORKFLOW_RESUME: self._handle_workflow_resume,
            OrchestrationMessageType.WORKFLOW_CANCEL: self._handle_workflow_cancel,
            OrchestrationMessageType.AGENT_TASK_COMPLETE: self._handle_agent_task_complete,
            OrchestrationMessageType.AGENT_TASK_FAIL: self._handle_agent_task_fail,
            OrchestrationMessageType.AGENT_STATUS_RESPONSE: self._handle_agent_status_update,
            OrchestrationMessageType.AGENT_HEARTBEAT: self._handle_agent_heartbeat
        }
    
    async def _handle_command_message(self, message: CoralMessage) -> CoralMessage:
        """Handle COMMAND messages and route to appropriate orchestration handlers"""
        try:
            logger.info(f"Orchestrator received COMMAND message: {message.id}")
            logger.info(f"Message payload: {message.payload}")
            
            # Extract the orchestration message type from the payload
            message_type_str = message.payload.get("message_type")
            if not message_type_str:
                logger.error("No message_type found in COMMAND payload")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": "No message_type in command payload"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
            
            # Convert string to OrchestrationMessageType
            try:
                orchestration_type = OrchestrationMessageType(message_type_str)
            except ValueError:
                logger.error(f"Unknown orchestration message type: {message_type_str}")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": f"Unknown message type: {message_type_str}"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
            
            # Route to appropriate handler
            if orchestration_type in self._orchestration_handlers:
                return await self._orchestration_handlers[orchestration_type](message)
            else:
                logger.error(f"No handler for orchestration type: {orchestration_type}")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": f"No handler for {orchestration_type}"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            logger.error(f"Error handling command message: {e}")
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.ERROR,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={"error": str(e)},
                priority=MessagePriority.HIGH,
                timestamp=datetime.utcnow()
            )
    
    async def _handle_response_message(self, message: CoralMessage) -> CoralMessage:
        """Handle RESPONSE messages and route to appropriate orchestration handlers"""
        try:
            logger.info(f"Orchestrator received RESPONSE message: {message.id}")
            logger.info(f"Message payload: {message.payload}")
            
            # Extract the orchestration message type from the payload
            message_type_str = message.payload.get("message_type")
            if not message_type_str:
                logger.error("No message_type found in RESPONSE payload")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": "No message_type in response payload"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
            
            # Convert string to OrchestrationMessageType
            try:
                orchestration_type = OrchestrationMessageType(message_type_str)
            except ValueError:
                logger.error(f"Unknown orchestration message type: {message_type_str}")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": f"Unknown message type: {message_type_str}"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
            
            # Route to appropriate handler
            if orchestration_type in self._orchestration_handlers:
                return await self._orchestration_handlers[orchestration_type](message)
            else:
                logger.error(f"No handler for orchestration type: {orchestration_type}")
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={"error": f"No handler for {orchestration_type}"},
                    priority=MessagePriority.HIGH,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            logger.error(f"Error handling command message: {e}")
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.ERROR,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={"error": str(e)},
                priority=MessagePriority.HIGH,
                timestamp=datetime.utcnow()
            )
    
    async def _handle_orchestrate_workflow(self, message: CoralMessage) -> CoralMessage:
        """Handle workflow orchestration request"""
        try:
            workflow_type = message.payload.get("workflow_type", "alert_triage")
            context = message.payload.get("context", {})
            
            # Create new workflow execution
            workflow_execution = await self._create_workflow_execution(workflow_type, context)
            
            # Start workflow execution
            await self._start_workflow_execution(workflow_execution.workflow_id)
            
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.RESPONSE,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={
                    "status": "success",
                    "workflow_id": workflow_execution.workflow_id,
                    "message": "Workflow orchestration initiated successfully"
                },
                priority=MessagePriority.HIGH,
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error(f"Error orchestrating workflow: {e}")
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.ERROR,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={
                    "status": "error",
                    "error": str(e)
                },
                priority=MessagePriority.HIGH,
                timestamp=datetime.utcnow()
            )
    
    async def _create_workflow_execution(self, workflow_type: str, context: Dict[str, Any]) -> WorkflowExecution:
        """Create a new workflow execution"""
        
        if workflow_type not in self.workflow_definitions:
            raise ValueError(f"Unknown workflow type: {workflow_type}")
        
        workflow_definition = self.workflow_definitions[workflow_type]
        workflow_id = str(uuid.uuid4())
        
        workflow_execution = WorkflowExecution(
            workflow_id=workflow_id,
            workflow_definition=workflow_definition,
            current_step=0,
            status=WorkflowState.PENDING,
            agent_tasks={},
            context=context,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        self.active_workflows[workflow_id] = workflow_execution
        logger.info(f"Created workflow execution: {workflow_id}")
        
        return workflow_execution
    
    async def _start_workflow_execution(self, workflow_id: str):
        """Start executing a workflow"""
        
        if workflow_id not in self.active_workflows:
            raise ValueError(f"Workflow not found: {workflow_id}")
        
        workflow = self.active_workflows[workflow_id]
        workflow.status = WorkflowState.RUNNING
        
        # Execute the first step(s)
        await self._execute_workflow_step(workflow_id)
        
        logger.info(f"Started workflow execution: {workflow_id}")
    
    async def _execute_workflow_step(self, workflow_id: str):
        """Execute the next step(s) in a workflow"""
        
        workflow = self.active_workflows[workflow_id]
        if workflow.status != WorkflowState.RUNNING:
            return
        
        # Find next executable steps
        next_steps = self._get_next_executable_steps(workflow)
        
        if not next_steps:
            # Workflow completed
            workflow.status = WorkflowState.COMPLETED
            logger.info(f"Workflow completed: {workflow_id}")
            return
        
        # Execute steps in parallel (up to max_parallel_steps)
        max_parallel = workflow.workflow_definition.max_parallel_steps
        steps_to_execute = next_steps[:max_parallel]
        
        for step in steps_to_execute:
            await self._assign_agent_task(workflow_id, step)
    
    def _get_next_executable_steps(self, workflow: WorkflowExecution) -> List[WorkflowStep]:
        """Get the next executable steps in a workflow"""
        
        executable_steps = []
        current_step = workflow.current_step
        
        for step in workflow.workflow_definition.steps:
            # Check if step is ready to execute
            if self._is_step_ready(workflow, step):
                executable_steps.append(step)
        
        return executable_steps
    
    def _is_step_ready(self, workflow: WorkflowExecution, step: WorkflowStep) -> bool:
        """Check if a step is ready to execute"""
        
        # Check if all dependencies are completed
        for dep_step_id in step.dependencies:
            if not self._is_step_completed(workflow, dep_step_id):
                return False
        
        # Check if step is not already running or completed
        if step.step_id in workflow.agent_tasks:
            task = workflow.agent_tasks[step.step_id]
            if task.status in [AgentStatus.RUNNING, AgentStatus.COMPLETED]:
                return False
        
        return True
    
    def _is_step_completed(self, workflow: WorkflowExecution, step_id: str) -> bool:
        """Check if a step is completed"""
        
        if step_id not in workflow.agent_tasks:
            return False
        
        task = workflow.agent_tasks[step_id]
        return task.status == AgentStatus.COMPLETED
    
    async def _assign_agent_task(self, workflow_id: str, step: WorkflowStep):
        """Assign a task to an agent"""
        
        workflow = self.active_workflows[workflow_id]
        
        # Create agent task
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            agent_id=step.agent_type,
            task_type=AgentTaskType.NORMALIZE_ALERT,  # Default task type
            payload={
                "step_id": step.step_id,
                "task_name": step.task_name,
                "description": step.description,
                "context": workflow.context
            },
            workflow_id=workflow_id,
            orchestrator_id=self.agent_id,
            priority=MessagePriority.HIGH,
            timeout=step.timeout_seconds,
            created_at=datetime.utcnow(),
            status=TaskStatus.PENDING
        )
        
        workflow.agent_tasks[step.step_id] = task
        
        # Send task assignment message to agent
        task_message = CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.COMMAND,
            sender_id=self.agent_id,
            receiver_id=step.agent_type,
            thread_id=workflow_id,
            payload={
                "command": "execute_task",
                "task": task.to_dict(),
                "workflow_context": workflow.context
            },
            priority=MessagePriority.HIGH,
            timestamp=datetime.utcnow()
        )
        
        await self.send_message(task_message)
        logger.info(f"Assigned task {task.task_id} to {step.agent_type}")
    
    async def _handle_agent_task_complete(self, message: CoralMessage) -> CoralMessage:
        """Handle agent task completion"""
        
        task_id = message.payload.get("task_id")
        result = message.payload.get("result", {})
        
        # Find the workflow and task
        workflow_id = None
        for workflow in self.active_workflows.values():
            for task in workflow.agent_tasks.values():
                if task.task_id == task_id:
                    workflow_id = workflow.workflow_id
                    task.status = AgentStatus.COMPLETED
                    task.result = result
                    task.completed_at = datetime.utcnow()
                    break
        
        if workflow_id:
            # Update workflow context with task result
            workflow = self.active_workflows[workflow_id]
            workflow.context.update(result)
            workflow.updated_at = datetime.utcnow()
            
            # Continue workflow execution
            await self._execute_workflow_step(workflow_id)
            
            logger.info(f"Task completed: {task_id}")
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "acknowledged"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_agent_task_fail(self, message: CoralMessage) -> CoralMessage:
        """Handle agent task failure"""
        
        task_id = message.payload.get("task_id")
        error = message.payload.get("error", "Unknown error")
        
        # Find the workflow and task
        workflow_id = None
        for workflow in self.active_workflows.values():
            for task in workflow.agent_tasks.values():
                if task.task_id == task_id:
                    workflow_id = workflow.workflow_id
                    task.status = AgentStatus.FAILED
                    task.error = error
                    task.failed_at = datetime.utcnow()
                    break
        
        if workflow_id:
            # Handle retry logic
            await self._handle_task_retry(workflow_id, task_id)
            
            logger.error(f"Task failed: {task_id} - {error}")
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "acknowledged"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_task_retry(self, workflow_id: str, task_id: str):
        """Handle task retry logic"""
        
        workflow = self.active_workflows[workflow_id]
        retry_policy = workflow.workflow_definition.retry_policy
        
        # Find the task
        task = None
        for t in workflow.agent_tasks.values():
            if t.task_id == task_id:
                task = t
                break
        
        if not task:
            return
        
        # Check retry count
        if task.retry_count >= retry_policy["max_retries"]:
            # Max retries exceeded, fail workflow
            workflow.status = WorkflowState.FAILED
            logger.error(f"Workflow failed after max retries: {workflow_id}")
            return
        
        # Increment retry count and reset status
        task.retry_count += 1
        task.status = AgentStatus.PENDING
        task.retry_delay = retry_policy["retry_delay"]
        
        if retry_policy["exponential_backoff"]:
            task.retry_delay *= (2 ** (task.retry_count - 1))
        
        # Schedule retry
        await asyncio.sleep(task.retry_delay)
        await self._assign_agent_task(workflow_id, workflow.workflow_definition.steps[workflow.current_step])
    
    async def _handle_workflow_pause(self, message: CoralMessage) -> CoralMessage:
        """Handle workflow pause request"""
        
        workflow_id = message.payload.get("workflow_id")
        
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            workflow.status = WorkflowState.PAUSED
            workflow.updated_at = datetime.utcnow()
            
            logger.info(f"Workflow paused: {workflow_id}")
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "paused"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_workflow_resume(self, message: CoralMessage) -> CoralMessage:
        """Handle workflow resume request"""
        
        workflow_id = message.payload.get("workflow_id")
        
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            workflow.status = WorkflowState.RUNNING
            workflow.updated_at = datetime.utcnow()
            
            # Continue execution
            await self._execute_workflow_step(workflow_id)
            
            logger.info(f"Workflow resumed: {workflow_id}")
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "resumed"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_workflow_cancel(self, message: CoralMessage) -> CoralMessage:
        """Handle workflow cancellation request"""
        
        workflow_id = message.payload.get("workflow_id")
        
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            workflow.status = WorkflowState.CANCELLED
            workflow.updated_at = datetime.utcnow()
            
            # Cancel all running tasks
            for task in workflow.agent_tasks.values():
                if task.status == AgentStatus.RUNNING:
                    task.status = AgentStatus.CANCELLED
                    task.cancelled_at = datetime.utcnow()
            
            logger.info(f"Workflow cancelled: {workflow_id}")
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "cancelled"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_agent_status_update(self, message: CoralMessage) -> CoralMessage:
        """Handle agent status updates"""
        
        agent_id = message.payload.get("agent_id")
        status = message.payload.get("status")
        
        if agent_id:
            self.agent_registry[agent_id] = AgentStatus(
                agent_id=agent_id,
                status=status,
                last_heartbeat=datetime.utcnow(),
                capabilities=message.payload.get("capabilities", []),
                current_tasks=message.payload.get("current_tasks", [])
            )
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "acknowledged"},
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_agent_heartbeat(self, message: CoralMessage) -> CoralMessage:
        """Handle agent heartbeat"""
        
        agent_id = message.payload.get("agent_id")
        
        if agent_id and agent_id in self.agent_registry:
            self.agent_registry[agent_id].last_heartbeat = datetime.utcnow()
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={"status": "acknowledged"},
            priority=MessagePriority.LOW,
            timestamp=datetime.utcnow()
        )
    
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get current status of a workflow"""
        
        if workflow_id not in self.active_workflows:
            return {"error": "Workflow not found"}
        
        workflow = self.active_workflows[workflow_id]
        
        return {
            "workflow_id": workflow_id,
            "status": workflow.status.value,
            "current_step": workflow.current_step,
            "total_steps": len(workflow.workflow_definition.steps),
            "agent_tasks": {task_id: task.to_dict() for task_id, task in workflow.agent_tasks.items()},
            "context": workflow.context,
            "created_at": workflow.created_at.isoformat(),
            "updated_at": workflow.updated_at.isoformat()
        }
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        
        # Get agent count from Coral registry if available
        coral_agent_count = 0
        if self.coral_registry:
            coral_agent_count = len(self.coral_registry.agents)
        
        return {
            "active_workflows": len(self.active_workflows),
            "registered_agents": coral_agent_count,
            "workflow_definitions": list(self.workflow_definitions.keys()),
            "agent_status": {agent_id: agent.to_dict() for agent_id, agent in self.agent_registry.items()},
            "coral_agents": list(self.coral_registry.agents.keys()) if self.coral_registry else []
        }
