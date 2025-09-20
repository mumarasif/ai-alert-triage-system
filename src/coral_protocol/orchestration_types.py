"""
Orchestration-specific message types and data structures for Coral Protocol
"""

import datetime
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Any, Optional, List, Union
from .message_types import CoralMessage, MessageType, MessagePriority


class OrchestrationMessageType(Enum):
    """Orchestration-specific message types extending Coral Protocol"""
    
    # Orchestrator Commands
    ORCHESTRATE_WORKFLOW = "orchestrate_workflow"
    WORKFLOW_START = "workflow_start"
    WORKFLOW_PAUSE = "workflow_pause"
    WORKFLOW_RESUME = "workflow_resume"
    WORKFLOW_CANCEL = "workflow_cancel"
    
    # Agent Task Management
    AGENT_TASK_ASSIGN = "agent_task_assign"
    AGENT_TASK_START = "agent_task_start"
    AGENT_TASK_COMPLETE = "agent_task_complete"
    AGENT_TASK_FAIL = "agent_task_fail"
    AGENT_TASK_RETRY = "agent_task_retry"
    
    # Agent Coordination
    AGENT_STATUS_REQUEST = "agent_status_request"
    AGENT_STATUS_RESPONSE = "agent_status_response"
    AGENT_CAPABILITY_REQUEST = "agent_capability_request"
    AGENT_CAPABILITY_RESPONSE = "agent_capability_response"
    AGENT_HEARTBEAT = "agent_heartbeat"
    
    # Workflow State Management
    WORKFLOW_STATE_UPDATE = "workflow_state_update"
    WORKFLOW_STEP_COMPLETE = "workflow_step_complete"
    WORKFLOW_STEP_FAIL = "workflow_step_fail"
    WORKFLOW_COMPLETE = "workflow_complete"
    WORKFLOW_ERROR = "workflow_error"
    
    # Routing and Decision Making
    ROUTING_DECISION_REQUEST = "routing_decision_request"
    ROUTING_DECISION_RESPONSE = "routing_decision_response"
    WORKFLOW_PLAN_REQUEST = "workflow_plan_request"
    WORKFLOW_PLAN_RESPONSE = "workflow_plan_response"


class WorkflowState(Enum):
    """Workflow execution states"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    BUSY = "busy"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class OrchestrationCommand:
    """Command sent to orchestrator"""
    command_type: OrchestrationMessageType
    workflow_id: Optional[str] = None
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    parameters: Dict[str, Any] = None
    timestamp: datetime.datetime = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.timestamp is None:
            self.timestamp = datetime.datetime.utcnow()


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class WorkflowStatus(Enum):
    """Workflow execution status"""
    INITIALIZED = "initialized"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentTaskType(Enum):
    """Types of tasks that can be assigned to agents"""
    NORMALIZE_ALERT = "normalize_alert"
    VALIDATE_ALERT = "validate_alert"
    CHECK_FALSE_POSITIVE = "check_false_positive"
    ANALYZE_SEVERITY = "analyze_severity"
    GATHER_CONTEXT = "gather_context"
    COORDINATE_RESPONSE = "coordinate_response"
    CREATE_INCIDENT = "create_incident"
    EXECUTE_AUTOMATION = "execute_automation"


@dataclass
class AgentTask:
    """Task assigned to an agent by the orchestrator"""
    task_id: str
    agent_id: str
    task_type: AgentTaskType
    payload: Dict[str, Any]
    workflow_id: str
    orchestrator_id: str
    priority: MessagePriority = MessagePriority.NORMAL
    timeout: int = 300  # seconds
    retry_count: int = 0
    max_retries: int = 3
    dependencies: List[str] = None  # task_ids this task depends on
    created_at: datetime.datetime = None
    assigned_at: Optional[datetime.datetime] = None
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    failed_at: Optional[datetime.datetime] = None
    cancelled_at: Optional[datetime.datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.created_at is None:
            self.created_at = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization"""
        return {
            'task_id': self.task_id,
            'agent_id': self.agent_id,
            'task_type': self.task_type.value,
            'payload': self.payload,
            'workflow_id': self.workflow_id,
            'orchestrator_id': self.orchestrator_id,
            'priority': self.priority.value,
            'timeout': self.timeout,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'dependencies': self.dependencies,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'failed_at': self.failed_at.isoformat() if self.failed_at else None,
            'cancelled_at': self.cancelled_at.isoformat() if self.cancelled_at else None,
            'status': self.status.value,
            'result': self.result,
            'error': self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentTask':
        """Create task from dictionary"""
        # Convert string values back to enums and datetime objects
        data['task_type'] = AgentTaskType(data['task_type'])
        data['priority'] = MessagePriority(data['priority'])
        data['status'] = TaskStatus(data['status'])
        
        # Convert datetime strings back to datetime objects
        if data.get('created_at'):
            data['created_at'] = datetime.datetime.fromisoformat(data['created_at'])
        if data.get('assigned_at'):
            data['assigned_at'] = datetime.datetime.fromisoformat(data['assigned_at'])
        if data.get('started_at'):
            data['started_at'] = datetime.datetime.fromisoformat(data['started_at'])
        if data.get('completed_at'):
            data['completed_at'] = datetime.datetime.fromisoformat(data['completed_at'])
        if data.get('failed_at'):
            data['failed_at'] = datetime.datetime.fromisoformat(data['failed_at'])
        if data.get('cancelled_at'):
            data['cancelled_at'] = datetime.datetime.fromisoformat(data['cancelled_at'])
        
        return cls(**data)


@dataclass
class AgentTaskResult:
    """Result returned by an agent after completing a task"""
    result_id: str
    task_id: str
    agent_id: str
    workflow_id: str
    success: bool
    result_data: Dict[str, Any]
    error_message: Optional[str] = None
    execution_time: float = 0.0
    confidence_score: float = 0.0
    metadata: Dict[str, Any] = None
    completed_at: datetime.datetime = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.completed_at is None:
            self.completed_at = datetime.datetime.now()


@dataclass
class WorkflowStep:
    """Individual step in a workflow execution plan"""
    step_id: str
    step_name: str
    agent_id: str
    task_type: AgentTaskType
    payload: Dict[str, Any]
    dependencies: List[str] = None
    timeout: int = 300
    retry_count: int = 0
    max_retries: int = 3
    parallel_group: Optional[str] = None
    quality_gates: List[str] = None
    fallback_agent: Optional[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.quality_gates is None:
            self.quality_gates = []


@dataclass
class WorkflowExecutionPlan:
    """Complete execution plan for a workflow"""
    plan_id: str
    workflow_id: str
    steps: List[WorkflowStep]
    parallel_groups: List[str] = None
    estimated_duration: int = 0  # seconds
    success_criteria: List[str] = None
    quality_gates: List[str] = None
    created_at: datetime.datetime = None
    
    def __post_init__(self):
        if self.parallel_groups is None:
            self.parallel_groups = []
        if self.success_criteria is None:
            self.success_criteria = []
        if self.quality_gates is None:
            self.quality_gates = []
        if self.created_at is None:
            self.created_at = datetime.datetime.now()


@dataclass
class WorkflowStep:
    """Individual step in a workflow definition"""
    step_id: str
    agent_type: str
    task_name: str
    description: str
    dependencies: List[str] = None
    timeout_seconds: int = 60
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class WorkflowDefinition:
    """Workflow definition template"""
    workflow_id: str
    name: str
    description: str
    steps: List[WorkflowStep]
    max_parallel_steps: int = 1
    retry_policy: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.retry_policy is None:
            self.retry_policy = {
                "max_retries": 3,
                "retry_delay": 5,
                "exponential_backoff": True
            }


@dataclass
class WorkflowInstance:
    """Active workflow instance being executed"""
    workflow_id: str
    alert_data: Dict[str, Any]
    execution_plan: WorkflowExecutionPlan
    status: WorkflowStatus = WorkflowStatus.INITIALIZED
    current_step: int = 0
    completed_steps: List[str] = None
    failed_steps: List[str] = None
    task_results: Dict[str, AgentTaskResult] = None
    created_at: datetime.datetime = None
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None
    orchestrator_id: str = "alert_triage_system"
    
    def __post_init__(self):
        if self.completed_steps is None:
            self.completed_steps = []
        if self.failed_steps is None:
            self.failed_steps = []
        if self.task_results is None:
            self.task_results = {}
        if self.created_at is None:
            self.created_at = datetime.datetime.now()


@dataclass
class OrchestrationMetrics:
    """Metrics for orchestration performance"""
    orchestrator_id: str
    active_workflows: int = 0
    completed_workflows: int = 0
    failed_workflows: int = 0
    total_tasks_assigned: int = 0
    total_tasks_completed: int = 0
    total_tasks_failed: int = 0
    average_workflow_duration: float = 0.0
    average_task_duration: float = 0.0
    agent_utilization: Dict[str, float] = None
    error_rate: float = 0.0
    
    def __post_init__(self):
        if self.agent_utilization is None:
            self.agent_utilization = {}


# Helper functions for creating orchestration messages
def create_orchestration_message(
    message_type: OrchestrationMessageType,
    sender_id: str,
    receiver_id: str,
    payload: Dict[str, Any],
    thread_id: str,
    priority: MessagePriority = MessagePriority.NORMAL,
    correlation_id: Optional[str] = None
) -> CoralMessage:
    """Create a Coral message for orchestration communication"""
    return CoralMessage(
        id=str(uuid.uuid4()),
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType(message_type.value),  # Convert to base MessageType
        thread_id=thread_id,
        payload=payload,
        timestamp=datetime.datetime.now(),
        priority=priority,
        correlation_id=correlation_id
    )


def create_agent_task_message(
    task: AgentTask,
    orchestrator_id: str
) -> CoralMessage:
    """Create a message to assign a task to an agent"""
    return create_orchestration_message(
        message_type=OrchestrationMessageType.AGENT_TASK_ASSIGN,
        sender_id=orchestrator_id,
        receiver_id=task.agent_id,
        payload={
            "task": asdict(task),
            "workflow_id": task.workflow_id
        },
        thread_id=task.workflow_id,
        priority=task.priority,
        correlation_id=task.task_id
    )


def create_task_result_message(
    result: AgentTaskResult,
    orchestrator_id: str
) -> CoralMessage:
    """Create a message to send task result back to orchestrator"""
    return create_orchestration_message(
        message_type=OrchestrationMessageType.AGENT_TASK_COMPLETE,
        sender_id=result.agent_id,
        receiver_id=orchestrator_id,
        payload={
            "result": asdict(result),
            "workflow_id": result.workflow_id
        },
        thread_id=result.workflow_id,
        correlation_id=result.task_id
    )


def create_workflow_state_message(
    workflow: WorkflowInstance,
    orchestrator_id: str,
    target_agent_id: str
) -> CoralMessage:
    """Create a message to update workflow state"""
    return create_orchestration_message(
        message_type=OrchestrationMessageType.WORKFLOW_STATE_UPDATE,
        sender_id=orchestrator_id,
        receiver_id=target_agent_id,
        payload={
            "workflow": asdict(workflow),
            "workflow_id": workflow.workflow_id
        },
        thread_id=workflow.workflow_id
    )
