"""
Task Executor Base Class - Base class for agents that execute tasks in orchestrated workflows
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from coral_protocol.agent_base import CoralAgent
from coral_protocol.message_types import CoralMessage, MessageType, MessagePriority, AgentCapability
from coral_protocol.orchestration_types import (
    OrchestrationMessageType, AgentTask, WorkflowState, TaskStatus
)
from coral_protocol.message_types import AgentStatus
from llm.agent_base import LLMAgentBase
from utils.logging_config import get_logger

logger = get_logger(__name__)


class TaskExecutorBase(LLMAgentBase):
    """
    Base class for agents that execute tasks in orchestrated workflows
    
    This class provides:
    1. Task execution framework
    2. Status reporting to orchestrator
    3. Heartbeat mechanism
    4. Error handling and retry logic
    5. Result reporting
    """
    
    def __init__(self, agent_id: str, **kwargs):
        # Define basic capabilities for task executors
        capabilities = [
            AgentCapability(
                name="execute_task",
                description="Execute assigned tasks from orchestrator",
                input_schema={
                    "type": "object",
                    "properties": {
                        "task": {"type": "object"},
                        "workflow_context": {"type": "object"}
                    }
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "result": {"type": "object"},
                        "status": {"type": "string"}
                    }
                }
            )
        ]
        
        super().__init__(
            agent_id=agent_id,
            agent_name=f"Task Executor {agent_id}",
            capabilities=capabilities,
            **kwargs
        )
        
        # Task management
        self.current_tasks: Dict[str, AgentTask] = {}
        self.task_queue: List[AgentTask] = []
        self.max_concurrent_tasks = 1
        
        # Status tracking
        self.agent_status = AgentStatus(
            agent_id=agent_id,
            name=f"Task Executor {agent_id}",
            status="idle",
            last_heartbeat=datetime.utcnow(),
            message_queue_size=0,
            active_threads=0,
            processed_messages=0,
            error_count=0
        )
        
        # Register orchestration message handlers
        self._register_orchestration_handlers()
        
        # Start heartbeat task
        asyncio.create_task(self._heartbeat_loop())
    
    async def initialize(self):
        """Initialize the task executor agent"""
        logger.info(f"Initializing Task Executor Agent: {self.agent_id}")
        
        # Initialize LLM capabilities if available
        if hasattr(self, 'initialize_llm'):
            await self.initialize_llm()
        
        # Set status to online
        self.status = "online"
        
        logger.info(f"Task Executor Agent {self.agent_id} initialized successfully")
    
    def _get_capabilities(self) -> List[str]:
        """Override in subclasses to define agent capabilities"""
        return []
    
    def _register_orchestration_handlers(self):
        """Register handlers for orchestration messages"""
        
        # Task management handlers
        self.register_message_handler(
            MessageType.COMMAND,
            self._handle_task_command
        )
        
        # Status management handlers - these are handled through COMMAND messages
        # The specific orchestration message types are handled in the command handler
    
    async def _handle_task_command(self, message: CoralMessage) -> CoralMessage:
        """Handle task execution commands from orchestrator"""
        
        try:
            command = message.payload.get("command")
            
            if command == "execute_task":
                task_data = message.payload.get("task")
                workflow_context = message.payload.get("workflow_context", {})
                
                # Create task object
                if not task_data:
                    raise ValueError("No task data provided")
                task = AgentTask.from_dict(task_data)
                task.status = TaskStatus.PENDING
                
                # Add to task queue
                self.task_queue.append(task)
                
                # Process task if we have capacity
                if len(self.current_tasks) < self.max_concurrent_tasks:
                    await self._process_next_task()
                
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.RESPONSE,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={
                        "status": "accepted",
                        "task_id": task.task_id,
                        "message": "Task accepted for execution"
                    },
                    priority=MessagePriority.NORMAL,
                    timestamp=datetime.utcnow()
                )
            
            elif command == "cancel_task":
                task_id = message.payload.get("task_id")
                if not task_id:
                    raise ValueError("No task_id provided for cancel_task command")
                await self._cancel_task(task_id)
                
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.RESPONSE,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={
                        "status": "cancelled",
                        "task_id": task_id
                    },
                    priority=MessagePriority.NORMAL,
                    timestamp=datetime.utcnow()
                )
            
            else:
                return CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.agent_id,
                    receiver_id=message.sender_id,
                    thread_id=message.thread_id,
                    payload={
                        "status": "error",
                        "error": f"Unknown command: {command}"
                    },
                    priority=MessagePriority.NORMAL,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            logger.error(f"Error handling task command: {e}")
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
    
    async def _process_next_task(self):
        """Process the next task in the queue"""
        
        if not self.task_queue or len(self.current_tasks) >= self.max_concurrent_tasks:
            return
        
        task = self.task_queue.pop(0)
        self.current_tasks[task.task_id] = task
        
        # Update status
        self.agent_status.status = "busy"
        
        # Start task execution
        asyncio.create_task(self._execute_task(task))
    
    async def _execute_task(self, task: AgentTask):
        """Execute a task (to be implemented by subclasses)"""
        
        try:
            # Update task status
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            
            # Execute the specific task logic
            result = await self._execute_task_logic(task)
            
            # Mark task as completed
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.utcnow()
            
            # Remove from current tasks
            if task.task_id in self.current_tasks:
                del self.current_tasks[task.task_id]
            
            # Update agent status
            if not self.current_tasks:
                self.agent_status.status = "idle"
            
            # Report completion to orchestrator
            await self._report_task_completion(task)
            
            # Process next task if available
            await self._process_next_task()
            
        except Exception as e:
            logger.error(f"Error executing task {task.task_id}: {e}")
            
            # Mark task as failed
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.failed_at = datetime.utcnow()
            
            # Remove from current tasks
            if task.task_id in self.current_tasks:
                del self.current_tasks[task.task_id]
            
            # Update agent status
            if not self.current_tasks:
                self.agent_status.status = "idle"
            
            # Report failure to orchestrator
            await self._report_task_failure(task, str(e))
            
            # Process next task if available
            await self._process_next_task()
    
    async def _execute_task_logic(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute the specific task logic (to be implemented by subclasses)
        
        Args:
            task: The task to execute
            
        Returns:
            Dict containing the task result
        """
        raise NotImplementedError("Subclasses must implement _execute_task_logic")
    
    async def _cancel_task(self, task_id: str):
        """Cancel a running task"""
        
        if task_id in self.current_tasks:
            task = self.current_tasks[task_id]
            task.status = TaskStatus.CANCELLED
            task.cancelled_at = datetime.utcnow()
            
            # Remove from current tasks
            del self.current_tasks[task_id]
            
            # Update agent status
            if not self.current_tasks:
                self.agent_status.status = "idle"
            
            logger.info(f"Task cancelled: {task_id}")
        
        # Also remove from queue if present
        self.task_queue = [task for task in self.task_queue if task.task_id != task_id]
    
    async def _report_task_completion(self, task: AgentTask):
        """Report task completion to orchestrator"""
        
        completion_message = CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id="alert_triage_system",
            thread_id=task.workflow_id,
            payload={
                "message_type": OrchestrationMessageType.AGENT_TASK_COMPLETE.value,
                "task_id": task.task_id,
                "workflow_id": task.workflow_id,
                "result": task.result,
                "status": "completed"
            },
            priority=MessagePriority.HIGH,
            timestamp=datetime.utcnow()
        )
        
        await self.send_message(completion_message)
        logger.info(f"Reported task completion: {task.task_id}")
    
    async def _report_task_failure(self, task: AgentTask, error: str):
        """Report task failure to orchestrator"""
        
        failure_message = CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id="alert_triage_system",
            thread_id=task.workflow_id,
            payload={
                "message_type": OrchestrationMessageType.AGENT_TASK_FAIL.value,
                "task_id": task.task_id,
                "workflow_id": task.workflow_id,
                "error": error,
                "status": "failed"
            },
            priority=MessagePriority.HIGH,
            timestamp=datetime.utcnow()
        )
        
        await self.send_message(failure_message)
        logger.error(f"Reported task failure: {task.task_id} - {error}")
    
    async def _handle_status_request(self, message: CoralMessage) -> CoralMessage:
        """Handle status request from orchestrator"""
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={
                "message_type": "agent_status_update",
                "agent_id": self.agent_id,
                "status": self.agent_status.status,
                "capabilities": self._get_capabilities(),
                "current_tasks": [task.task_id for task in self.current_tasks.values()],
                "last_heartbeat": self.agent_status.last_heartbeat.isoformat()
            },
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
    
    async def _handle_heartbeat_request(self, message: CoralMessage) -> CoralMessage:
        """Handle heartbeat request from orchestrator"""
        
        self.agent_status.last_heartbeat = datetime.utcnow()
        
        return CoralMessage(
            id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE,
            sender_id=self.agent_id,
            receiver_id=message.sender_id,
            thread_id=message.thread_id,
            payload={
                "message_type": "agent_heartbeat",
                "agent_id": self.agent_id,
                "timestamp": self.agent_status.last_heartbeat.isoformat()
            },
            priority=MessagePriority.LOW,
            timestamp=datetime.utcnow()
        )
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to orchestrator"""
        
        while True:
            try:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
                heartbeat_message = CoralMessage(
                    id=str(uuid.uuid4()),
                    message_type=MessageType.RESPONSE,
                    sender_id=self.agent_id,
                    receiver_id="alert_triage_system",
                    thread_id="heartbeat",
                    payload={
                        "message_type": "agent_heartbeat",
                        "agent_id": self.agent_id,
                        "status": self.agent_status.status,
                        "current_tasks": [task.task_id for task in self.current_tasks.values()],
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    priority=MessagePriority.LOW,
                    timestamp=datetime.utcnow()
                )
                
                await self.send_message(heartbeat_message)
                
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")
    
    async def handle_message(self, message: CoralMessage) -> CoralMessage:
        """Handle incoming messages - required by CoralAgent base class"""
        
        # Check if we have a specific handler for this message type
        if message.message_type in self._message_handlers:
            return await self._message_handlers[message.message_type](message)
        else:
            # Default handling - create a simple response
            return CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.RESPONSE,
                sender_id=self.agent_id,
                receiver_id=message.sender_id,
                thread_id=message.thread_id,
                payload={
                    "status": "received",
                    "message": f"Message received by {self.agent_id}"
                },
                priority=MessagePriority.NORMAL,
                timestamp=datetime.utcnow()
            )
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        
        return {
            "agent_id": self.agent_id,
            "status": self.agent_status.status,
            "capabilities": self._get_capabilities(),
            "current_tasks": [task.task_id for task in self.current_tasks.values()],
            "task_queue_length": len(self.task_queue),
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "last_heartbeat": self.agent_status.last_heartbeat.isoformat()
        }
