#!/usr/bin/env python3
"""
Alert Triage System - Orchestrated Version Main Entry Point
"""

import asyncio
import sys
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List
import json
import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv

# Load .env file at startup
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv(env_path)
    logging.info(f"Loaded environment variables from {env_path}")
else:
    logging.warning("No .env file found - using system environment variables only")

# Third-party imports  
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

# Import Coral Protocol components
from coral_protocol import CoralRegistry, CoralMessage, MessageType, MessagePriority, OrchestrationMessageType

# Import orchestrated agents
from agents.orchestrator import OrchestratorAgent
from agents.alert_receiver import AlertReceiverAgent
from agents.false_positive_checker import FalsePositiveCheckerAgent
from agents.severity_analyzer import SeverityAnalyzerAgent
from agents.context_gatherer import ContextGathererAgent
from agents.response_coordinator import ResponseCoordinatorAgent

# Import configuration and utilities
from utils.logging_config import setup_logging
from utils.config_loader import load_config
from utils.metrics_collector import MetricsCollector

# Import database and API components
from services.database_service import db_service
from api.routes import app as api_routes_app

logger = logging.getLogger(__name__)

# Global system instance
system_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    global system_instance
    
    # Startup
    config = load_config("config/default.yaml")
    system_instance = OrchestratedAlertTriageSystem(config)
    await system_instance.initialize()
    
    logger.info("Orchestrated Alert Triage System started successfully!")
    logger.info("Webhook endpoint: http://localhost:8080/webhook/alert")
    logger.info("Health endpoint: http://localhost:8080/health")
    logger.info("Metrics endpoint: http://localhost:8080/metrics")
    logger.info("Workflow status endpoint: http://localhost:8080/workflow/status/{workflow_id}")
    
    yield
    
    # Shutdown
    if system_instance:
        await system_instance.shutdown()

# FastAPI app - integrate with database API routes
app = FastAPI(
    title="Orchestrated Alert Triage System API",
    description="AI-powered security alert processing system with true orchestration and Supabase integration",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://f9864b46-7f81-4309-94ac-cf5c65160a9c.lovableproject.com",  # ← Correct domain
        "http://localhost:3000",  # For local development
        "http://localhost:8080",  # For local API testing
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],  # ← Added PATCH
    allow_headers=["*"],
)

# Include API routes from routes.py
app.include_router(api_routes_app.router)
class OrchestratedAlertTriageSystem:
    """Main orchestrated system with true workflow orchestration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry = CoralRegistry()
        self.agents = []
        self.orchestrator = None
        self.metrics = MetricsCollector()
        self.running = False
        
    async def initialize(self):
        """Initialize all system components with orchestration"""
        logger.info("Initializing Orchestrated Alert Triage System...")
        
        try:
            # Coral Registry is ready to use (no initialization needed)
            logger.info("Coral Registry ready")
            
            # Initialize Orchestrator Agent (central coordinator)
            self.orchestrator = OrchestratorAgent()
            await self.orchestrator.initialize()
            self.agents.append(self.orchestrator)
            logger.info("Orchestrator Agent initialized")
            
            # Initialize Task Executor Agents
            await self._initialize_task_executors()
            
            # Register all agents with Coral Registry
            for agent in self.agents:
                await agent.register_with_coral(self.registry)
                logger.info(f"Registered agent: {agent.agent_id}")
            
            # Start agent message processing
            for agent in self.agents:
                asyncio.create_task(agent.process_messages())
                logger.info(f"Started message processing for: {agent.agent_id}")
            
            self.running = True
            logger.info("Orchestrated Alert Triage System initialized successfully!")
            
        except Exception as e:
            logger.error(f"Error initializing system: {e}")
            raise
    
    async def _initialize_task_executors(self):
        """Initialize all task executor agents"""
        
        # Alert Receiver Agent
        try:
            alert_receiver = AlertReceiverAgent()
            await alert_receiver.initialize()
            self.agents.append(alert_receiver)
            logger.info("Alert Receiver Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Alert Receiver Agent: {e}")
            raise
        
        # False Positive Checker Agent
        try:
            false_positive_checker = FalsePositiveCheckerAgent()
            await false_positive_checker.initialize()
            self.agents.append(false_positive_checker)
            logger.info("False Positive Checker Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize False Positive Checker Agent: {e}")
            raise
        
        # Severity Analyzer Agent
        try:
            severity_analyzer = SeverityAnalyzerAgent()
            await severity_analyzer.initialize()
            self.agents.append(severity_analyzer)
            logger.info("Severity Analyzer Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Severity Analyzer Agent: {e}")
            raise
        
        # Context Gatherer Agent
        try:
            context_gatherer = ContextGathererAgent()
            await context_gatherer.initialize()
            self.agents.append(context_gatherer)
            logger.info("Context Gatherer Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Context Gatherer Agent: {e}")
            raise
        
        # Response Coordinator Agent
        try:
            response_coordinator = ResponseCoordinatorAgent()
            await response_coordinator.initialize()
            self.agents.append(response_coordinator)
            logger.info("Response Coordinator Agent initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Response Coordinator Agent: {e}")
            raise
    
    async def process_alert(self, alert_data: Dict[str, Any], source_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process an alert through the orchestrated workflow
        
        Args:
            alert_data: Raw alert data from external system
            source_metadata: Metadata about the alert source
            
        Returns:
            Dict containing workflow execution results
        """
        
        try:
            logger.info(f"Processing alert through orchestrated workflow: {alert_data.get('id', 'unknown')}")
            
            # Save alert to database first
            alert_id = alert_data.get('id', alert_data.get('alert_id', str(uuid.uuid4())))
            db_alert = None
            
            try:
                db_alert = await db_service.create_alert({
                    "alert_id": alert_id,
                    "type": alert_data.get("type", "unknown"),
                    "description": alert_data.get("description", "Unknown Alert"),
                    "source_ip": alert_data.get("source_ip"),
                    "user_id": alert_data.get("user_id"),
                    "hostname": alert_data.get("hostname"),
                    "severity": alert_data.get("severity", "medium"),
                    "status": "processing",
                    "source_system": source_metadata.get("system_name", "unknown") if source_metadata else "unknown",
                    "raw_data": alert_data
                })
                
                if db_alert:
                    logger.info(f"Alert saved to database: {alert_id}")
                else:
                    logger.warning(f"Failed to save alert to database: {alert_id}")
                    
            except Exception as db_error:
                logger.error(f"Database error while saving alert: {db_error}")
                # Continue processing even if database save fails
            
            # Create workflow initiation message
            workflow_message = CoralMessage(
                id=str(uuid.uuid4()),
                message_type=MessageType.COMMAND,
                sender_id="api_webhook",
                receiver_id="alert_triage_system",
                thread_id=str(uuid.uuid4()),
                payload={
                    "message_type": OrchestrationMessageType.ORCHESTRATE_WORKFLOW.value,
                    "workflow_type": "alert_triage",
                    "context": {
                        "alert_data": alert_data,
                        "source_metadata": source_metadata or {},
                        "initiated_by": "api_webhook",
                        "initiated_at": datetime.utcnow().isoformat(),
                        "database_alert_id": db_alert.get("id") if db_alert else None
                    }
                },
                priority=MessagePriority.HIGH,
                timestamp=datetime.utcnow()
            )
            
            # Send to orchestrator
            logger.info(f"Sending workflow message to orchestrator: {workflow_message.id}")
            await self.orchestrator.send_message(workflow_message)
            
            # Call the orchestrator's workflow handler directly to get a response
            response = await self.orchestrator._handle_orchestrate_workflow(workflow_message)
            logger.info(f"Received response from orchestrator: {response}")
            
            # Check if response is valid
            if not response or not hasattr(response, 'payload'):
                logger.error("Invalid response from orchestrator")
                return {
                    "status": "error",
                    "message": "Invalid response from orchestrator",
                    "error": "No response received"
                }
            
            # Extract workflow ID from response
            workflow_id = response.payload.get("workflow_id")
            
            if workflow_id:
                logger.info(f"Alert workflow initiated: {workflow_id}")
                
                # Save workflow state to database
                try:
                    await db_service.save_workflow_state(workflow_id, {
                        "status": "initiated",
                        "alert_id": alert_id,
                        "initiated_at": datetime.utcnow().isoformat(),
                        "workflow_type": "alert_triage"
                    })
                except Exception as db_error:
                    logger.error(f"Failed to save workflow state: {db_error}")
                
                # Return workflow tracking information
                return {
                    "status": "workflow_initiated",
                    "workflow_id": workflow_id,
                    "alert_id": alert_id,
                    "message": "Alert processing workflow started",
                    "tracking_url": f"/workflow/status/{workflow_id}",
                    "database_saved": db_alert is not None
                }
            else:
                logger.error("Failed to initiate workflow")
                return {
                    "status": "error",
                    "message": "Failed to initiate alert processing workflow",
                    "error": response.payload.get("error", "Unknown error")
                }
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return {
                "status": "error",
                "message": "Error processing alert",
                "error": str(e)
            }
    
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get status of a specific workflow"""
        
        try:
            if self.orchestrator:
                return await self.orchestrator.get_workflow_status(workflow_id)
            else:
                return {"error": "Orchestrator not available"}
        except Exception as e:
            logger.error(f"Error getting workflow status: {e}")
            return {"error": str(e)}
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        
        try:
            if self.orchestrator:
                return await self.orchestrator.get_system_status()
            else:
                return {"error": "Orchestrator not available"}
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {"error": str(e)}
    
    async def shutdown(self):
        """Shutdown all system components"""
        logger.info("Shutting down Orchestrated Alert Triage System...")
        
        try:
            self.running = False
            
            # Stop all agents
            for agent in self.agents:
                if hasattr(agent, 'stop_message_processing'):
                    await agent.stop_message_processing()
                logger.info(f"Stopped agent: {agent.agent_id}")
            
            # Coral Registry doesn't need explicit shutdown
            logger.info("Coral Registry cleanup complete")
            
            logger.info("Orchestrated Alert Triage System shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")

# API Endpoints

@app.post("/webhook/alert")
async def webhook_alert(alert_data: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Webhook endpoint for receiving security alerts
    
    This endpoint receives alerts and initiates the orchestrated workflow
    """
    try:
        logger.info(f"Received alert webhook: {alert_data.get('id', 'unknown')}")
        
        # Extract source metadata
        source_metadata = {
            "system_name": alert_data.get("source_system", "unknown"),
            "received_at": datetime.utcnow().isoformat(),
            "webhook_source": "api"
        }
        
        # Process alert through orchestrated workflow
        result = await system_instance.process_alert(alert_data, source_metadata)
        
        # Log metrics
        system_instance.metrics.increment_counter("alerts_received")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in webhook endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        if system_instance and system_instance.running:
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "system": "orchestrated_alert_triage",
                "version": "2.0.0"
            }
        else:
            return {
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "system": "orchestrated_alert_triage",
                "version": "2.0.0"
            }
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@app.get("/metrics")
async def get_metrics():
    """Metrics endpoint"""
    try:
        return {
            "system_metrics": system_instance.metrics.get_metrics(),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/workflow/status/{workflow_id}")
async def get_workflow_status(workflow_id: str):
    """Get status of a specific workflow"""
    try:
        status = await system_instance.get_workflow_status(workflow_id)
        return status
    except Exception as e:
        logger.error(f"Error getting workflow status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/status")
async def get_system_status():
    """Get overall system status"""
    try:
        status = await system_instance.get_system_status()
        return status
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/workflow/pause/{workflow_id}")
async def pause_workflow(workflow_id: str):
    """Pause a running workflow"""
    try:
        # Send pause command to orchestrator
        pause_message = CoralMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.COMMAND,
            sender_id="api",
            receiver_id="alert_triage_system",
            payload={
                "message_type": OrchestrationMessageType.WORKFLOW_PAUSE.value,
                "workflow_id": workflow_id
            },
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
        
        response = await system_instance.orchestrator.send_message(pause_message)
        return response.payload
        
    except Exception as e:
        logger.error(f"Error pausing workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/workflow/resume/{workflow_id}")
async def resume_workflow(workflow_id: str):
    """Resume a paused workflow"""
    try:
        # Send resume command to orchestrator
        resume_message = CoralMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.COMMAND,
            sender_id="api",
            receiver_id="alert_triage_system",
            payload={
                "message_type": OrchestrationMessageType.WORKFLOW_RESUME.value,
                "workflow_id": workflow_id
            },
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
        
        response = await system_instance.orchestrator.send_message(resume_message)
        return response.payload
        
    except Exception as e:
        logger.error(f"Error resuming workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/workflow/cancel/{workflow_id}")
async def cancel_workflow(workflow_id: str):
    """Cancel a running workflow"""
    try:
        # Send cancel command to orchestrator
        cancel_message = CoralMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.COMMAND,
            sender_id="api",
            receiver_id="alert_triage_system",
            payload={
                "message_type": OrchestrationMessageType.WORKFLOW_CANCEL.value,
                "workflow_id": workflow_id
            },
            priority=MessagePriority.NORMAL,
            timestamp=datetime.utcnow()
        )
        
        response = await system_instance.orchestrator.send_message(cancel_message)
        return response.payload
        
    except Exception as e:
        logger.error(f"Error cancelling workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Setup logging
    config = load_config("config/default.yaml")
    setup_logging(config.get("logging", {}))
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
