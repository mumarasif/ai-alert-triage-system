"""
FastAPI routes for the AI Alert Triage System
Provides REST API endpoints for frontend integration
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, Query, Path
from fastapi.middleware.cors import CORSMiddleware

from services.database_service import db_service
from database.supabase_client import get_connection_status

logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    """
    Create and configure FastAPI application
    
    Returns:
        FastAPI: Configured FastAPI application
    """
    app = FastAPI(
        title="AI Alert Triage System API",
        description="AI-powered security alert processing system with Supabase integration",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Enable CORS for frontend integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for your specific frontend domain in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    return app

# Create the app instance
app = create_app()

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    
    Returns:
        Dict: Health status information
    """
    try:
        # Check database connection
        db_status = get_connection_status()
        
        health_status = {
            "status": "healthy" if db_status["connected"] else "degraded",
            "timestamp": datetime.now().isoformat(),
            "system": "ai_alert_triage_system",
            "version": "2.0.0",
            "database": {
                "connected": db_status["connected"],
                "url_configured": db_status["url_configured"],
                "key_configured": db_status["key_configured"]
            }
        }
        
        if not db_status["connected"]:
            health_status["warnings"] = ["Database connection not available"]
            if db_status["error"]:
                health_status["database"]["error"] = db_status["error"]
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=1000, description="Number of alerts to return"),
    offset: int = Query(0, ge=0, description="Number of alerts to skip"),
    status: Optional[str] = Query(None, description="Filter by alert status")
):
    """
    Get alerts with pagination and optional filtering
    
    Args:
        limit: Maximum number of alerts to return
        offset: Number of alerts to skip
        status: Optional status filter
        
    Returns:
        Dict: Paginated alerts data
    """
    try:
        alerts = await db_service.get_alerts(limit=limit, offset=offset, status=status)
        
        # Get total count for pagination
        total_count = len(await db_service.get_alerts(limit=10000))  # Get approximate total
        
        return {
            "data": alerts,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": total_count,
                "has_more": len(alerts) == limit
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/alerts/{alert_id}")
async def get_alert_details(
    alert_id: str = Path(..., description="Alert identifier")
):
    """
    Get detailed information about a specific alert
    
    Args:
        alert_id: Alert identifier
        
    Returns:
        Dict: Alert details including AI analysis
    """
    try:
        # Get alert data
        alert = await db_service.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Get AI analysis if available
        analysis = await db_service.get_ai_analysis(alert_id)
        
        response = {
            "alert": alert,
            "ai_analysis": analysis,
            "timestamp": datetime.now().isoformat()
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str = Path(..., description="Alert identifier"),
    status_data: Dict[str, Any] = None
):
    """
    Update alert status and additional data
    
    Args:
        alert_id: Alert identifier
        status_data: Status update data
        
    Returns:
        Dict: Updated alert data
    """
    try:
        if not status_data:
            raise HTTPException(status_code=400, detail="Status data is required")
        
        status = status_data.get("status")
        if not status:
            raise HTTPException(status_code=400, detail="Status field is required")
        
        updated_alert = await db_service.update_alert_status(
            alert_id=alert_id,
            status=status,
            additional_data=status_data
        )
        
        if not updated_alert:
            raise HTTPException(status_code=404, detail="Alert not found or update failed")
        
        return {
            "alert": updated_alert,
            "message": "Alert status updated successfully",
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents/status")
async def get_agent_status(
    agent_name: Optional[str] = Query(None, description="Specific agent name filter")
):
    """
    Get agent status information
    
    Args:
        agent_name: Optional specific agent name filter
        
    Returns:
        Dict: Agent status information
    """
    try:
        agents = await db_service.get_agent_status(agent_name=agent_name)
        
        return {
            "agents": agents,
            "count": len(agents),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/metrics")
async def get_system_metrics(
    metric_name: Optional[str] = Query(None, description="Specific metric name filter"),
    hours: int = Query(24, ge=1, le=168, description="Hours to look back (1-168)")
):
    """
    Get system metrics
    
    Args:
        metric_name: Optional specific metric name filter
        hours: Number of hours to look back
        
    Returns:
        Dict: System metrics data
    """
    try:
        metrics = await db_service.get_metrics(metric_name=metric_name, hours=hours)
        
        # Aggregate metrics for dashboard
        aggregated_metrics = {}
        for metric in metrics:
            name = metric["metric_name"]
            if name not in aggregated_metrics:
                aggregated_metrics[name] = {
                    "values": [],
                    "latest_value": None,
                    "count": 0
                }
            
            aggregated_metrics[name]["values"].append({
                "value": metric["metric_value"],
                "timestamp": metric["timestamp"],
                "metadata": metric.get("metadata", {})
            })
            aggregated_metrics[name]["count"] += 1
            aggregated_metrics[name]["latest_value"] = metric["metric_value"]
        
        return {
            "metrics": aggregated_metrics,
            "period_hours": hours,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/workflows/{workflow_id}")
async def get_workflow_status(
    workflow_id: str = Path(..., description="Workflow identifier")
):
    """
    Get workflow status information
    
    Args:
        workflow_id: Workflow identifier
        
    Returns:
        Dict: Workflow status data
    """
    try:
        workflow_state = await db_service.get_workflow_state(workflow_id)
        
        if not workflow_state:
            raise HTTPException(status_code=404, detail="Workflow not found")
        
        return {
            "workflow": workflow_state,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving workflow status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard/summary")
async def get_dashboard_summary():
    """
    Get dashboard summary data
    
    Returns:
        Dict: Summary data for dashboard
    """
    try:
        # Get recent alerts
        recent_alerts = await db_service.get_alerts(limit=10)
        
        # Get agent status
        agents = await db_service.get_agent_status()
        
        # Get recent metrics
        recent_metrics = await db_service.get_metrics(hours=1)
        
        # Calculate summary statistics
        alert_counts = {}
        for alert in recent_alerts:
            status = alert.get("status", "unknown")
            alert_counts[status] = alert_counts.get(status, 0) + 1
        
        active_agents = len([agent for agent in agents if agent.get("status") == "active"])
        
        return {
            "summary": {
                "total_alerts": len(recent_alerts),
                "alert_counts_by_status": alert_counts,
                "active_agents": active_agents,
                "total_agents": len(agents),
                "recent_metrics_count": len(recent_metrics)
            },
            "recent_alerts": recent_alerts[:5],  # Last 5 alerts
            "agent_status": agents,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving dashboard summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/alerts/{alert_id}/analysis")
async def save_alert_analysis(
    alert_id: str = Path(..., description="Alert identifier"),
    analysis_data: Dict[str, Any] = None
):
    """
    Save AI analysis for an alert
    
    Args:
        alert_id: Alert identifier
        analysis_data: AI analysis results
        
    Returns:
        Dict: Saved analysis data
    """
    try:
        if not analysis_data:
            raise HTTPException(status_code=400, detail="Analysis data is required")
        
        saved_analysis = await db_service.save_ai_analysis(
            alert_id=alert_id,
            analysis=analysis_data
        )
        
        if not saved_analysis:
            raise HTTPException(status_code=404, detail="Alert not found or analysis save failed")
        
        return {
            "analysis": saved_analysis,
            "message": "AI analysis saved successfully",
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving alert analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/database/status")
async def get_database_status():
    """
    Get detailed database connection status
    
    Returns:
        Dict: Database status information
    """
    try:
        status = get_connection_status()
        return {
            "database_status": status,
            "service_healthy": db_service.is_healthy(),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error retrieving database status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
