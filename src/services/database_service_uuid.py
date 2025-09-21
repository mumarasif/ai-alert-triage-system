"""
Database service layer for Supabase operations - UUID Version
Handles all database interactions for the AI Alert Triage System
Updated to work with UUID primary keys
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from src.database.supabase_client import supabase

logger = logging.getLogger(__name__)

class DatabaseService:
    """
    Service class for database operations using Supabase
    
    This service provides methods for:
    - Alert management (create, update, retrieve)
    - AI analysis storage and retrieval
    - Agent status tracking
    - System metrics collection
    - Workflow state management
    """
    
    def __init__(self):
        self.supabase = supabase
        self.connection_healthy = self._test_connection()
        
    def _test_connection(self) -> bool:
        """Test database connection"""
        try:
            if not self.supabase:
                logger.warning("Supabase client not available")
                return False
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def _ensure_connection(self) -> bool:
        """Ensure database connection is available"""
        return self.connection_healthy and self.supabase is not None
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create new alert in database
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Dict containing created alert data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping alert creation")
                return None
                
            # Ensure required fields are present
            alert_record = {
                "alert_id": alert_data.get("alert_id"),
                "type": alert_data.get("type", "unknown"),
                "description": alert_data.get("description", ""),
                "source_ip": alert_data.get("source_ip"),
                "destination_ip": alert_data.get("destination_ip"),
                "user_id": alert_data.get("user_id"),
                "hostname": alert_data.get("hostname"),
                "severity": alert_data.get("severity", "medium"),
                "status": alert_data.get("status", "processing"),
                "source_system": alert_data.get("source_system", "unknown"),
                "raw_data": alert_data.get("raw_data", {}),
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            result = self.supabase.table("alerts").insert(alert_record).execute()  # type: ignore
            
            if result.data:
                logger.info(f"Alert created successfully: {alert_record['alert_id']}")
                return result.data[0]
            else:
                logger.error("Failed to create alert - no data returned")
                return None
                
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    async def update_alert_status(self, alert_id: str, status: str, additional_data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Update alert status and additional data
        
        Args:
            alert_id: Alert identifier
            status: New status
            additional_data: Additional fields to update
            
        Returns:
            Dict containing updated alert data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping alert update")
                return None
                
            update_data = {
                "status": status,
                "updated_at": datetime.now().isoformat()
            }
            
            if additional_data:
                update_data.update(additional_data)
            
            result = self.supabase.table("alerts").update(update_data).eq("alert_id", alert_id).execute()  # type: ignore
            
            if result.data:
                logger.info(f"Alert status updated: {alert_id} -> {status}")
                return result.data[0]
            else:
                logger.warning(f"No alert found with ID: {alert_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return None
    
    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get alert by ID
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Dict containing alert data or None if not found
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve alert")
                return None
                
            result = self.supabase.table("alerts").select("*").eq("alert_id", alert_id).execute()  # type: ignore
            
            if result.data:
                return result.data[0]
            else:
                logger.warning(f"Alert not found: {alert_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving alert: {e}")
            return None
    
    async def get_alerts(self, limit: int = 50, offset: int = 0, status: str = None) -> List[Dict[str, Any]]:
        """
        Get alerts with pagination and optional status filter
        
        Args:
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip
            status: Optional status filter
            
        Returns:
            List of alert dictionaries
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve alerts")
                return []
                
            query = self.supabase.table("alerts").select("*")
            
            if status:
                query = query.eq("status", status)
                
            result = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()  # type: ignore
            
            return result.data if result.data else []
            
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
    
    async def save_ai_analysis(self, alert_id: str, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Save AI analysis results for an alert
        
        Args:
            alert_id: Alert identifier
            analysis: AI analysis results
            
        Returns:
            Dict containing saved analysis data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping AI analysis save")
                return None
                
            # Get internal alert ID (UUID)
            alert = self.supabase.table("alerts").select("id").eq("alert_id", alert_id).execute()  # type: ignore
            if not alert.data:
                logger.error(f"Alert not found for analysis: {alert_id}")
                return None
                
            analysis_data = {
                "alert_id": alert.data[0]["id"],  # This is now a UUID
                "false_positive_probability": analysis.get("false_positive_probability"),
                "severity_score": analysis.get("severity_score"),
                "context_data": analysis.get("context_data", {}),
                "recommended_actions": analysis.get("recommended_actions", []),
                "agent_results": analysis.get("agent_results", {}),
                "confidence_score": analysis.get("confidence_score"),
                "processing_time_ms": analysis.get("processing_time_ms"),
                "created_at": datetime.now().isoformat()
            }
            
            result = self.supabase.table("ai_analysis").insert(analysis_data).execute()  # type: ignore
            
            if result.data:
                logger.info(f"AI analysis saved for alert: {alert_id}")
                return result.data[0]
            else:
                logger.error("Failed to save AI analysis - no data returned")
                return None
                
        except Exception as e:
            logger.error(f"Error saving AI analysis: {e}")
            return None
    
    async def get_ai_analysis(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get AI analysis for an alert
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Dict containing analysis data or None if not found
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve AI analysis")
                return None
                
            # Get internal alert ID first
            alert = self.supabase.table("alerts").select("id").eq("alert_id", alert_id).execute()  # type: ignore
            if not alert.data:
                return None
                
            result = self.supabase.table("ai_analysis").select("*").eq("alert_id", alert.data[0]["id"]).execute()  # type: ignore
            
            if result.data:
                return result.data[0]
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving AI analysis: {e}")
            return None
    
    async def update_agent_status(self, agent_name: str, status_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update agent status information
        
        Args:
            agent_name: Name of the agent
            status_data: Status information to update
            
        Returns:
            Dict containing updated status data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping agent status update")
                return None
                
            status_record = {
                "agent_name": agent_name,
                **status_data,
                "updated_at": datetime.now().isoformat()
            }
            
            # Use upsert to create or update
            result = self.supabase.table("agent_status").upsert(status_record).execute()  # type: ignore
            
            if result.data:
                logger.debug(f"Agent status updated: {agent_name}")
                return result.data[0]
            else:
                logger.error("Failed to update agent status - no data returned")
                return None
                
        except Exception as e:
            logger.error(f"Error updating agent status: {e}")
            return None
    
    async def get_agent_status(self, agent_name: str = None) -> List[Dict[str, Any]]:
        """
        Get agent status information
        
        Args:
            agent_name: Optional specific agent name filter
            
        Returns:
            List of agent status records
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve agent status")
                return []
                
            query = self.supabase.table("agent_status").select("*")
            
            if agent_name:
                query = query.eq("agent_name", agent_name)
                
            result = query.execute()  # type: ignore
            
            return result.data if result.data else []
            
        except Exception as e:
            logger.error(f"Error retrieving agent status: {e}")
            return []
    
    async def save_metrics(self, metric_name: str, value: float, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Save system metrics
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            metadata: Optional metadata dictionary
            
        Returns:
            Dict containing saved metric data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping metrics save")
                return None
                
            metric_record = {
                "metric_name": metric_name,
                "metric_value": value,
                "metadata": metadata or {},
                "timestamp": datetime.now().isoformat()
            }
            
            result = self.supabase.table("system_metrics").insert(metric_record).execute()  # type: ignore
            
            if result.data:
                logger.debug(f"Metric saved: {metric_name} = {value}")
                return result.data[0]
            else:
                logger.error("Failed to save metric - no data returned")
                return None
                
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")
            return None
    
    async def get_metrics(self, metric_name: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get system metrics
        
        Args:
            metric_name: Optional specific metric name filter
            hours: Number of hours to look back
            
        Returns:
            List of metric records
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve metrics")
                return []
                
            since_time = datetime.now() - timedelta(hours=hours)
            
            query = self.supabase.table("system_metrics").select("*").gte("timestamp", since_time.isoformat())
            
            if metric_name:
                query = query.eq("metric_name", metric_name)
                
            result = query.order("timestamp", desc=True).execute()  # type: ignore
            
            return result.data if result.data else []
            
        except Exception as e:
            logger.error(f"Error retrieving metrics: {e}")
            return []
    
    async def save_workflow_state(self, workflow_id: str, state_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Save workflow state information
        
        Args:
            workflow_id: Workflow identifier
            state_data: Workflow state data
            
        Returns:
            Dict containing saved state data or None if failed
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, skipping workflow state save")
                return None
                
            state_record = {
                "workflow_id": workflow_id,
                **state_data,
                "updated_at": datetime.now().isoformat()
            }
            
            result = self.supabase.table("workflow_states").upsert(state_record).execute()  # type: ignore
            
            if result.data:
                logger.debug(f"Workflow state saved: {workflow_id}")
                return result.data[0]
            else:
                logger.error("Failed to save workflow state - no data returned")
                return None
                
        except Exception as e:
            logger.error(f"Error saving workflow state: {e}")
            return None
    
    async def get_workflow_state(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get workflow state information
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            Dict containing workflow state or None if not found
        """
        try:
            if not self._ensure_connection():
                logger.warning("Database not available, cannot retrieve workflow state")
                return None
                
            result = self.supabase.table("workflow_states").select("*").eq("workflow_id", workflow_id).execute()  # type: ignore
            
            if result.data:
                return result.data[0]
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving workflow state: {e}")
            return None
    
    def is_healthy(self) -> bool:
        """
        Check if database service is healthy
        
        Returns:
            bool: True if healthy, False otherwise
        """
        return self.connection_healthy and self.supabase is not None

# Global database service instance
db_service = DatabaseService()
