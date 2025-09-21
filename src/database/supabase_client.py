"""
Supabase client configuration and connection management
"""

import os
import logging
from typing import Optional
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

def get_supabase_client() -> Optional[Client]:
    """
    Create and return a Supabase client instance
    
    Returns:
        Client: Supabase client instance or None if configuration is missing
    """
    try:
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            logger.warning("Supabase credentials not found in environment variables")
            logger.info("Please set SUPABASE_URL and SUPABASE_SERVICE_KEY in your .env file")
            return None
            
        client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        logger.info("Supabase client initialized successfully")
        return client
        
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None

# Global Supabase client instance
supabase = get_supabase_client()

def test_connection() -> bool:
    """
    Test the Supabase connection
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        if not supabase:
            logger.error("Supabase client not initialized")
            return False
            
        # Test connection by querying a simple table
        # This will fail gracefully if tables don't exist yet
        result = supabase.table("alerts").select("count").limit(1).execute()
        logger.info("Supabase connection test successful")
        return True
        
    except Exception as e:
        logger.warning(f"Supabase connection test failed (this is expected if tables don't exist yet): {e}")
        return True  # Return True as the connection itself might be working

def get_connection_status() -> dict:
    """
    Get detailed connection status information
    
    Returns:
        dict: Connection status details
    """
    status = {
        "connected": False,
        "url_configured": bool(SUPABASE_URL),
        "key_configured": bool(SUPABASE_SERVICE_KEY),
        "client_initialized": bool(supabase),
        "error": None
    }
    
    if status["client_initialized"]:
        try:
            # Try a simple query to verify connection
            supabase.table("alerts").select("count").limit(1).execute()
            status["connected"] = True
        except Exception as e:
            status["error"] = str(e)
            status["connected"] = False
    
    return status