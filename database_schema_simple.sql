-- Database Schema Update Script - Simple Version
-- This script updates existing tables to match the application requirements

-- =============================================================================
-- Step 1: Check existing tables and their structure
-- =============================================================================
SELECT table_name, column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name IN ('alerts', 'ai_analysis', 'agent_status', 'system_metrics')
ORDER BY table_name, ordinal_position;

-- =============================================================================
-- Step 2: Add missing columns to existing tables
-- =============================================================================

-- Update alerts table to add missing columns
DO $$ 
BEGIN
    -- Add source_system column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alerts' AND column_name = 'source_system') THEN
        ALTER TABLE alerts ADD COLUMN source_system VARCHAR(100) DEFAULT 'unknown';
    END IF;
    
    -- Add destination_ip column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alerts' AND column_name = 'destination_ip') THEN
        ALTER TABLE alerts ADD COLUMN destination_ip INET;
    END IF;
    
    -- Add hostname column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alerts' AND column_name = 'hostname') THEN
        ALTER TABLE alerts ADD COLUMN hostname VARCHAR(255);
    END IF;
    
    -- Update severity constraint to include more values
    IF EXISTS (SELECT 1 FROM information_schema.check_constraints 
               WHERE constraint_name LIKE '%alerts_severity%') THEN
        ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_severity_check;
    END IF;
    ALTER TABLE alerts ADD CONSTRAINT alerts_severity_check 
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
    
    -- Update status constraint to include more values
    IF EXISTS (SELECT 1 FROM information_schema.check_constraints 
               WHERE constraint_name LIKE '%alerts_status%') THEN
        ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_status_check;
    END IF;
    ALTER TABLE alerts ADD CONSTRAINT alerts_status_check 
        CHECK (status IN ('processing', 'completed', 'failed', 'pending', 'cancelled'));
END $$;

-- Update ai_analysis table to add missing columns
DO $$ 
BEGIN
    -- Add confidence_score column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ai_analysis' AND column_name = 'confidence_score') THEN
        ALTER TABLE ai_analysis ADD COLUMN confidence_score DECIMAL(3,2) 
            CHECK (confidence_score >= 0 AND confidence_score <= 1);
    END IF;
    
    -- Add processing_time_ms column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'ai_analysis' AND column_name = 'processing_time_ms') THEN
        ALTER TABLE ai_analysis ADD COLUMN processing_time_ms INTEGER;
    END IF;
    
    -- Change recommended_actions from TEXT[] to JSONB if needed
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'ai_analysis' AND column_name = 'recommended_actions' 
               AND data_type = 'ARRAY') THEN
        -- First, create a new column with JSONB type
        ALTER TABLE ai_analysis ADD COLUMN recommended_actions_jsonb JSONB;
        
        -- Copy data from array to JSONB (convert array to JSON array)
        UPDATE ai_analysis SET recommended_actions_jsonb = to_jsonb(recommended_actions);
        
        -- Drop the old column
        ALTER TABLE ai_analysis DROP COLUMN recommended_actions;
        
        -- Rename the new column
        ALTER TABLE ai_analysis RENAME COLUMN recommended_actions_jsonb TO recommended_actions;
    END IF;
END $$;

-- Update agent_status table to add missing columns
DO $$ 
BEGIN
    -- Add last_processed_alert column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'agent_status' AND column_name = 'last_processed_alert') THEN
        ALTER TABLE agent_status ADD COLUMN last_processed_alert VARCHAR(255);
    END IF;
    
    -- Add processing_count column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'agent_status' AND column_name = 'processing_count') THEN
        ALTER TABLE agent_status ADD COLUMN processing_count INTEGER DEFAULT 0;
    END IF;
    
    -- Update status constraint to include more values
    IF EXISTS (SELECT 1 FROM information_schema.check_constraints 
               WHERE constraint_name LIKE '%agent_status_status%') THEN
        ALTER TABLE agent_status DROP CONSTRAINT IF EXISTS agent_status_status_check;
    END IF;
    ALTER TABLE agent_status ADD CONSTRAINT agent_status_status_check 
        CHECK (status IN ('active', 'idle', 'error', 'inactive'));
END $$;

-- Update system_metrics table to change metric_value precision
DO $$ 
BEGIN
    -- Change metric_value to higher precision if needed
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'system_metrics' AND column_name = 'metric_value' 
               AND numeric_precision < 15) THEN
        ALTER TABLE system_metrics ALTER COLUMN metric_value TYPE DECIMAL(15,6);
    END IF;
END $$;

-- =============================================================================
-- Step 3: Create missing tables
-- =============================================================================

-- Create workflow_states table if it doesn't exist
CREATE TABLE IF NOT EXISTS workflow_states (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    workflow_id VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'initiated',
    alert_id VARCHAR(255),
    workflow_type VARCHAR(100) NOT NULL,
    initiated_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================================================
-- Step 4: Create indexes for better performance
-- =============================================================================

-- Alerts indexes
CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_system ON alerts(source_system);

-- AI Analysis indexes
CREATE INDEX IF NOT EXISTS idx_ai_analysis_alert_id ON ai_analysis(alert_id);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_created_at ON ai_analysis(created_at);

-- Agent Status indexes
CREATE INDEX IF NOT EXISTS idx_agent_status_agent_name ON agent_status(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_status_status ON agent_status(status);
CREATE INDEX IF NOT EXISTS idx_agent_status_last_activity ON agent_status(last_activity);

-- System Metrics indexes
CREATE INDEX IF NOT EXISTS idx_system_metrics_metric_name ON system_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_system_metrics_name_timestamp ON system_metrics(metric_name, timestamp);

-- Workflow States indexes
CREATE INDEX IF NOT EXISTS idx_workflow_states_workflow_id ON workflow_states(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_states_status ON workflow_states(status);
CREATE INDEX IF NOT EXISTS idx_workflow_states_alert_id ON workflow_states(alert_id);
CREATE INDEX IF NOT EXISTS idx_workflow_states_created_at ON workflow_states(created_at);

-- =============================================================================
-- Step 5: Enable Row Level Security and create policies
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_analysis ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_states ENABLE ROW LEVEL SECURITY;

-- Create policies (allow all for now)
DO $$ 
BEGIN
    -- Drop existing policies if they exist
    DROP POLICY IF EXISTS "Allow all operations" ON alerts;
    DROP POLICY IF EXISTS "Allow all operations" ON ai_analysis;
    DROP POLICY IF EXISTS "Allow all operations" ON agent_status;
    DROP POLICY IF EXISTS "Allow all operations" ON system_metrics;
    DROP POLICY IF EXISTS "Allow all operations" ON workflow_states;
    
    -- Create new policies
    CREATE POLICY "Service role can do everything on alerts" ON alerts
        FOR ALL USING (true) WITH CHECK (true);
    
    CREATE POLICY "Service role can do everything on ai_analysis" ON ai_analysis
        FOR ALL USING (true) WITH CHECK (true);
    
    CREATE POLICY "Service role can do everything on agent_status" ON agent_status
        FOR ALL USING (true) WITH CHECK (true);
    
    CREATE POLICY "Service role can do everything on system_metrics" ON system_metrics
        FOR ALL USING (true) WITH CHECK (true);
    
    CREATE POLICY "Service role can do everything on workflow_states" ON workflow_states
        FOR ALL USING (true) WITH CHECK (true);
END $$;

-- =============================================================================
-- Step 6: Create functions and triggers
-- =============================================================================

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
DROP TRIGGER IF EXISTS update_alerts_updated_at ON alerts;
CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_agent_status_updated_at ON agent_status;
CREATE TRIGGER update_agent_status_updated_at BEFORE UPDATE ON agent_status
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_workflow_states_updated_at ON workflow_states;
CREATE TRIGGER update_workflow_states_updated_at BEFORE UPDATE ON workflow_states
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Step 7: Create views for common queries
-- =============================================================================

-- View for alerts with their AI analysis
CREATE OR REPLACE VIEW alerts_with_analysis AS
SELECT 
    a.*,
    ai.false_positive_probability,
    ai.severity_score,
    ai.confidence_score,
    ai.recommended_actions,
    ai.processing_time_ms as ai_processing_time_ms,
    ai.created_at as analysis_created_at
FROM alerts a
LEFT JOIN ai_analysis ai ON a.id = ai.alert_id;

-- View for system health dashboard
CREATE OR REPLACE VIEW system_health AS
SELECT 
    (SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '1 hour') as alerts_last_hour,
    (SELECT COUNT(*) FROM alerts WHERE status = 'processing') as alerts_processing,
    (SELECT COUNT(*) FROM alerts WHERE status = 'completed') as alerts_completed,
    (SELECT COUNT(*) FROM agent_status WHERE status = 'active') as active_agents,
    (SELECT AVG(processing_time_ms) FROM ai_analysis WHERE created_at >= NOW() - INTERVAL '1 hour') as avg_processing_time_ms;

-- =============================================================================
-- Step 8: Insert sample data (simple approach)
-- =============================================================================

-- Insert sample agent status records (using simple INSERT, no ON CONFLICT)
INSERT INTO agent_status (agent_name, status, last_activity) 
SELECT 'alert_receiver_ai', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM agent_status WHERE agent_name = 'alert_receiver_ai');

INSERT INTO agent_status (agent_name, status, last_activity) 
SELECT 'false_positive_checker_ai', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM agent_status WHERE agent_name = 'false_positive_checker_ai');

INSERT INTO agent_status (agent_name, status, last_activity) 
SELECT 'severity_analyzer_ai', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM agent_status WHERE agent_name = 'severity_analyzer_ai');

INSERT INTO agent_status (agent_name, status, last_activity) 
SELECT 'context_gatherer_ai', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM agent_status WHERE agent_name = 'context_gatherer_ai');

INSERT INTO agent_status (agent_name, status, last_activity) 
SELECT 'response_coordinator_ai', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM agent_status WHERE agent_name = 'response_coordinator_ai');

-- =============================================================================
-- Step 9: Verify the update
-- =============================================================================

-- Show final table structure
SELECT table_name, column_name, data_type, is_nullable, column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name IN ('alerts', 'ai_analysis', 'agent_status', 'system_metrics', 'workflow_states')
ORDER BY table_name, ordinal_position;

-- Show success message
SELECT 'Database schema updated successfully!' as message;
