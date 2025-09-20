#!/usr/bin/env python3
"""
Comprehensive Orchestration Demo - Complete End-to-End Agent Testing
This demo tests the complete orchestration workflow of all 5 agents:
1. Alert Receiver Agent
2. False Positive Checker Agent  
3. Severity Analyzer Agent
4. Context Gatherer Agent
5. Response Coordinator Agent
"""

import requests
import json
import time
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, List
import sys
import os

class ComprehensiveOrchestrationDemo:
    """Comprehensive demo for complete agent orchestration testing"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.demo_results = []
        self.workflow_tracker = {}
        
    def print_header(self, title: str):
        """Print a formatted header"""
        print("\n" + "=" * 60)
        print(f"🎯 {title}")
        print("=" * 60)
    
    def print_step(self, step_num: int, title: str, status: str = "info"):
        """Print a formatted step"""
        status_icons = {
            "info": "ℹ️",
            "success": "✅", 
            "error": "❌",
            "warning": "⚠️",
            "processing": "🔄"
        }
        icon = status_icons.get(status, "ℹ️")
        print(f"\n{icon} Step {step_num}: {title}")
        print("-" * 40)
    
    def test_system_health(self) -> bool:
        """Test if the system is healthy and ready"""
        self.print_step(1, "System Health Check", "info")
        
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                health_data = response.json()
                print(f"   Status: {health_data['status']}")
                print(f"   System: {health_data['system']}")
                print(f"   Version: {health_data['version']}")
                print(f"   Timestamp: {health_data['timestamp']}")
                
                if health_data['status'] == 'healthy':
                    print("   ✅ System is healthy and ready for orchestration!")
                    return True
                else:
                    print("   ❌ System is not healthy")
                    return False
            else:
                print(f"   ❌ Health check failed: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ❌ Health check error: {e}")
            return False
    
    def create_test_alert(self, alert_type: str, severity: str, description: str, 
                         source_ip: str = "192.168.1.100", dest_ip: str = "10.0.0.1") -> Dict[str, Any]:
        """Create a comprehensive test alert"""
        return {
            "alert_id": f"orchestration_demo_{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.utcnow().isoformat(),
            "source_system": "orchestration_demo",
            "alert_type": alert_type,
            "severity": severity,
            "description": description,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "user_id": "demo.user",
            "hostname": "demo-workstation",
            "raw_data": {
                "event_type": f"{alert_type}_detection",
                "threat_name": f"Demo.{alert_type.title()}.{uuid.uuid4().hex[:4]}",
                "action_taken": "detected",
                "confidence_score": 0.85,
                "threat_category": alert_type,
                "attack_vector": "network",
                "indicators": [
                    f"IP: {source_ip}",
                    f"Domain: suspicious-{alert_type}.com",
                    f"Hash: {uuid.uuid4().hex[:16]}"
                ]
            },
            "metadata": {
                "demo_mode": True,
                "orchestration_test": True,
                "expected_agents": [
                    "alert_receiver",
                    "false_positive_checker", 
                    "severity_analyzer",
                    "context_gatherer",
                    "response_coordinator"
                ]
            }
        }
    
    def send_alert_to_system(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert to the orchestrated system"""
        self.print_step(2, f"Sending {alert_data['alert_type'].upper()} Alert", "processing")
        
        print(f"   Alert ID: {alert_data['alert_id']}")
        print(f"   Type: {alert_data['alert_type']}")
        print(f"   Severity: {alert_data['severity']}")
        print(f"   Description: {alert_data['description']}")
        print(f"   Source IP: {alert_data['source_ip']}")
        print(f"   Destination IP: {alert_data['destination_ip']}")
        
        try:
            response = requests.post(
                f"{self.base_url}/webhook/alert",
                json=alert_data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Alert submitted successfully!")
                print(f"   Status: {result.get('status', 'unknown')}")
                print(f"   Workflow ID: {result.get('workflow_id', 'N/A')}")
                print(f"   Message: {result.get('message', 'N/A')}")
                
                if 'workflow_id' in result:
                    self.workflow_tracker[result['workflow_id']] = {
                        'alert_data': alert_data,
                        'submitted_at': datetime.utcnow(),
                        'status': 'submitted'
                    }
                
                return result
            else:
                print(f"   ❌ Alert submission failed: HTTP {response.status_code}")
                print(f"   Response: {response.text}")
                return {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            print(f"   ❌ Alert submission error: {e}")
            return {"error": str(e)}
    
    def monitor_orchestration_workflow(self, workflow_id: str, max_checks: int = 20) -> Dict[str, Any]:
        """Monitor the complete orchestration workflow"""
        self.print_step(3, "Monitoring Orchestration Workflow", "processing")
        
        print(f"   Workflow ID: {workflow_id}")
        print(f"   Expected Agent Flow:")
        print(f"   1. Alert Receiver Agent (receives & normalizes alert)")
        print(f"   2. False Positive Checker Agent (validates alert legitimacy)")
        print(f"   3. Severity Analyzer Agent (determines severity & priority)")
        print(f"   4. Context Gatherer Agent (collects additional context)")
        print(f"   5. Response Coordinator Agent (coordinates response actions)")
        print()
        
        workflow_completed = False
        final_status = None
        
        for check_num in range(1, max_checks + 1):
            try:
                response = requests.get(f"{self.base_url}/workflow/status/{workflow_id}", timeout=10)
                
                if response.status_code == 200:
                    status_data = response.json()
                    current_status = status_data.get('status', 'unknown')
                    
                    print(f"   Check {check_num:2d}: Status = {current_status}")
                    
                    # Show detailed workflow progress
                    if 'steps' in status_data and status_data['steps']:
                        print(f"      Workflow Steps:")
                        for i, step in enumerate(status_data['steps'], 1):
                            agent_id = step.get('agent_id', 'unknown')
                            step_status = step.get('status', 'pending')
                            step_result = step.get('result', {})
                            
                            status_icon = "✅" if step_status == "completed" else "🔄" if step_status == "in_progress" else "⏳"
                            print(f"         {i}. {status_icon} {agent_id}: {step_status}")
                            
                            if step_result and step_status == "completed":
                                if 'confidence_score' in step_result:
                                    print(f"            Confidence: {step_result['confidence_score']}")
                                if 'reasoning' in step_result:
                                    print(f"            Reasoning: {step_result['reasoning'][:100]}...")
                    
                    # Check for completion
                    if current_status == "completed":
                        print(f"\n   🎉 ORCHESTRATION COMPLETED SUCCESSFULLY!")
                        print(f"   ✅ All 5 agents have been orchestrated!")
                        workflow_completed = True
                        final_status = status_data
                        break
                    elif current_status == "failed":
                        print(f"\n   ❌ Workflow failed!")
                        print(f"   Error: {status_data.get('error', 'Unknown error')}")
                        final_status = status_data
                        break
                    elif current_status == "running":
                        print(f"      Workflow is actively running...")
                    
                else:
                    print(f"   Check {check_num:2d}: Failed to get status (HTTP {response.status_code})")
                    
            except Exception as e:
                print(f"   Check {check_num:2d}: Error - {e}")
            
            time.sleep(3)  # Wait 3 seconds between checks
        
        if not workflow_completed:
            print(f"\n   ⚠️ Workflow monitoring timed out after {max_checks} checks")
            print(f"   Final status: {final_status.get('status', 'unknown') if final_status else 'timeout'}")
        
        return final_status or {"status": "timeout", "error": "Monitoring timed out"}
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics"""
        self.print_step(4, "System Metrics & Performance", "info")
        
        try:
            response = requests.get(f"{self.base_url}/metrics", timeout=10)
            if response.status_code == 200:
                metrics_data = response.json()
                print("   System Performance Metrics:")
                
                if 'system_metrics' in metrics_data:
                    metrics = metrics_data['system_metrics']
                    for key, value in metrics.items():
                        print(f"      {key}: {value}")
                else:
                    print(f"      Raw metrics: {metrics_data}")
                
                return metrics_data
            else:
                print(f"   ❌ Metrics check failed: HTTP {response.status_code}")
                return {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            print(f"   ❌ Metrics check error: {e}")
            return {"error": str(e)}
    
    def run_comprehensive_demo(self):
        """Run the complete orchestration demo"""
        self.print_header("COMPREHENSIVE ORCHESTRATION DEMO")
        print("This demo tests the complete end-to-end orchestration")
        print("of all 5 agents in the Alert Triage System.")
        print()
        
        # Step 1: Health Check
        if not self.test_system_health():
            print("\n❌ System is not healthy. Please start the server first.")
            print("   Run: python src/main.py")
            return False
        
        # Step 2: Create and send test alerts
        test_alerts = [
            ("malware", "high", "Suspicious malware detected on workstation", "192.168.1.100", "10.0.0.1"),
            ("intrusion", "critical", "Unauthorized access attempt detected", "203.0.113.1", "10.0.0.50"),
            ("phishing", "medium", "Suspicious email with malicious attachment", "198.51.100.1", "10.0.0.25"),
            ("ddos", "high", "Distributed denial of service attack detected", "203.0.113.5", "10.0.0.100"),
            ("data_exfiltration", "critical", "Large data transfer to external IP detected", "192.168.1.200", "203.0.113.10")
        ]
        
        successful_workflows = []
        
        for i, (alert_type, severity, description, src_ip, dest_ip) in enumerate(test_alerts, 1):
            print(f"\n{'='*60}")
            print(f"🚨 TEST ALERT {i}/{len(test_alerts)}: {alert_type.upper()}")
            print(f"{'='*60}")
            
            # Create test alert
            alert_data = self.create_test_alert(alert_type, severity, description, src_ip, dest_ip)
            
            # Send alert
            result = self.send_alert_to_system(alert_data)
            
            if 'workflow_id' in result:
                # Monitor orchestration
                workflow_status = self.monitor_orchestration_workflow(result['workflow_id'])
                
                # Record results
                test_result = {
                    "alert_id": alert_data['alert_id'],
                    "alert_type": alert_type,
                    "severity": severity,
                    "workflow_id": result['workflow_id'],
                    "workflow_status": workflow_status,
                    "success": workflow_status.get('status') == 'completed',
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                self.demo_results.append(test_result)
                
                if test_result['success']:
                    successful_workflows.append(result['workflow_id'])
                    print(f"   ✅ Alert {i} orchestration completed successfully!")
                else:
                    print(f"   ❌ Alert {i} orchestration failed or timed out!")
                
                # Small delay between alerts
                if i < len(test_alerts):
                    print(f"\n   ⏳ Waiting 5 seconds before next alert...")
                    time.sleep(5)
            else:
                print(f"   ❌ Alert {i} failed to initiate workflow!")
                self.demo_results.append({
                    "alert_id": alert_data['alert_id'],
                    "alert_type": alert_type,
                    "severity": severity,
                    "workflow_id": None,
                    "workflow_status": None,
                    "success": False,
                    "error": result.get('error', 'Unknown error'),
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Step 3: Final metrics
        self.get_system_metrics()
        
        # Step 4: Demo summary
        self.print_step(5, "Demo Summary & Results", "info")
        
        total_alerts = len(self.demo_results)
        successful_alerts = len(successful_workflows)
        success_rate = (successful_alerts / total_alerts * 100) if total_alerts > 0 else 0
        
        print(f"   Total alerts tested: {total_alerts}")
        print(f"   Successful orchestrations: {successful_alerts}")
        print(f"   Success rate: {success_rate:.1f}%")
        print(f"   Failed orchestrations: {total_alerts - successful_alerts}")
        
        # Detailed results
        print(f"\n   Detailed Results:")
        for i, result in enumerate(self.demo_results, 1):
            status_icon = "✅" if result['success'] else "❌"
            print(f"      {i}. {status_icon} {result['alert_type']} ({result['severity']}) - {result['alert_id']}")
            if not result['success'] and 'error' in result:
                print(f"         Error: {result['error']}")
        
        # Save comprehensive report
        report_data = {
            "demo_id": str(uuid.uuid4()),
            "demo_type": "comprehensive_orchestration",
            "timestamp": datetime.utcnow().isoformat(),
            "total_alerts": total_alerts,
            "successful_alerts": successful_alerts,
            "success_rate": success_rate,
            "successful_workflows": successful_workflows,
            "test_results": self.demo_results,
            "system_metrics": self.get_system_metrics()
        }
        
        report_file = f"comprehensive_orchestration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\n   📝 Comprehensive report saved to: {report_file}")
        
        # Final verdict
        self.print_header("DEMO COMPLETION")
        if success_rate >= 80:
            print("🎉 EXCELLENT! Your Alert Triage System orchestration is working perfectly!")
            print("✅ All agents are being orchestrated successfully!")
            print("✅ Complete end-to-end workflow is functional!")
        elif success_rate >= 50:
            print("⚠️ GOOD! Your system is mostly working with some issues.")
            print("🔧 Check the report for details on failed orchestrations.")
        else:
            print("❌ NEEDS ATTENTION! Several orchestrations failed.")
            print("🔧 Please check the system logs and configuration.")
        
        return success_rate >= 50

def main():
    """Main demo execution"""
    print("🚀 Starting Comprehensive Orchestration Demo")
    print("Make sure the Alert Triage System server is running on http://localhost:8080")
    print()
    
    # Wait a moment for user to read
    time.sleep(2)
    
    demo = ComprehensiveOrchestrationDemo()
    success = demo.run_comprehensive_demo()
    
    return 0 if success else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        sys.exit(1)
