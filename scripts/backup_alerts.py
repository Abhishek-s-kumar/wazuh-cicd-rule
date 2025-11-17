#!/usr/bin/env python3
"""
Backup current Wazuh alerts for regression testing
"""
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def backup_alerts():
    """Backup current alert patterns"""
    backup_dir = Path("/tmp/wazuh_backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"alerts_baseline_{timestamp}.json"
    
    try:
        # Get recent alerts (last 24 hours)
        # Using wazuh-logtest to generate sample alerts
        sample_alerts = generate_sample_alerts()
        
        # Save to backup file
        with open(backup_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'alert_count': len(sample_alerts),
                'alerts': sample_alerts
            }, f, indent=2)
        
        print(f"✅ Alerts backup created: {backup_file}")
        return True
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def generate_sample_alerts():
    """Generate sample alerts using wazuh-logtest"""
    sample_logs = [
        "Jan  1 12:00:00 hostname sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2",
        "Jan  1 12:00:01 hostname sudo: pam_unix(sudo:session): session opened for user root",
        "Jan  1 12:00:02 hostname kernel: [12345.67890] Firewall: TCP DROP IN=eth0 OUT= MAC=00:11:22:33:44:55:66 SRC=10.1.1.1 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=443 DPT=12345 WINDOW=65535 RES=0x00 SYN URGP=0",
    ]
    
    alerts = []
    
    for log_line in sample_logs:
        try:
            # Test log line with wazuh-logtest
            result = subprocess.run(
                ["/var/ossec/bin/wazuh-logtest", "-q"],
                input=log_line,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "Rule id" in result.stdout:
                alerts.append({
                    'log': log_line,
                    'output': result.stdout.strip(),
                    'timestamp': datetime.now().isoformat()
                })
                
        except subprocess.TimeoutExpired:
            print(f"⚠️  Timeout processing: {log_line[:50]}...")
        except Exception as e:
            print(f"⚠️  Error processing log: {e}")
    
    return alerts

if __name__ == "__main__":
    success = backup_alerts()
    sys.exit(0 if success else 1)