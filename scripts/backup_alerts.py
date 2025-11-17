#!/usr/bin/env python3
"""
Backup current Wazuh alerts for regression testing - CI/CD compatible version
"""
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def backup_alerts():
    """Backup current alert patterns using mock data for CI/CD"""
    backup_dir = Path("/tmp/wazuh_backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"alerts_baseline_{timestamp}.json"
    
    try:
        # Try real Wazuh first
        if can_run_wazuh():
            sample_alerts = generate_real_alerts()
        else:
            # Fall back to mock data for CI/CD
            sample_alerts = generate_mock_alerts()
        
        # Save to backup file
        with open(backup_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'alert_count': len(sample_alerts),
                'environment': 'production' if can_run_wazuh() else 'mock',
                'alerts': sample_alerts
            }, f, indent=2)
        
        print(f"✅ Alerts backup created: {backup_file}")
        print(f"📊 Environment: {'Production' if can_run_wazuh() else 'Mock/CI-CD'}")
        return True
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def can_run_wazuh():
    """Check if Wazuh is accessible"""
    try:
        result = subprocess.run(
            ["which", "wazuh-logtest"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def generate_real_alerts():
    """Generate real alerts using wazuh-logtest"""
    sample_logs = get_sample_logs()
    alerts = []
    
    for log_line in sample_logs:
        try:
            result = subprocess.run(
                ["wazuh-logtest", "-q"],
                input=log_line,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                rule_id = extract_rule_id(result.stdout)
                alerts.append({
                    'log': log_line,
                    'rule_id': rule_id,
                    'output': result.stdout.strip()[:200]  # Limit size
                })
                
        except Exception as e:
            print(f"⚠️  Error processing log: {e}")
            # Add mock entry for consistency
            alerts.append({
                'log': log_line,
                'rule_id': 'mock_001',
                'output': f'mock: {e}'
            })
    
    return alerts

def generate_mock_alerts():
    """Generate mock alerts for CI/CD environments"""
    sample_logs = get_sample_logs()
    alerts = []
    
    # Mock rule mappings based on common log patterns
    mock_rules = {
        'sshd': '5715',
        'sudo': '5402', 
        'kernel': '5103',
        'firewall': '5102'
    }
    
    for log_line in sample_logs:
        # Simple pattern matching for mock rules
        rule_id = '0000'  # default
        for pattern, rid in mock_rules.items():
            if pattern in log_line.lower():
                rule_id = rid
                break
        
        alerts.append({
            'log': log_line,
            'rule_id': rule_id,
            'output': f'mock: Rule id "{rule_id}" triggered by log pattern'
        })
    
    return alerts

def get_sample_logs():
    """Return sample log lines for testing"""
    return [
        "Jan  1 12:00:00 hostname sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2",
        "Jan  1 12:00:01 hostname sudo: pam_unix(sudo:session): session opened for user root",
        "Jan  1 12:00:02 hostname kernel: [12345.67890] Firewall: TCP DROP IN=eth0 OUT= MAC=00:11:22:33:44:55:66 SRC=10.1.1.1 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=443 DPT=12345 WINDOW=65535 RES=0x00 SYN URGP=0",
    ]

def extract_rule_id(output):
    """Extract rule ID from wazuh-logtest output"""
    if "Rule id" in output:
        for line in output.split('\n'):
            if "Rule id" in line:
                parts = line.split("Rule id")[1].strip()
                rule_id = parts.split()[0].strip('"')
                if rule_id.isdigit():
                    return rule_id
    return 'unknown'

if __name__ == "__main__":
    success = backup_alerts()
    sys.exit(0 if success else 1)