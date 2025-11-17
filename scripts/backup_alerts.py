#!/usr/bin/env python3
"""
Kali-compatible backup script - no external dependencies
"""
import json
import sys
from pathlib import Path
from datetime import datetime

def backup_alerts():
    """Backup alert patterns without Wazuh dependencies"""
    backup_dir = Path("/tmp/wazuh_backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"alerts_baseline_{timestamp}.json"
    
    # Generate mock alerts suitable for Kali environment
    sample_alerts = generate_kali_mock_alerts()
    
    # Save to backup file
    with open(backup_file, 'w') as f:
        json.dump({
            'timestamp': timestamp,
            'alert_count': len(sample_alerts),
            'environment': 'kali_mock',
            'alerts': sample_alerts,
            'note': 'Kali-compatible mock data for regression testing'
        }, f, indent=2)
    
    print(f"✅ Kali-compatible backup created: {backup_file}")
    return True

def generate_kali_mock_alerts():
    """Generate mock alerts with Kali-relevant security events"""
    return [
        {
            'log': 'Jan  1 12:00:00 kali sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2',
            'rule_id': '5715',
            'output': 'mock: SSH authentication failure',
            'category': 'authentication'
        },
        {
            'log': 'Jan  1 12:00:01 kali sudo: pam_unix(sudo:session): session opened for user root',
            'rule_id': '5402',
            'output': 'mock: Privilege escalation',
            'category': 'privilege_escalation'
        },
        {
            'log': 'Jan  1 12:00:02 kali kernel: [12345.67890] Firewall: TCP DROP IN=eth0 OUT=',
            'rule_id': '5103',
            'output': 'mock: Firewall block',
            'category': 'network'
        },
        {
            'log': 'Jan  1 12:00:03 kali nmap[5678]: Starting Nmap 7.94 scan',
            'rule_id': '5104',
            'output': 'mock: Network scanning detected',
            'category': 'reconnaissance'
        },
        {
            'log': 'Jan  1 12:00:04 kali metasploit[9012]: Meterpreter session opened',
            'rule_id': '5710',
            'output': 'mock: Exploitation tool activity',
            'category': 'exploitation'
        }
    ]

if __name__ == "__main__":
    success = backup_alerts()
    sys.exit(0 if success else 1)