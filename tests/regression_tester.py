#!/usr/bin/env python3
"""
Regression testing for Wazuh rules
"""
import json
import subprocess
from pathlib import Path
from datetime import datetime

def load_baseline_alerts():
    """Load the most recent baseline alerts"""
    backup_dir = Path("/tmp/wazuh_backups")
    if not backup_dir.exists():
        print("❌ No backup directory found")
        return None
    
    backup_files = sorted(backup_dir.glob("alerts_baseline_*.json"))
    if not backup_files:
        print("❌ No baseline alerts found")
        return None
    
    latest_backup = backup_files[-1]
    with open(latest_backup, 'r') as f:
        return json.load(f)

def run_regression_test():
    """Run regression tests against baseline"""
    baseline = load_baseline_alerts()
    if not baseline:
        return False
    
    print(f"📊 Using baseline from: {baseline['timestamp']}")
    print(f"📊 Baseline alert count: {baseline['alert_count']}")
    
    current_alerts = generate_current_alerts()
    
    # Compare results
    regression_issues = compare_alerts(baseline['alerts'], current_alerts)
    
    if regression_issues:
        print("❌ Regression issues found:")
        for issue in regression_issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ No regression issues detected")
        return True

def generate_current_alerts():
    """Generate current alerts for comparison"""
    sample_logs = [
        "Jan  1 12:00:00 hostname sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2",
        "Jan  1 12:00:01 hostname sudo: pam_unix(sudo:session): session opened for user root",
        "Jan  1 12:00:02 hostname kernel: [12345.67890] Firewall: TCP DROP IN=eth0 OUT= MAC=00:11:22:33:44:55:66 SRC=10.1.1.1 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=443 DPT=12345 WINDOW=65535 RES=0x00 SYN URGP=0",
    ]
    
    current_alerts = []
    
    for log_line in sample_logs:
        try:
            result = subprocess.run(
                ["/var/ossec/bin/wazuh-logtest", "-q"],
                input=log_line,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                current_alerts.append({
                    'log': log_line,
                    'output': result.stdout.strip()
                })
                
        except Exception as e:
            print(f"⚠️  Error processing {log_line[:50]}: {e}")
    
    return current_alerts

def compare_alerts(baseline_alerts, current_alerts):
    """Compare baseline and current alerts"""
    issues = []
    
    # Check if we have similar number of alerts
    if len(current_alerts) < len(baseline_alerts) * 0.5:  # 50% threshold
        issues.append(f"Alert count dropped significantly: {len(baseline_alerts)} → {len(current_alerts)}")
    
    # Check for missing rule matches
    baseline_rules = extract_rule_ids(baseline_alerts)
    current_rules = extract_rule_ids(current_alerts)
    
    missing_rules = baseline_rules - current_rules
    if missing_rules:
        issues.append(f"Missing rule matches: {missing_rules}")
    
    return issues

def extract_rule_ids(alerts):
    """Extract rule IDs from alert outputs"""
    rule_ids = set()
    for alert in alerts:
        output = alert.get('output', '')
        # Extract rule IDs from wazuh-logtest output
        if "Rule id" in output:
            for line in output.split('\n'):
                if "Rule id" in line:
                    parts = line.split("Rule id")[1].strip()
                    rule_id = parts.split()[0].strip('"')
                    if rule_id.isdigit():
                        rule_ids.add(rule_id)
    return rule_ids

if __name__ == "__main__":
    success = run_regression_test()
    exit(0 if success else 1)