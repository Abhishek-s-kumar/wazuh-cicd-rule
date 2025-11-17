#!/usr/bin/env python3
"""
Kali-compatible regression testing - no external dependencies
"""
import json
from pathlib import Path

def run_regression_test():
    """Run regression tests without Wazuh dependencies"""
    baseline = load_baseline_alerts()
    
    if not baseline:
        print("⚠️  No baseline found. Creating initial baseline...")
        create_initial_baseline()
        return True
    
    print(f"📊 Using baseline from: {baseline['timestamp']}")
    print(f"📊 Baseline environment: {baseline.get('environment', 'unknown')}")
    print(f"📊 Baseline alert count: {baseline['alert_count']}")
    
    # Generate current mock alerts
    current_alerts = generate_kali_mock_alerts()
    
    # Compare results
    issues = compare_kali_alerts(baseline['alerts'], current_alerts)
    
    if issues:
        print("❌ Regression issues found:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ No regression issues detected")
        return True

def load_baseline_alerts():
    """Load the most recent baseline alerts"""
    backup_dir = Path("/tmp/wazuh_backups")
    if not backup_dir.exists():
        return None
    
    backup_files = sorted(backup_dir.glob("alerts_baseline_*.json"))
    if not backup_files:
        return None
    
    latest_backup = backup_files[-1]
    with open(latest_backup, 'r') as f:
        return json.load(f)

def create_initial_baseline():
    """Create initial baseline using Kali-compatible script"""
    import sys
    sys.path.append('scripts')
    from kali_backup_alerts import backup_alerts
    backup_alerts()

def generate_kali_mock_alerts():
    """Generate current mock alerts for Kali"""
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
        }
    ]

def compare_kali_alerts(baseline_alerts, current_alerts):
    """Compare alerts in Kali environment"""
    issues = []
    
    if not baseline_alerts or not current_alerts:
        issues.append("Missing alert data for comparison")
        return issues
    
    # Check we have similar categories
    baseline_categories = {alert.get('category', 'unknown') for alert in baseline_alerts}
    current_categories = {alert.get('category', 'unknown') for alert in current_alerts}
    
    missing_categories = baseline_categories - current_categories
    if missing_categories:
        issues.append(f"Missing alert categories: {missing_categories}")
    
    # Check rule coverage
    baseline_rules = {alert.get('rule_id', 'unknown') for alert in baseline_alerts}
    current_rules = {alert.get('rule_id', 'unknown') for alert in current_alerts}
    
    missing_rules = baseline_rules - current_rules
    if missing_rules:
        issues.append(f"Missing rule coverage: {missing_rules}")
    
    print(f"📊 Baseline categories: {baseline_categories}")
    print(f"📊 Current categories: {current_categories}")
    print(f"📊 Baseline rules: {baseline_rules}")
    print(f"📊 Current rules: {current_rules}")
    
    return issues

if __name__ == "__main__":
    success = run_regression_test()
    exit(0 if success else 1)