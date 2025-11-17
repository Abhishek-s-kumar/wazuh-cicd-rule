#!/usr/bin/env python3
import subprocess
import time
import json
import sys
import argparse
from pathlib import Path

class PerformanceMonitor:
    def __init__(self):
        self.metrics_file = Path("/tmp/wazuh_perf_metrics.json")
    
    def get_baseline(self):
        """Capture performance baseline"""
        baseline = {
            'timestamp': time.time(),
            'memory_usage': self.get_memory_usage(),
            'rule_count': self.get_rule_count(),
            'analysisd_status': self.get_service_status()
        }
        
        # Save baseline
        with open(self.metrics_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        print("Performance baseline captured:")
        print(f"  Memory: {baseline['memory_usage']} MB")
        print(f"  Rules: {baseline['rule_count']}")
    
    def compare_performance(self):
        """Compare current performance with baseline"""
        if not self.metrics_file.exists():
            print("No baseline found")
            return True
        
        with open(self.metrics_file, 'r') as f:
            baseline = json.load(f)
        
        current = {
            'memory_usage': self.get_memory_usage(),
            'rule_count': self.get_rule_count(),
            'analysisd_status': self.get_service_status()
        }
        
        # Calculate differences
        memory_change = ((current['memory_usage'] - baseline['memory_usage']) / 
                        baseline['memory_usage']) * 100
        
        print("\nPerformance Comparison:")
        print(f"  Memory: {baseline['memory_usage']}MB → {current['memory_usage']}MB ({memory_change:+.1f}%)")
        print(f"  Rules: {baseline['rule_count']} → {current['rule_count']}")
        
        # Check thresholds
        warnings = []
        if memory_change > 20:
            warnings.append(f"Memory increased by {memory_change:.1f}% (threshold: 20%)")
        if current['analysisd_status'] != 'active':
            warnings.append("Wazuh analysisd not active")
        
        if warnings:
            print("\n⚠️  Performance warnings:")
            for warning in warnings:
                print(f"  - {warning}")
            return False
        
        print("✅ Performance within acceptable limits")
        return True
    
    def get_memory_usage(self):
        """Get Wazuh analysisd memory usage in MB"""
        try:
            result = subprocess.run(
                ["ps", "-o", "rss=", "-C", "wazuh-analysisd"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                memory_kb = int(result.stdout.strip())
                return memory_kb / 1024  # Convert to MB
        except Exception:
            pass
        return 0
    
    def get_rule_count(self):
        """Count total rules"""
        count = 0
        for rules_file in Path("/var/ossec/etc/rules").glob("*.xml"):
            try:
                # Simple line count for rule elements
                result = subprocess.run(
                    ["grep", "-c", "<rule", str(rules_file)],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    count += int(result.stdout.strip())
            except Exception:
                pass
        return count
    
    def get_service_status(self):
        """Get wazuh-analysisd service status"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "wazuh-analysisd"],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

def main():
    parser = argparse.ArgumentParser(description="Wazuh Performance Monitor")
    parser.add_argument('--action', choices=['baseline', 'compare'], required=True)
    
    args = parser.parse_args()
    monitor = PerformanceMonitor()
    
    if args.action == 'baseline':
        monitor.get_baseline()
    else:
        success = monitor.compare_performance()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()