#!/usr/bin/env python3
"""
Kali-compatible performance monitoring - no external dependencies
"""
import os
from pathlib import Path

def get_rule_count():
    """Count rules without Wazuh dependencies"""
    count = 0
    rules_dir = Path("rules")
    
    if rules_dir.exists():
        for rules_file in rules_dir.glob("*.xml"):
            try:
                # Count rule elements in XML
                with open(rules_file, 'r') as f:
                    content = f.read()
                    count += content.count('<rule')
            except:
                pass
    return count

def main():
    rule_count = get_rule_count()
    print(f"📊 Current rule count: {rule_count}")
    
    # Simple performance check based on rule count
    if rule_count > 1000:
        print("⚠️  High rule count may impact performance")
    else:
        print("✅ Rule count within normal range")

if __name__ == "__main__":
    main()