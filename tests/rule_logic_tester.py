#!/usr/bin/env python3
"""
Wazuh Rule Logic Tester
Validates XML rule files for common issues.
Run as: python tests/rule_logic_tester.py
"""

import os
import sys
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Tuple

class RuleLogicTester:
    def __init__(self, rules_dir: str = "rules"):
        """
        Initialize tester with path to rules directory.
        
        Args:
            rules_dir: Path to directory containing XML rule files
        """
        self.rules_dir = Path(rules_dir)
        self.rule_files = []
        self.all_rules = []  # List of (rule_id, file_name, rule_element)
        self.errors = []
        self.warnings = []
        
    def discover_rule_files(self) -> bool:
        """Find all XML files in rules directory."""
        if not self.rules_dir.exists():
            self._add_error(f"Rules directory not found: {self.rules_dir}")
            return False
            
        self.rule_files = list(self.rules_dir.glob("*.xml"))
        if not self.rule_files:
            self._add_warning(f"No XML files found in {self.rules_dir}")
            return False
            
        print(f"Found {len(self.rule_files)} rule file(s)")
        return True
    
    def parse_rule_files(self):
        """Parse all rule files and extract rule information."""
        for file_path in self.rule_files:
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Wazuh rules are typically under <group> or direct <rule> elements
                for rule_elem in root.findall(".//rule"):
                    rule_id = rule_elem.get("id")
                    if rule_id:
                        self.all_rules.append((rule_id, file_path.name, rule_elem))
                    else:
                        self._add_warning(f"Rule without ID in {file_path.name}")
                        
            except ET.ParseError as e:
                self._add_error(f"XML parse error in {file_path.name}: {e}")
            except Exception as e:
                self._add_error(f"Unexpected error reading {file_path.name}: {e}")
    
    def validate_rule_ids(self):
        """Check for duplicate rule IDs."""
        id_count = {}
        for rule_id, file_name, _ in self.all_rules:
            id_count[rule_id] = id_count.get(rule_id, 0) + 1
            
        for rule_id, count in id_count.items():
            if count > 1:
                # Find all files with this duplicate ID
                files = [f for rid, f, _ in self.all_rules if rid == rule_id]
                self._add_error(f"Duplicate rule ID {rule_id} found in {count} files: {', '.join(files)}")
    
    def validate_rule_structure(self):
        """Validate required fields in each rule."""
        required_fields = ["id", "level"]
        recommended_fields = ["description", "group"]
        
        for rule_id, file_name, rule_elem in self.all_rules:
            # Check required fields
            for field in required_fields:
                if not rule_elem.get(field):
                    self._add_error(f"Rule {rule_id} ({file_name}) missing required attribute: {field}")
            
            # Check recommended fields
            for field in recommended_fields:
                if not rule_elem.get(field):
                    self._add_warning(f"Rule {rule_id} ({file_name}) missing recommended attribute: {field}")
            
            # Validate level is numeric and reasonable
            level = rule_elem.get("level")
            if level:
                try:
                    level_num = int(level)
                    if not (0 <= level_num <= 15):
                        self._add_warning(f"Rule {rule_id} ({file_name}) has unusual level: {level}")
                except ValueError:
                    self._add_error(f"Rule {rule_id} ({file_name}) has non-numeric level: {level}")
    
    def test_regex_patterns(self):
        """Test if regex patterns in rules are valid."""
        for rule_id, file_name, rule_elem in self.all_rules:
            # Look for common regex-containing elements
            regex_elements = [
                ("match", rule_elem.findtext("match")),
                ("regex", rule_elem.findtext("regex")),
                ("pattern", rule_elem.findtext("pattern")),
            ]
            
            for field_name, pattern in regex_elements:
                if pattern and pattern.strip():
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        self._add_error(f"Rule {rule_id} ({file_name}) has invalid regex in '{field_name}': {pattern} - Error: {e}")
    
    def check_rule_dependencies(self):
        """
        Check for potential rule dependencies.
        Wazuh rules can reference other rules using 'if_sid' or 'if_defined_sid'.
        """
        for rule_id, file_name, rule_elem in self.all_rules:
            if_sid = rule_elem.get("if_sid") or rule_elem.findtext("if_sid")
            if if_sid:
                # Check if referenced rule exists
                referenced_ids = [sid.strip() for sid in if_sid.split(",")]
                for ref_id in referenced_ids:
                    if not any(rid == ref_id for rid, _, _ in self.all_rules):
                        self._add_warning(f"Rule {rule_id} ({file_name}) references non-existent rule ID: {ref_id}")
    
    def _add_error(self, message: str):
        """Add an error message."""
        self.errors.append(message)
    
    def _add_warning(self, message: str):
        """Add a warning message."""
        self.warnings.append(message)
    
    def run_tests(self) -> bool:
        """
        Run all validation tests.
        
        Returns:
            bool: True if no errors found, False otherwise
        """
        print("=" * 60)
        print("Wazuh Rule Logic Tester")
        print("=" * 60)
        
        # Step 1: Discover files
        if not self.discover_rule_files():
            return False
        
        # Step 2: Parse files
        self.parse_rule_files()
        if not self.all_rules:
            self._add_warning("No rules found in any XML files")
        
        print(f"Parsed {len(self.all_rules)} rule(s)")
        
        # Step 3: Run validations
        print("\nRunning validations...")
        self.validate_rule_ids()
        self.validate_rule_structure()
        self.test_regex_patterns()
        self.check_rule_dependencies()
        
        # Step 4: Report results
        self.print_results()
        
        # Return success status (no errors)
        return len(self.errors) == 0
    
    def print_results(self):
        """Print all test results."""
        if self.errors:
            print("\n" + "!" * 60)
            print("ERRORS FOUND:")
            print("!" * 60)
            for i, error in enumerate(self.errors, 1):
                print(f"{i}. {error}")
        
        if self.warnings:
            print("\n" + "-" * 60)
            print("WARNINGS:")
            print("-" * 60)
            for i, warning in enumerate(self.warnings, 1):
                print(f"{i}. {warning}")
        
        print("\n" + "=" * 60)
        print("SUMMARY:")
        print("=" * 60)
        print(f"Rule files processed: {len(self.rule_files)}")
        print(f"Total rules found: {len(self.all_rules)}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")
        
        if not self.errors and not self.warnings:
            print("\n✅ All tests passed!")
        elif self.errors:
            print("\n❌ Validation failed with errors")
        else:
            print("\n⚠️  Validation passed with warnings")

def main():
    """Main entry point for the script."""
    # Default to 'rules' directory, but allow command line argument
    rules_dir = "rules"
    if len(sys.argv) > 1:
        rules_dir = sys.argv[1]
    
    tester = RuleLogicTester(rules_dir)
    success = tester.run_tests()
    
    # Exit with appropriate code for CI/CD pipeline
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
