#!/usr/bin/env python3
import re
from pathlib import Path
import sys

class SecurityScanner:
    def __init__(self):
        self.issues = []
        
        # Security patterns to check
        self.patterns = {
            "hardcoded_password": r'password\s*=\s*["\']\w+["\']',
            "api_key": r'api[_-]?key\s*=\s*["\']\w+["\']',
            "secret_token": r'token\s*=\s*["\']\w+["\']',
            "broad_regex": r'<regex>.*\\.\*.*</regex>',
            "potential_redos": r'\(\?[iLmsux]*\).*\(\?[iLmsux]*\)',  # Nested regex flags
        }
    
    def scan_file(self, file_path):
        """Scan a single file for security issues"""
        try:
            content = file_path.read_text()
            
            for issue_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    self.issues.append({
                        'file': file_path,
                        'line': self.get_line_number(content, match.start()),
                        'issue': issue_type,
                        'context': match.group()[:100]
                    })
        except Exception as e:
            self.issues.append({
                'file': file_path,
                'line': 0,
                'issue': 'read_error',
                'context': str(e)
            })
    
    def get_line_number(self, content, position):
        """Get line number from character position"""
        return content[:position].count('\n') + 1
    
    def scan_directory(self):
        """Scan all rules and decoders"""
        xml_files = list(Path("rules").glob("*.xml")) + list(Path("decoders").glob("*.xml"))
        
        for xml_file in xml_files:
            self.scan_file(xml_file)
    
    def report(self):
        """Generate security report"""
        if not self.issues:
            print("✅ No security issues found")
            return True
        
        print("Security issues found:")
        for issue in self.issues:
            print(f"  ❌ {issue['file']}:{issue['line']} - {issue['issue']}")
            print(f"     Context: {issue['context']}")
        
        # Only fail on critical issues
        critical_issues = [i for i in self.issues if i['issue'] in ['hardcoded_password', 'api_key', 'secret_token']]
        
        if critical_issues:
            print(f"\n🚨 {len(critical_issues)} critical security issues found!")
            return False
        
        print(f"\n⚠️  {len(self.issues)} non-critical issues found (warnings only)")
        return True

def main():
    scanner = SecurityScanner()
    scanner.scan_directory()
    
    if not scanner.report():
        sys.exit(1)

if __name__ == "__main__":
    main()