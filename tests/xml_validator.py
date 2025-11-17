#!/usr/bin/env python3
import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import sys
import urllib.request
import tempfile
import os

def install_xmllint():
    """Install xmllint if not available"""
    try:
        subprocess.run(["which", "xmllint"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Installing xmllint...")
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "libxml2-utils"], check=True)

def download_wazuh_schema():
    """Download Wazuh schema with caching"""
    schema_path = "/tmp/wazuh_rules.xsd"
    if not os.path.exists(schema_path):
        print("Downloading Wazuh schema...")
        try:
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/wazuh/wazuh/master/src/rule_opcodes.xsd",
                schema_path
            )
        except Exception as e:
            print(f"Warning: Could not download schema: {e}")
            return None
    return schema_path

def validate_xml_syntax():
    """Validate XML files are well-formed"""
    errors = []
    xml_files = list(Path("rules").glob("*.xml")) + list(Path("decoders").glob("*.xml"))
    
    for xml_file in xml_files:
        try:
            ET.parse(xml_file)
        except ET.ParseError as e:
            errors.append(f"XML syntax error in {xml_file}: {e}")
    
    return errors

def validate_with_xmllint():
    """Use xmllint for additional validation"""
    errors = []
    xml_files = list(Path("rules").glob("*.xml"))
    
    for xml_file in xml_files:
        result = subprocess.run(
            ["xmllint", "--noout", str(xml_file)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            errors.append(f"xmllint error in {xml_file}: {result.stderr}")
    
    return errors

def main():
    print("Starting XML validation...")
    
    # Install dependencies
    install_xmllint()
    
    # Basic XML syntax
    errors = validate_xml_syntax()
    
    # xmllint validation
    errors.extend(validate_with_xmllint())
    
    if errors:
        print("XML validation failed:")
        for error in errors:
            print(f"   {error}")
        sys.exit(1)
    else:
        print(" All XML files passed validation")
        sys.exit(0)

if __name__ == "__main__":
    main()