#!/bin/bash

set -e

echo "Starting Wazuh pre-flight checks..."

# Create test directories
mkdir -p /var/ossec/etc/rules-test
mkdir -p /var/ossec/etc/decoders-test

# Copy rules for testing
cp -r rules/*.xml /var/ossec/etc/rules-test/ 2>/dev/null || true
cp -r decoders/*.xml /var/ossec/etc/decoders-test/ 2>/dev/null || true

# Test configuration syntax
echo "Testing configuration syntax..."
if ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "❌ Configuration test failed"
    exit 1
fi

# Test individual rule files
echo "Testing rule files..."
for rule_file in /var/ossec/etc/rules-test/*.xml; do
    if [[ -f "$rule_file" ]]; then
        echo "Testing $(basename "$rule_file")..."
        if ! /var/ossec/bin/wazuh-logtest -q -U "$rule_file" < /dev/null; then
            echo "❌ Rule test failed for $rule_file"
            exit 1
        fi
    fi
done

echo "✅ All pre-flight checks passed"

# Cleanup
rm -rf /var/ossec/etc/rules-test
rm -rf /var/ossec/etc/decoders-test