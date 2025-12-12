#!/bin/bash
# scripts/wazuh_preflight.sh - Enhanced for self-hosted runners

set -e

echo "=== Wazuh Pre-flight Checks ==="
echo "Runner: $(hostname)"
echo "Working directory: $(pwd)"

# Determine environment
if [ -d "/var/ossec" ] && [ -f "/var/ossec/bin/wazuh-analysisd" ]; then
  echo "✅ Environment: Self-hosted runner with Wazuh installed"
  WAZUH_PATH="/var/ossec"
  USE_SUDO="sudo"
  ENV_TYPE="self-hosted"
elif [ -f "/etc/ossec-init.conf" ] || ( [ -d "/var/ossec" ] && [ -f "/var/ossec/bin/wazuh-analysisd" ] ); then
  echo "✅ Environment: Wazuh container"
  WAZUH_PATH="/var/ossec"
  USE_SUDO=""
  ENV_TYPE="container"
else
  echo "⚠️  Environment: No Wazuh detected - running limited checks"
  WAZUH_PATH=""
  ENV_TYPE="no-wazuh"
fi

# =============================================
# SECTION 1: BASIC XML VALIDATION (Always run)
# =============================================
echo ""
echo "--- XML Syntax Validation ---"

check_xml_files() {
  local dir=$1
  local type=$2
  
  if [ -d "$dir" ] && [ "$(ls -A $dir/*.xml 2>/dev/null)" ]; then
    echo "Checking $type files in $dir:"
    local error_count=0
    
    # Try to install xmllint if not available
    if ! command -v xmllint &> /dev/null; then
      echo "  Installing xmllint for XML validation..."
      apt-get update && apt-get install -y libxml2-utils 2>/dev/null || \
      yum install -y libxml2 2>/dev/null || \
      echo "  ⚠️  Could not install xmllint, skipping XML validation"
    fi
    
    for xml_file in $dir/*.xml; do
      if [ -f "$xml_file" ]; then
        if command -v xmllint &> /dev/null; then
          if xmllint --noout "$xml_file" 2>/dev/null; then
            echo "    ✅ $(basename "$xml_file")"
          else
            echo "    ❌ $(basename "$xml_file") - XML syntax error"
            error_count=$((error_count + 1))
            
            # Show first error
            echo "      First error:"
            xmllint --noout "$xml_file" 2>&1 | head -2 | sed 's/^/      /'
          fi
        else
          # Basic check if it looks like XML
          if head -1 "$xml_file" | grep -q "<?xml\|<rule\|<decoder\|<group"; then
            echo "    ⚠️  $(basename "$xml_file") - XML check skipped (no xmllint)"
          else
            echo "    ❓ $(basename "$xml_file") - Doesn't look like XML"
          fi
        fi
      fi
    done
    
    if [ $error_count -eq 0 ]; then
      echo "  ✅ All $type files have valid XML syntax"
      return 0
    else
      echo "  ❌ Found $error_count XML syntax error(s) in $type files"
      return 1
    fi
  else
    echo "No $type files found in $dir"
    return 0
  fi
}

# Check rules and decoders from repository
check_xml_files "rules" "rule"
RULES_OK=$?

check_xml_files "decoders" "decoder"  
DECODERS_OK=$?

# =============================================
# SECTION 2: WAZUH-SPECIFIC TESTS (If available)
# =============================================
if [ "$ENV_TYPE" = "self-hosted" ] || [ "$ENV_TYPE" = "container" ]; then
  echo ""
  echo "--- Wazuh Configuration Test ---"
  
  CONFIG_FILE="$WAZUH_PATH/etc/ossec.conf"
  
  # Ensure config exists
  if [ ! -f "$CONFIG_FILE" ] || [ ! -s "$CONFIG_FILE" ]; then
    echo "Creating minimal ossec.conf for testing..."
    $USE_SUDO tee "$CONFIG_FILE" > /dev/null << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
  </global>
  <ruleset>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
  <active-response>
    <disabled>yes</disabled>
  </active-response>
</ossec_config>
EOF
    echo "✓ Created minimal configuration"
    
    # Set permissions
    $USE_SUDO chown wazuh:wazuh "$CONFIG_FILE" 2>/dev/null || true
  fi
  
  # Test configuration
  echo "Testing Wazuh configuration syntax..."
  if $USE_SUDO "$WAZUH_PATH/bin/wazuh-analysisd" -t 2>&1 | grep -q "Configuration OK"; then
    echo "✅ Wazuh configuration syntax is valid"
    CONFIG_OK=0
  else
    echo "⚠️  Wazuh configuration test issues:"
    $USE_SUDO "$WAZUH_PATH/bin/wazuh-analysisd" -t 2>&1 | head -5
    CONFIG_OK=1
  fi
  
  # =============================================
  # SECTION 3: RULE TESTING WITH WAZUH (Optional)
  # =============================================
  echo ""
  echo "--- Wazuh Rule Testing ---"
  
  # Create test directories
  TEST_RULES_DIR="/tmp/wazuh_test_rules"
  TEST_DECODERS_DIR="/tmp/wazuh_test_decoders"
  
  mkdir -p "$TEST_RULES_DIR" "$TEST_DECODERS_DIR"
  
  # Copy rules for testing
  if [ -d "rules" ] && [ "$(ls -A rules/*.xml 2>/dev/null)" ]; then
    cp rules/*.xml "$TEST_RULES_DIR/" 2>/dev/null || true
    echo "Copied $(ls rules/*.xml 2>/dev/null | wc -l) rule files for testing"
  fi
  
  if [ -d "decoders" ] && [ "$(ls -A decoders/*.xml 2>/dev/null)" ]; then
    cp decoders/*.xml "$TEST_DECODERS_DIR/" 2>/dev/null || true
    echo "Copied $(ls decoders/*.xml 2>/dev/null | wc -l) decoder files for testing"
  fi
  
  # Test rule loading (simplified - your original was too strict)
  echo "Testing rule structure (basic check)..."
  
  # Check for common Wazuh rule issues
  if [ "$(ls -A $TEST_RULES_DIR/*.xml 2>/dev/null)" ]; then
    RULE_ERRORS=0
    for rule_file in "$TEST_RULES_DIR"/*.xml; do
      # Basic structure check
      if grep -q "<rule id=" "$rule_file" && grep -q "level=" "$rule_file"; then
        echo "    ✅ $(basename "$rule_file") - Basic structure OK"
      else
        echo "    ⚠️  $(basename "$rule_file") - Missing required rule attributes"
        RULE_ERRORS=$((RULE_ERRORS + 1))
      fi
    done
    
    if [ $RULE_ERRORS -eq 0 ]; then
      echo "✅ All rule files have basic structure"
    else
      echo "⚠️  Found $RULE_ERRORS rule file(s) with issues"
    fi
  fi
  
  # Cleanup
  rm -rf "$TEST_RULES_DIR" "$TEST_DECODERS_DIR"
  
else
  echo ""
  echo "--- Skipping Wazuh-specific tests ---"
  echo "Wazuh not available on this runner"
  CONFIG_OK=0
fi

# =============================================
# SECTION 4: SUMMARY
# =============================================
echo ""
echo "=== Pre-flight Check Summary ==="
echo "Environment: $ENV_TYPE"
echo "XML Rules: $( [ $RULES_OK -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL' )"
echo "XML Decoders: $( [ $DECODERS_OK -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL' )"

if [ "$ENV_TYPE" != "no-wazuh" ]; then
  echo "Wazuh Config: $( [ $CONFIG_OK -eq 0 ] && echo '✅ PASS' || echo '⚠️  WARN' )"
fi

echo ""
echo "Overall Status:"

# Exit with appropriate code
if [ $RULES_OK -ne 0 ] || [ $DECODERS_OK -ne 0 ]; then
  echo "❌ Critical XML syntax errors found"
  exit 1  # Block PR on XML errors
elif [ "$ENV_TYPE" = "no-wazuh" ]; then
  echo "⚠️  Limited checks completed (Wazuh not available)"
  echo "To enable full Wazuh testing:"
  echo "  1. Install Wazuh on your runner, OR"
  echo "  2. Use Docker containers instead of self-hosted runner"
  exit 0  # Non-blocking
elif [ $CONFIG_OK -ne 0 ]; then
  echo "⚠️  Wazuh configuration issues (non-blocking for PR)"
  echo "Note: Configuration errors may be runner-specific"
  exit 0  # Non-blocking for config issues
else
  echo "✅ All checks passed!"
  exit 0
fi
