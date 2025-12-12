name: Validate Rule Changes
on:
  pull_request:
    branches: [ "main","rollb" ]
    paths: ["rules/**", "decoders/**"]

jobs:
  check-rule-ids:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR branch
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Fetch main branch
        run: git fetch origin main
      
      - name: Run rule ID conflict checker
        run: python check_rule_ids.py

  validate-xml-syntax:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Run XML validation
        run: python tests/xml_validator.py

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
      - name: Run security checks
        run: python tests/security_scanner.py

  wazuh-preflight:
    runs-on: [self-hosted, linux, kali]  # Make sure these match your runner labels
    steps:
      - uses: actions/checkout@v4
      
      - name: Identify runner environment
        run: |
          echo "Runner Hostname: $(hostname)"
          echo "Current Directory: $(pwd)"
          echo "Runner OS: $(uname -a)"
          echo "Checking for Wazuh installation..."
      
      - name: Check if Wazuh is installed
        id: check_wazuh
        run: |
          RUNNER_NAME="$(hostname)"
          echo "Running on: $RUNNER_NAME"
          
          if [ -d "/var/ossec" ] && [ -f "/var/ossec/bin/wazuh-analysisd" ]; then
            echo "✅ Wazuh found at /var/ossec"
            WA_VERSION=$(/var/ossec/bin/wazuh-analysisd -V 2>/dev/null | head -1 || echo "Version unknown")
            echo "Wazuh version: $WA_VERSION"
            echo "WAZUH_EXISTS=true" >> $GITHUB_OUTPUT
            echo "WAZUH_CONFIG_PATH=/var/ossec/etc/ossec.conf" >> $GITHUB_OUTPUT
          elif [ -d "/var/ossec" ]; then
            echo "⚠️  Wazuh directory exists but wazuh-analysisd not found"
            echo "WAZUH_EXISTS=false" >> $GITHUB_OUTPUT
          else
            echo "❌ Wazuh directory not found at /var/ossec"
            echo "This runner ($RUNNER_NAME) doesn't have Wazuh installed"
            echo "WAZUH_EXISTS=false" >> $GITHUB_OUTPUT
          fi
      
      - name: Skip pre-flight (Wazuh not installed)
        if: steps.check_wazuh.outputs.WAZUH_EXISTS == 'false'
        run: |
          echo "⚠️  Skipping Wazuh pre-flight checks"
          echo "Wazuh is not properly installed on this runner: $(hostname)"
          echo "To fix this:"
          echo "1. Install Wazuh on your kali runner"
          echo "2. OR use Docker containers instead"
          
          # Basic XML validation if xmllint is available
          if command -v xmllint &> /dev/null; then
            echo "Running basic XML validation with xmllint..."
            for xml_file in rules/*.xml decoders/*.xml 2>/dev/null; do
              if [ -f "$xml_file" ]; then
                xmllint --noout "$xml_file" && echo "  ✓ $(basename "$xml_file")" || echo "  ✗ $(basename "$xml_file")"
              fi
            done
          fi
          
          echo "✅ Job will pass (non-blocking for PR)"
      
      - name: Run pre-flight checks on installed Wazuh
        if: steps.check_wazuh.outputs.WAZUH_EXISTS == 'true'
        run: |
          echo "Running Wazuh pre-flight checks on installed instance..."
          echo "Runner: $(hostname)"
          
          CONFIG_FILE="${{ steps.check_wazuh.outputs.WAZUH_CONFIG_PATH }}"
          if [ ! -f "$CONFIG_FILE" ] || [ ! -s "$CONFIG_FILE" ]; then
            echo "Creating minimal config for testing..."
            
            sudo tee "$CONFIG_FILE" > /dev/null << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>
  <ruleset>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
    <include>etc/rules/*.xml</include>
    <include>etc/decoders/*.xml</include>
  </ruleset>
  <active-response>
    <disabled>yes</disabled>
  </active-response>
</ossec_config>
EOF
            echo "✓ Created minimal ossec.conf"
            sudo chown wazuh:wazuh "$CONFIG_FILE" 2>/dev/null || true
          fi
          
          # Test configuration
          echo "Testing Wazuh configuration syntax..."
          sudo /var/ossec/bin/wazuh-analysisd -t && echo "✅ Wazuh configuration is valid" || echo "⚠️  Wazuh configuration test failed (non-blocking)"
          
          # Test XML syntax
          echo ""
          echo "Testing XML syntax of PR files..."
          
          # Install xmllint if not available
          if ! command -v xmllint &> /dev/null; then
            echo "Installing xmllint..."
            sudo apt-get update && sudo apt-get install -y libxml2-utils 2>/dev/null || echo "Failed to install xmllint"
          fi
          
          # Test rules
          if [ -d "rules" ] && ls rules/*.xml 1> /dev/null 2>&1; then
            echo "Checking rule files:"
            for rule_file in rules/*.xml; do
              if [ -f "$rule_file" ]; then
                xmllint --noout "$rule_file" 2>/dev/null && echo "  ✅ $(basename "$rule_file")" || echo "  ❌ $(basename "$rule_file")"
              fi
            done
          fi
          
          # Test decoders
          if [ -d "decoders" ] && ls decoders/*.xml 1> /dev/null 2>&1; then
            echo "Checking decoder files:"
            for decoder_file in decoders/*.xml; do
              if [ -f "$decoder_file" ]; then
                xmllint --noout "$decoder_file" 2>/dev/null && echo "  ✅ $(basename "$decoder_file")" || echo "  ❌ $(basename "$decoder_file")"
              fi
            done
          fi
          
          echo ""
          echo "✅ Pre-flight checks completed"
