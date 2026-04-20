#!/bin/bash
# Integration test script for environment variable configuration
#
# This script builds a Docker image and runs spiffe-helper with various
# environment variable configurations to verify that the configuration
# is correctly parsed and applied.
#
# Usage: ./script/docker/test-env-vars.sh
#        or: make test-integration-docker
#
# Requirements: Docker must be installed and running
#
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

IMAGE_NAME="spiffe-helper-test"
CONTAINER_PREFIX="spiffe-helper-test-"
GO_VERSION="1.25.3"

# Get the project root directory (parent of script directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up containers...${NC}"
    docker ps -a --filter "name=${CONTAINER_PREFIX}" --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null || true
}

trap cleanup EXIT

# Change to project root
cd "${PROJECT_ROOT}"

# Build the Docker image
echo -e "${GREEN}Building Docker image: ${IMAGE_NAME}${NC}"
docker build -t "${IMAGE_NAME}" -f Dockerfile --build-arg go_version="${GO_VERSION}" .

# Check if build actually succeeded by verifying image exists
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo -e "${RED}Failed to build Docker image${NC}"
    exit 1
fi

echo -e "${GREEN}Docker image built successfully${NC}\n"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    set +e  # Temporarily disable exit on error for this function
    local test_name="$1"
    shift
    local env_vars=("$@")
    
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    
    # Display environment variables for this test
    echo -e "${YELLOW}Environment variables:${NC}"
    for env_var in "${env_vars[@]}"; do
        echo "  ${env_var}"
    done
    echo ""  # Empty line for readability
    
    # Build docker run command with env vars
    local docker_cmd="docker run --rm"
    # Add SPIFFE_HLP_LOG_LEVEL=debug to all tests to see configuration output
    docker_cmd="${docker_cmd} -e SPIFFE_HLP_LOG_LEVEL=debug"
    for env_var in "${env_vars[@]}"; do
        docker_cmd="${docker_cmd} -e ${env_var}"
    done
    
    # Add daemon-mode=false to make it exit quickly
    docker_cmd="${docker_cmd} ${IMAGE_NAME} --daemon-mode=false"
    
    # Run container and capture output with 10 second timeout
    local output
    local exit_code=0
    output=$(timeout 10 ${docker_cmd} 2>&1) || exit_code=$?
    
    # Extract and display the "Reconciled configuration:" key=value pairs
    # The logrus format is: time="..." level=debug msg="Reconciled configuration: key1=value1,key2=value2,..." system=...
    local reconciled_line
    reconciled_line=$(echo "${output}" | grep "Reconciled configuration:" | head -1)
    
    if [ -n "${reconciled_line}" ]; then
        # Extract the key=value pairs from the log line
        # Pattern: msg="Reconciled configuration: key1=value1,key2=value2,..." system=...
        local reconciled_config
        reconciled_config=$(echo "${reconciled_line}" | sed 's/.*Reconciled configuration: //' | sed 's/" system=.*//')
        
        if [ -n "${reconciled_config}" ]; then
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}Reconciled Configuration:${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
            
            # Create a map of expected values from environment variables
            declare -A expected_values
            for env_var in "${env_vars[@]}"; do
                # Parse env var: SPIFFE_HLP_KEY=value
                if [[ "${env_var}" =~ ^SPIFFE_HLP_([^=]+)=(.*)$ ]]; then
                    env_key="${BASH_REMATCH[1]}"
                    env_value="${BASH_REMATCH[2]}"
                    
                    # Convert SPIFFE_HLP_KEY to config field name (lowercase, underscores)
                    # Handle special cases for nested structs
                    config_key=""
                    case "${env_key}" in
                        LISTENER_ENABLED|BIND_PORT|LIVENESS_PATH|READINESS_PATH)
                            config_key="health_checks.${env_key,,}"
                            ;;
                        *)
                            # Convert to lowercase and replace underscores
                            config_key=$(echo "${env_key}" | tr '[:upper:]' '[:lower:]')
                            ;;
                    esac
                    
                    # Handle special case for DAEMON_MODE (boolean conversion)
                    if [ "${env_key}" = "DAEMON_MODE" ]; then
                        # Store the boolean value
                        expected_values["${config_key}"]="${env_value}"
                    else
                        expected_values["${config_key}"]="${env_value}"
                    fi
                fi
            done
            
            # Also handle indexed JWTSVIDs environment variables
            local jwt_svids_indices=""
            for env_var in "${env_vars[@]}"; do
                if [[ "${env_var}" =~ ^SPIFFE_HLP_JWT_SVIDS=([0-9,]+)$ ]]; then
                    jwt_svids_indices="${BASH_REMATCH[1]}"
                fi
            done
            
            # Format as one key=value per line for better readability and validate
            local validation_errors=0
            local temp_file=$(mktemp)
            echo "${reconciled_config}" | tr ',' '\n' | sed 's/^[[:space:]]*//' > "${temp_file}"
            
            while IFS= read -r line; do
                if [ -z "${line}" ]; then
                    continue
                fi
                
                # Parse key=value
                key=$(echo "${line}" | cut -d'=' -f1)
                value=$(echo "${line}" | cut -d'=' -f2-)
                
                # Check if this value was expected from environment variables
                if [ -n "${expected_values[${key}]:-}" ]; then
                    expected_value="${expected_values[${key}]}"
                    
                    # Special handling for numeric values (file modes, ports)
                    if [[ "${key}" =~ (file_mode|bind_port)$ ]]; then
                        # Compare numeric values (handle octal notation)
                        if [ "${value}" = "${expected_value}" ] || [ "${value}" = "$((8#${expected_value}))" ]; then
                            echo -e "  ${GREEN}${key}${NC}=${YELLOW}${value}${NC} ${GREEN}✓${NC}"
                        else
                            echo -e "  ${RED}${key}${NC}=${YELLOW}${value}${NC} ${RED}✗ (expected: ${expected_value})${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    # Special handling for boolean values
                    elif [[ "${key}" =~ (enabled|expired|domains|bundle)$ ]] || [ "${key}" = "daemon_mode" ]; then
                        # Normalize boolean values for comparison
                        normalized_expected=$(echo "${expected_value}" | tr '[:upper:]' '[:lower:]')
                        normalized_value=$(echo "${value}" | tr '[:upper:]' '[:lower:]')
                        if [ "${normalized_value}" = "${normalized_expected}" ] || \
                           ([ "${normalized_expected}" = "true" ] && [ "${normalized_value}" = "1" ]) || \
                           ([ "${normalized_expected}" = "false" ] && [ "${normalized_value}" = "0" ]); then
                            echo -e "  ${GREEN}${key}${NC}=${YELLOW}${value}${NC} ${GREEN}✓${NC}"
                        else
                            echo -e "  ${RED}${key}${NC}=${YELLOW}${value}${NC} ${RED}✗ (expected: ${expected_value})${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    # String comparison
                    else
                        if [ "${value}" = "${expected_value}" ]; then
                            echo -e "  ${GREEN}${key}${NC}=${YELLOW}${value}${NC} ${GREEN}✓${NC}"
                        else
                            echo -e "  ${RED}${key}${NC}=${YELLOW}${value}${NC} ${RED}✗ (expected: ${expected_value})${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    fi
                else
                    # Not an expected value from env vars, just display it
                    if echo "${line}" | grep -q '=$'; then
                        # Empty value
                        echo -e "  ${line}"
                    else
                        # Non-empty value - highlight it
                        echo -e "  ${GREEN}${key}${NC}=${YELLOW}${value}${NC}"
                    fi
                fi
            done < "${temp_file}"
            rm -f "${temp_file}"
            
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
            
            # Validate JWTSVIDs if present
            if [ -n "${jwt_svids_indices}" ]; then
                # Parse indices (comma-separated or count)
                local env_indices_array=()
                if [[ "${jwt_svids_indices}" =~ ^[0-9]+$ ]] && [ "${#jwt_svids_indices}" -le 2 ]; then
                    # It's a count, generate indices 0, 1, 2, ..., count-1
                    local count="${jwt_svids_indices}"
                    for ((i=0; i<count; i++)); do
                        env_indices_array+=("${i}")
                    done
                else
                    # It's comma-separated indices (may be sparse like "0,2,5")
                    IFS=',' read -ra env_indices_array <<< "${jwt_svids_indices}"
                fi
                
                # Go slices are dense (0, 1, 2, ...), so we need to map env indices to slice positions
                # The populateJWTSVIDsFromEnv function processes indices in order and appends to slice
                # So env index order determines slice position (not sorted order)
                declare -A env_to_slice_pos
                local slice_pos=0
                for env_idx in "${env_indices_array[@]}"; do
                    # Check if this index actually has an AUDIENCE set (required for it to be added)
                    local has_audience=false
                    for env_var in "${env_vars[@]}"; do
                        if [[ "${env_var}" =~ ^SPIFFE_HLP_JWT_SVIDS_${env_idx}_AUDIENCE= ]]; then
                            has_audience=true
                            break
                        fi
                    done
                    if [ "${has_audience}" = "true" ]; then
                        env_to_slice_pos["${env_idx}"]="${slice_pos}"
                        slice_pos=$((slice_pos + 1))
                    fi
                done
                
                # Check each expected JWT SVID
                for env_idx in "${env_indices_array[@]}"; do
                    local expected_audience=""
                    local expected_svid_file=""
                    local expected_extra_audiences=""
                    
                    for env_var in "${env_vars[@]}"; do
                        if [[ "${env_var}" =~ ^SPIFFE_HLP_JWT_SVIDS_${env_idx}_AUDIENCE=(.*)$ ]]; then
                            expected_audience="${BASH_REMATCH[1]}"
                        elif [[ "${env_var}" =~ ^SPIFFE_HLP_JWT_SVIDS_${env_idx}_SVID_FILE_NAME=(.*)$ ]]; then
                            expected_svid_file="${BASH_REMATCH[1]}"
                        elif [[ "${env_var}" =~ ^SPIFFE_HLP_JWT_SVIDS_${env_idx}_EXTRA_AUDIENCES=(.*)$ ]]; then
                            expected_extra_audiences="${BASH_REMATCH[1]}"
                        fi
                    done
                    
                    # Get the actual slice position for this env index
                    local slice_pos="${env_to_slice_pos[${env_idx}]}"
                    
                    # Check if these values appear in reconciled config at the correct slice position
                    if [ -n "${expected_audience}" ]; then
                        if echo "${reconciled_config}" | grep -q "jwt_svids\[${slice_pos}\]\.jwt_audience=${expected_audience}"; then
                            echo -e "  ${GREEN}jwt_svids[${slice_pos}].jwt_audience${NC}=${YELLOW}${expected_audience}${NC} ${GREEN}✓${NC} (env index ${env_idx})"
                        else
                            echo -e "  ${RED}jwt_svids[${slice_pos}].jwt_audience${NC} ${RED}✗ (expected: ${expected_audience} at slice pos ${slice_pos}, env index ${env_idx}, not found)${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    fi
                    
                    if [ -n "${expected_svid_file}" ]; then
                        if echo "${reconciled_config}" | grep -q "jwt_svids\[${slice_pos}\]\.jwt_svid_file_name=${expected_svid_file}"; then
                            echo -e "  ${GREEN}jwt_svids[${slice_pos}].jwt_svid_file_name${NC}=${YELLOW}${expected_svid_file}${NC} ${GREEN}✓${NC} (env index ${env_idx})"
                        else
                            echo -e "  ${RED}jwt_svids[${slice_pos}].jwt_svid_file_name${NC} ${RED}✗ (expected: ${expected_svid_file} at slice pos ${slice_pos}, env index ${env_idx}, not found)${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    fi
                    
                    if [ -n "${expected_extra_audiences}" ]; then
                        # Convert comma-separated to semicolon-separated (as per our format)
                        expected_formatted=$(echo "${expected_extra_audiences}" | tr ',' ';')
                        if echo "${reconciled_config}" | grep -q "jwt_svids\[${slice_pos}\]\.jwt_extra_audiences=\[${expected_formatted}\]"; then
                            echo -e "  ${GREEN}jwt_svids[${slice_pos}].jwt_extra_audiences${NC}=${YELLOW}[${expected_formatted}]${NC} ${GREEN}✓${NC} (env index ${env_idx})"
                        else
                            echo -e "  ${RED}jwt_svids[${slice_pos}].jwt_extra_audiences${NC} ${RED}✗ (expected: [${expected_formatted}] at slice pos ${slice_pos}, env index ${env_idx}, not found)${NC}"
                            validation_errors=$((validation_errors + 1))
                        fi
                    fi
                done
            fi
            
            echo ""  # Empty line for readability
            
            # If validation errors occurred, mark test as failed
            if [ ${validation_errors} -gt 0 ]; then
                echo -e "${RED}✗ FAILED (${validation_errors} validation error(s) - environment variables not honored)${NC}"
                ((TESTS_FAILED++))
                set -e  # Re-enable exit on error
                return 1
            fi
        fi
    fi
    
    # Check if the error is a configuration error (which is a failure) vs connection error (which is expected)
    if echo "${output}" | grep -q "invalid configuration\|failed to parse"; then
        echo -e "${RED}✗ FAILED (configuration error)${NC}"
        ((TESTS_FAILED++))
        set -e  # Re-enable exit on error
        return 1
    elif echo "${output}" | grep -q "connection error\|no such file or directory\|Error fetching\|Error starting spiffe-helper"; then
        # Connection errors are expected when SPIRE agent is not available - config was parsed correctly
        echo -e "${GREEN}✓ PASSED (configuration valid, connection error expected)${NC}"
        ((TESTS_PASSED++))
        return 0
    elif [ ${exit_code:-0} -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        # Unknown error
        echo -e "${RED}✗ FAILED (exit code: ${exit_code:-1})${NC}"
        ((TESTS_FAILED++))
        set -e  # Re-enable exit on error
        return 1
    fi
    set -e  # Re-enable exit on error
}

# Test 1: Basic environment variables
echo -e "\n${GREEN}=== Test 1: Basic Environment Variables ===${NC}"
run_test "Basic config with required fields" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem"

# Test 2: Boolean environment variables
echo -e "\n${GREEN}=== Test 2: Boolean Environment Variables ===${NC}"
run_test "Boolean values" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_ADD_INTERMEDIATES_TO_BUNDLE=true" \
    "SPIFFE_HLP_INCLUDE_FEDERATED_DOMAINS=false" \
    "SPIFFE_HLP_OMIT_EXPIRED=true"

# Test 3: Integer environment variables
echo -e "\n${GREEN}=== Test 3: Integer Environment Variables ===${NC}"
run_test "Integer values (file modes)" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_CERT_FILE_MODE=0644" \
    "SPIFFE_HLP_KEY_FILE_MODE=0600" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_MODE=0600"

# Test 4: Health check configuration
echo -e "\n${GREEN}=== Test 4: Health Check Configuration ===${NC}"
run_test "Health check env vars" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_LISTENER_ENABLED=true" \
    "SPIFFE_HLP_BIND_PORT=8081" \
    "SPIFFE_HLP_LIVENESS_PATH=/live" \
    "SPIFFE_HLP_READINESS_PATH=/ready"

# Test 5: JWT configuration
echo -e "\n${GREEN}=== Test 5: JWT Configuration ===${NC}"
run_test "JWT bundle filename" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_NAME=jwt-bundle.json"

# Test 6: JWTSVIDs with count-based indices
echo -e "\n${GREEN}=== Test 6: JWTSVIDs - Count-based Indices ===${NC}"
run_test "JWTSVIDs count format" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_NAME=jwt-bundle.json" \
    "SPIFFE_HLP_JWT_SVIDS=2" \
    "SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE=audience-0" \
    "SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME=file-0.token" \
    "SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES=extra1,extra2" \
    "SPIFFE_HLP_JWT_SVIDS_1_AUDIENCE=audience-1" \
    "SPIFFE_HLP_JWT_SVIDS_1_SVID_FILE_NAME=file-1.token"

# Test 7: JWTSVIDs with comma-separated indices
echo -e "\n${GREEN}=== Test 7: JWTSVIDs - Comma-separated Indices ===${NC}"
run_test "JWTSVIDs comma-separated format" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_NAME=jwt-bundle.json" \
    "SPIFFE_HLP_JWT_SVIDS=0,2" \
    "SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE=audience-0" \
    "SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME=file-0.token" \
    "SPIFFE_HLP_JWT_SVIDS_2_AUDIENCE=audience-2" \
    "SPIFFE_HLP_JWT_SVIDS_2_SVID_FILE_NAME=file-2.token" \
    "SPIFFE_HLP_JWT_SVIDS_2_EXTRA_AUDIENCES=extra1,extra2,extra3"

# Test 8: Complex configuration with all options
echo -e "\n${GREEN}=== Test 8: Complex Configuration ===${NC}"
run_test "All configuration options" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_ADD_INTERMEDIATES_TO_BUNDLE=true" \
    "SPIFFE_HLP_INCLUDE_FEDERATED_DOMAINS=true" \
    "SPIFFE_HLP_OMIT_EXPIRED=false" \
    "SPIFFE_HLP_CERT_FILE_MODE=0644" \
    "SPIFFE_HLP_KEY_FILE_MODE=0600" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_MODE=0600" \
    "SPIFFE_HLP_JWT_SVID_FILE_MODE=0600" \
    "SPIFFE_HLP_JWT_BUNDLE_FILE_NAME=jwt-bundle.json" \
    "SPIFFE_HLP_LISTENER_ENABLED=true" \
    "SPIFFE_HLP_BIND_PORT=9090" \
    "SPIFFE_HLP_LIVENESS_PATH=/health/live" \
    "SPIFFE_HLP_READINESS_PATH=/health/ready" \
    "SPIFFE_HLP_HINT=test-hint" \
    "SPIFFE_HLP_RENEW_SIGNAL=SIGHUP" \
    "SPIFFE_HLP_JWT_SVIDS=1" \
    "SPIFFE_HLP_JWT_SVIDS_0_AUDIENCE=test-audience" \
    "SPIFFE_HLP_JWT_SVIDS_0_SVID_FILE_NAME=test.token" \
    "SPIFFE_HLP_JWT_SVIDS_0_EXTRA_AUDIENCES=aud1,aud2"

# Test 9: Daemon mode override
echo -e "\n${GREEN}=== Test 9: Daemon Mode Environment Variable ===${NC}"
run_test "Daemon mode via env var (false)" \
    "SPIFFE_HLP_AGENT_ADDRESS=/tmp/test-agent.sock" \
    "SPIFFE_HLP_CERT_DIR=/tmp/certs" \
    "SPIFFE_HLP_SVID_FILE_NAME=svid.pem" \
    "SPIFFE_HLP_SVID_KEY_FILE_NAME=svid-key.pem" \
    "SPIFFE_HLP_SVID_BUNDLE_FILE_NAME=bundle.pem" \
    "SPIFFE_HLP_DAEMON_MODE=false"

# Test 10: Missing required fields (should fail)
echo -e "\n${GREEN}=== Test 10: Missing Required Fields (Expected to Fail) ===${NC}"
echo -e "${YELLOW}Testing: Missing required configuration${NC}"
echo -e "${YELLOW}Container output:${NC}"
output=$(timeout 10 docker run --rm -e SPIFFE_HLP_LOG_LEVEL=debug "${IMAGE_NAME}" --daemon-mode=false 2>&1) || exit_code=$?
echo "${output}"
echo ""  # Empty line for readability

if echo "${output}" | grep -q "invalid configuration\|failed to parse"; then
    echo -e "${GREEN}✓ PASSED (correctly failed with missing config)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED (should have failed with missing config)${NC}"
    ((TESTS_FAILED++))
fi

# Summary
echo -e "\n${GREEN}=== Test Summary ===${NC}"
echo -e "Tests passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests failed: ${RED}${TESTS_FAILED}${NC}"

if [ ${TESTS_FAILED} -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi

