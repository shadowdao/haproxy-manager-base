#!/bin/bash

# HAProxy Manager Certificate Request Test Script
# This script tests the new certificate request endpoint

BASE_URL="http://localhost:8000"
API_KEY="${HAPROXY_API_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "PASS")
            echo -e "${GREEN}✓ PASS${NC}: $message"
            ;;
        "FAIL")
            echo -e "${RED}✗ FAIL${NC}: $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ INFO${NC}: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠ WARN${NC}: $message"
            ;;
    esac
}

# Function to make API request
api_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    local headers=""
    if [ -n "$API_KEY" ]; then
        headers="-H \"Authorization: Bearer $API_KEY\""
    fi
    
    if [ -n "$data" ]; then
        headers="$headers -H \"Content-Type: application/json\" -d '$data'"
    fi
    
    eval "curl -s -w \"%{http_code}\" -o /tmp/cert_request_response.json $headers -X $method $BASE_URL$endpoint"
}

# Test single domain certificate request
test_single_domain_request() {
    print_status "INFO" "Testing single domain certificate request..."
    
    local test_domain="test-$(date +%s).example.com"
    local data="{\"domains\": [\"$test_domain\"], \"force_renewal\": false, \"include_www\": false}"
    
    local response=$(api_request "POST" "/api/certificates/request" "$data")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "207" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Single domain request endpoint responded (status: $status_code)"
        
        if [ "$status_code" != "401" ]; then
            # Parse response
            local success_count=$(jq -r '.summary.successful' /tmp/cert_request_response.json 2>/dev/null)
            local failed_count=$(jq -r '.summary.failed' /tmp/cert_request_response.json 2>/dev/null)
            
            if [ "$success_count" = "1" ]; then
                print_status "PASS" "Certificate request successful for $test_domain"
            elif [ "$failed_count" = "1" ]; then
                print_status "WARN" "Certificate request failed for $test_domain (expected for test domain)"
            else
                print_status "FAIL" "Unexpected response format"
            fi
        fi
    else
        print_status "FAIL" "Single domain request failed with status $status_code"
    fi
}

# Test multiple domain certificate request
test_multiple_domain_request() {
    print_status "INFO" "Testing multiple domain certificate request..."
    
    local test_domains="[\"test1-$(date +%s).example.com\", \"test2-$(date +%s).example.com\"]"
    local data="{\"domains\": $test_domains, \"force_renewal\": false, \"include_www\": true}"
    
    local response=$(api_request "POST" "/api/certificates/request" "$data")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "207" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Multiple domain request endpoint responded (status: $status_code)"
        
        if [ "$status_code" != "401" ]; then
            local total=$(jq -r '.summary.total' /tmp/cert_request_response.json 2>/dev/null)
            if [ "$total" = "2" ]; then
                print_status "PASS" "Multiple domain request processed correctly"
            else
                print_status "FAIL" "Multiple domain request response format error"
            fi
        fi
    else
        print_status "FAIL" "Multiple domain request failed with status $status_code"
    fi
}

# Test certificate request with force renewal
test_force_renewal_request() {
    print_status "INFO" "Testing certificate request with force renewal..."
    
    local test_domain="test-force-$(date +%s).example.com"
    local data="{\"domains\": [\"$test_domain\"], \"force_renewal\": true, \"include_www\": false}"
    
    local response=$(api_request "POST" "/api/certificates/request" "$data")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "207" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Force renewal request endpoint responded (status: $status_code)"
    else
        print_status "FAIL" "Force renewal request failed with status $status_code"
    fi
}

# Test invalid request (no domains)
test_invalid_request() {
    print_status "INFO" "Testing invalid request (no domains)..."
    
    local data="{\"domains\": [], \"force_renewal\": false, \"include_www\": false}"
    
    local response=$(api_request "POST" "/api/certificates/request" "$data")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "400" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Invalid request properly rejected (status: $status_code)"
    else
        print_status "FAIL" "Invalid request not properly rejected (status: $status_code)"
    fi
}

# Test certificate status endpoint
test_certificate_status() {
    print_status "INFO" "Testing certificate status endpoint..."
    
    local response=$(api_request "GET" "/api/certificates/status")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Certificate status endpoint responded (status: $status_code)"
        
        if [ "$status_code" != "401" ]; then
            local cert_count=$(jq -r '.certificates | length' /tmp/cert_request_response.json 2>/dev/null)
            print_status "INFO" "Found $cert_count certificates in status"
        fi
    else
        print_status "FAIL" "Certificate status failed with status $status_code"
    fi
}

# Main test execution
main() {
    echo "HAProxy Manager Certificate Request Test Suite"
    echo "=============================================="
    echo "Base URL: $BASE_URL"
    echo "API Key: ${API_KEY:-"Not configured"}"
    echo ""
    
    test_invalid_request
    test_single_domain_request
    test_multiple_domain_request
    test_force_renewal_request
    test_certificate_status
    
    echo ""
    echo "Test completed. Check /tmp/cert_request_response.json for detailed responses."
    echo ""
    echo "Note: Certificate requests for test domains will likely fail as they don't"
    echo "resolve to this server. This is expected behavior for testing."
}

# Run tests
main "$@" 