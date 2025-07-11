#!/bin/bash

# HAProxy Manager API Test Script
# This script tests the new API endpoints

BASE_URL="http://localhost:8000"
API_KEY="${HAPROXY_API_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $message"
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC}: $message"
    else
        echo -e "${YELLOW}? INFO${NC}: $message"
    fi
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
    
    eval "curl -s -w \"%{http_code}\" -o /tmp/api_response.json $headers -X $method $BASE_URL$endpoint"
}

# Test health endpoint (no auth required)
test_health() {
    print_status "INFO" "Testing health endpoint..."
    local response=$(api_request "GET" "/health")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ]; then
        print_status "PASS" "Health endpoint working"
    else
        print_status "FAIL" "Health endpoint failed with status $status_code"
    fi
}

# Test domains endpoint
test_domains() {
    print_status "INFO" "Testing domains endpoint..."
    local response=$(api_request "GET" "/api/domains")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Domains endpoint responded correctly (status: $status_code)"
    else
        print_status "FAIL" "Domains endpoint failed with status $status_code"
    fi
}

# Test certificate status endpoint
test_cert_status() {
    print_status "INFO" "Testing certificate status endpoint..."
    local response=$(api_request "GET" "/api/certificates/status")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Certificate status endpoint responded correctly (status: $status_code)"
    else
        print_status "FAIL" "Certificate status endpoint failed with status $status_code"
    fi
}

# Test certificate renewal endpoint
test_cert_renewal() {
    print_status "INFO" "Testing certificate renewal endpoint..."
    local response=$(api_request "POST" "/api/certificates/renew")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Certificate renewal endpoint responded correctly (status: $status_code)"
    else
        print_status "FAIL" "Certificate renewal endpoint failed with status $status_code"
    fi
}

# Test reload endpoint
test_reload() {
    print_status "INFO" "Testing HAProxy reload endpoint..."
    local response=$(api_request "GET" "/api/reload")
    local status_code=$(echo "$response" | tail -c 4)
    
    if [ "$status_code" = "200" ] || [ "$status_code" = "401" ]; then
        print_status "PASS" "Reload endpoint responded correctly (status: $status_code)"
    else
        print_status "FAIL" "Reload endpoint failed with status $status_code"
    fi
}

# Test authentication
test_auth() {
    if [ -n "$API_KEY" ]; then
        print_status "INFO" "API key is configured"
        
        # Test with valid API key
        local response=$(api_request "GET" "/api/domains")
        local status_code=$(echo "$response" | tail -c 4)
        
        if [ "$status_code" = "200" ]; then
            print_status "PASS" "Authentication working with API key"
        else
            print_status "FAIL" "Authentication failed with API key (status: $status_code)"
        fi
    else
        print_status "INFO" "No API key configured - testing without authentication"
        
        # Test without API key
        local response=$(api_request "GET" "/api/domains")
        local status_code=$(echo "$response" | tail -c 4)
        
        if [ "$status_code" = "200" ]; then
            print_status "PASS" "API accessible without authentication"
        else
            print_status "FAIL" "API not accessible without authentication (status: $status_code)"
        fi
    fi
}

# Main test execution
main() {
    echo "HAProxy Manager API Test Suite"
    echo "=============================="
    echo "Base URL: $BASE_URL"
    echo "API Key: ${API_KEY:-"Not configured"}"
    echo ""
    
    test_health
    test_auth
    test_domains
    test_cert_status
    test_cert_renewal
    test_reload
    
    echo ""
    echo "Test completed. Check /tmp/api_response.json for detailed responses."
}

# Run tests
main "$@" 