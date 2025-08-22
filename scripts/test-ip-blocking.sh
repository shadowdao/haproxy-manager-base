#!/bin/bash

# HAProxy Manager IP Blocking Test Script
# This script tests the IP blocking functionality

BASE_URL="http://localhost:8000"
API_KEY="${HAPROXY_API_KEY:-}"
TEST_IP="192.168.100.50"

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
    
    eval "curl -s -w '\n%{http_code}' $headers -X $method $BASE_URL$endpoint"
}

echo "HAProxy Manager IP Blocking Test Suite"
echo "======================================"
echo "Base URL: $BASE_URL"
echo "API Key: ${API_KEY:-"Not configured"}"
echo "Test IP: $TEST_IP"
echo ""

# Test 1: Get current blocked IPs
print_status "INFO" "Testing GET /api/blocked-ips endpoint..."
response=$(api_request "GET" "/api/blocked-ips")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
    print_status "PASS" "Get blocked IPs endpoint working (status: $http_code)"
    echo "Current blocked IPs: $body"
else
    print_status "FAIL" "Get blocked IPs failed with status $http_code"
fi

echo ""

# Test 2: Block an IP
print_status "INFO" "Testing POST /api/blocked-ips endpoint..."
block_data='{
    "ip_address": "'$TEST_IP'",
    "reason": "Test blocking from script",
    "blocked_by": "Test Script"
}'

response=$(api_request "POST" "/api/blocked-ips" "$block_data")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
    print_status "PASS" "Block IP endpoint working - IP $TEST_IP blocked"
    echo "Response: $body"
elif [ "$http_code" = "409" ]; then
    print_status "INFO" "IP $TEST_IP is already blocked"
elif [ "$http_code" = "401" ]; then
    print_status "FAIL" "Authentication required (check API key)"
else
    print_status "FAIL" "Block IP failed with status $http_code"
    echo "Response: $body"
fi

echo ""

# Test 3: Try to block same IP again (should get 409)
print_status "INFO" "Testing duplicate block (should fail)..."
response=$(api_request "POST" "/api/blocked-ips" "$block_data")
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "409" ]; then
    print_status "PASS" "Duplicate block correctly rejected with 409"
else
    print_status "FAIL" "Unexpected status $http_code for duplicate block"
fi

echo ""

# Test 4: Get blocked IPs to verify our IP is there
print_status "INFO" "Verifying IP is in blocked list..."
response=$(api_request "GET" "/api/blocked-ips")
body=$(echo "$response" | head -n -1)

if echo "$body" | grep -q "$TEST_IP"; then
    print_status "PASS" "IP $TEST_IP found in blocked list"
else
    print_status "FAIL" "IP $TEST_IP not found in blocked list"
fi

echo ""

# Test 5: Unblock the IP
print_status "INFO" "Testing DELETE /api/blocked-ips endpoint..."
unblock_data='{"ip_address": "'$TEST_IP'"}'

response=$(api_request "DELETE" "/api/blocked-ips" "$unblock_data")
http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

if [ "$http_code" = "200" ]; then
    print_status "PASS" "Unblock IP endpoint working - IP $TEST_IP unblocked"
    echo "Response: $body"
elif [ "$http_code" = "404" ]; then
    print_status "INFO" "IP $TEST_IP was not in blocked list"
elif [ "$http_code" = "401" ]; then
    print_status "FAIL" "Authentication required (check API key)"
else
    print_status "FAIL" "Unblock IP failed with status $http_code"
fi

echo ""

# Test 6: Try to unblock non-existent IP (should get 404)
print_status "INFO" "Testing unblock of non-existent IP..."
fake_data='{"ip_address": "1.2.3.4"}'
response=$(api_request "DELETE" "/api/blocked-ips" "$fake_data")
http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" = "404" ]; then
    print_status "PASS" "Non-existent IP correctly returned 404"
else
    print_status "FAIL" "Unexpected status $http_code for non-existent IP"
fi

echo ""

# Test 7: Test missing IP address in request
print_status "INFO" "Testing requests with missing IP address..."
invalid_data='{}'

response=$(api_request "POST" "/api/blocked-ips" "$invalid_data")
http_code=$(echo "$response" | tail -n 1)
if [ "$http_code" = "400" ]; then
    print_status "PASS" "Block request with missing IP correctly returned 400"
else
    print_status "FAIL" "Unexpected status $http_code for missing IP in block request"
fi

response=$(api_request "DELETE" "/api/blocked-ips" "$invalid_data")
http_code=$(echo "$response" | tail -n 1)
if [ "$http_code" = "400" ]; then
    print_status "PASS" "Unblock request with missing IP correctly returned 400"
else
    print_status "FAIL" "Unexpected status $http_code for missing IP in unblock request"
fi

echo ""
echo "======================================"
echo "IP Blocking tests completed"
echo ""
echo "To manually test the blocked page:"
echo "1. Block an IP: curl -X POST $BASE_URL/api/blocked-ips -H 'Authorization: Bearer YOUR_KEY' -H 'Content-Type: application/json' -d '{\"ip_address\": \"YOUR_IP\"}'"
echo "2. Access any domain through HAProxy from that IP"
echo "3. You should see the 'Access Denied' page"