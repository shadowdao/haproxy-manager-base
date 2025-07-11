#!/bin/bash

# HAProxy Manager External Monitoring Script
# This script monitors the HAProxy Manager from outside the container

# Configuration - modify these variables
CONTAINER_NAME="haproxy-manager"
CONTAINER_API_URL="http://localhost:8000"
LOG_DIR="/var/lib/docker/volumes/haproxy-logs/_data"  # Adjust path as needed
ERROR_LOG="$LOG_DIR/haproxy-manager-errors.log"
ALERT_EMAIL=""
WEBHOOK_URL=""
API_KEY=""

# Load configuration from file if it exists
CONFIG_FILE="/etc/haproxy-monitor.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Function to send email alert
send_email_alert() {
    local subject="$1"
    local message="$2"
    
    if [ -n "$ALERT_EMAIL" ]; then
        if command -v mail >/dev/null 2>&1; then
            echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
        else
            echo "Email alert (mail command not available): $subject - $message"
        fi
    fi
}

# Function to send webhook alert
send_webhook_alert() {
    local message="$1"
    
    if [ -n "$WEBHOOK_URL" ]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"$message\"}" >/dev/null 2>&1
    fi
}

# Function to check if container is running
check_container_status() {
    if ! docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        local alert_message="HAProxy Manager Alert: Container $CONTAINER_NAME is not running!"
        send_email_alert "HAProxy Manager Container Down" "$alert_message"
        send_webhook_alert "$alert_message"
        return 1
    fi
    return 0
}

# Function to check for recent errors
check_recent_errors() {
    local minutes="${1:-60}"  # Default to last 60 minutes
    
    if [ ! -f "$ERROR_LOG" ]; then
        echo "Error log file not found: $ERROR_LOG"
        echo "Container may not be running or log volume not mounted correctly"
        return 1
    fi
    
    # Get current timestamp minus specified minutes
    local cutoff_time=$(date -d "$minutes minutes ago" +%s)
    
    # Check for errors in the last N minutes
    local recent_errors=$(awk -v cutoff="$cutoff_time" '
        BEGIN { FS="\""; found=0 }
        /"timestamp":/ {
            # Extract timestamp and convert to epoch
            gsub(/[",]/, "", $4)
            split($4, parts, "T")
            split(parts[1], date_parts, "-")
            split(parts[2], time_parts, ":")
            timestamp = mktime(date_parts[1] " " date_parts[2] " " date_parts[3] " " time_parts[1] " " time_parts[2] " " time_parts[3])
            if (timestamp > cutoff) {
                found=1
                print $0
            }
        }
        END { exit found ? 0 : 1 }
    ' "$ERROR_LOG")
    
    if [ $? -eq 0 ]; then
        echo "Recent errors found in the last $minutes minutes:"
        echo "$recent_errors"
        
        # Send alerts
        local alert_message="HAProxy Manager Error Alert: Recent errors detected in the last $minutes minutes. Check $ERROR_LOG for details."
        send_email_alert "HAProxy Manager Error Alert" "$alert_message"
        send_webhook_alert "$alert_message"
        
        return 1  # Return error status
    else
        echo "No recent errors found in the last $minutes minutes."
        return 0  # Return success status
    fi
}

# Function to check certificate expiration via API
check_certificate_expiration() {
    local warning_days="${1:-30}"  # Default to 30 days warning
    
    if [ -z "$API_KEY" ]; then
        echo "No API key configured. Cannot check certificate status."
        return 1
    fi
    
    # Check if container is running
    if ! check_container_status; then
        return 1
    fi
    
    # Use the API to get certificate status
    local cert_status=$(curl -s -H "Authorization: Bearer $API_KEY" "$CONTAINER_API_URL/api/certificates/status")
    
    if [ $? -eq 0 ]; then
        # Parse JSON to check for expiring certificates
        local expiring_certs=$(echo "$cert_status" | jq -r --arg days "$warning_days" '
            .certificates[] | 
            select(.days_until_expiry != null and .days_until_expiry <= ($days | tonumber)) |
            "\(.domain): expires in \(.days_until_expiry) days"
        ' 2>/dev/null)
        
        if [ -n "$expiring_certs" ]; then
            echo "Certificates expiring soon:"
            echo "$expiring_certs"
            
            local alert_message="HAProxy Manager Certificate Alert: Certificates expiring soon. $expiring_certs"
            send_email_alert "HAProxy Manager Certificate Alert" "$alert_message"
            send_webhook_alert "$alert_message"
            
            return 1
        else
            echo "No certificates expiring within $warning_days days."
            return 0
        fi
    else
        echo "Failed to get certificate status from API."
        return 1
    fi
}

# Function to check API health
check_api_health() {
    local health_response=$(curl -s "$CONTAINER_API_URL/health")
    
    if [ $? -eq 0 ]; then
        local status=$(echo "$health_response" | jq -r '.status' 2>/dev/null)
        if [ "$status" = "healthy" ]; then
            echo "API health check passed"
            return 0
        else
            echo "API health check failed: $health_response"
            return 1
        fi
    else
        echo "API health check failed: cannot connect to $CONTAINER_API_URL"
        return 1
    fi
}

# Main script logic
case "${1:-help}" in
    "container")
        check_container_status
        ;;
    "health")
        check_api_health
        ;;
    "errors")
        check_recent_errors "${2:-60}"
        ;;
    "certs")
        check_certificate_expiration "${2:-30}"
        ;;
    "all")
        echo "Checking container status..."
        check_container_status
        container_status=$?
        
        echo "Checking API health..."
        check_api_health
        health_status=$?
        
        echo "Checking for recent errors..."
        check_recent_errors "${2:-60}"
        error_status=$?
        
        echo "Checking certificate expiration..."
        check_certificate_expiration "${3:-30}"
        cert_status=$?
        
        exit $((container_status + health_status + error_status + cert_status))
        ;;
    "help"|*)
        echo "HAProxy Manager External Monitoring Script"
        echo ""
        echo "Usage: $0 {container|health|errors|certs|all} [minutes] [cert_warning_days]"
        echo ""
        echo "Commands:"
        echo "  container              Check if container is running"
        echo "  health                 Check API health endpoint"
        echo "  errors [minutes]       Check for errors in the last N minutes (default: 60)"
        echo "  certs [days]           Check for certificates expiring within N days (default: 30)"
        echo "  all [minutes] [days]   Check container, health, errors, and certificates"
        echo "  help                   Show this help message"
        echo ""
        echo "Configuration:"
        echo "  Set variables at the top of this script or create $CONFIG_FILE"
        echo "  Required variables: CONTAINER_NAME, CONTAINER_API_URL, API_KEY"
        echo "  Optional variables: ALERT_EMAIL, WEBHOOK_URL, LOG_DIR"
        echo ""
        echo "Examples:"
        echo "  $0 container           # Check if container is running"
        echo "  $0 errors 30           # Check for errors in last 30 minutes"
        echo "  $0 certs 7             # Check for certificates expiring in 7 days"
        echo "  $0 all 60 14           # Check everything (60 min errors, 14 day certs)"
        ;;
esac 