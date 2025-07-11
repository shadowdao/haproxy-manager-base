#!/bin/bash

# HAProxy Manager Error Monitoring Script
# This script monitors the error log and can send alerts

ERROR_LOG="/var/log/haproxy-manager-errors.log"
ALERT_EMAIL=""
WEBHOOK_URL=""

# Function to send email alert
send_email_alert() {
    local subject="$1"
    local message="$2"
    
    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
    fi
}

# Function to send webhook alert
send_webhook_alert() {
    local message="$1"
    
    if [ -n "$WEBHOOK_URL" ]; then
        curl -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"$message\"}"
    fi
}

# Function to check for recent errors
check_recent_errors() {
    local minutes="${1:-60}"  # Default to last 60 minutes
    
    if [ ! -f "$ERROR_LOG" ]; then
        echo "Error log file not found: $ERROR_LOG"
        exit 1
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

# Function to check certificate expiration
check_certificate_expiration() {
    local warning_days="${1:-30}"  # Default to 30 days warning
    
    # Use the API to get certificate status
    local api_key="${HAPROXY_API_KEY:-}"
    local base_url="http://localhost:8000"
    
    if [ -n "$api_key" ]; then
        local cert_status=$(curl -s -H "Authorization: Bearer $api_key" "$base_url/api/certificates/status")
        
        if [ $? -eq 0 ]; then
            # Parse JSON to check for expiring certificates
            local expiring_certs=$(echo "$cert_status" | jq -r --arg days "$warning_days" '
                .certificates[] | 
                select(.days_until_expiry != null and .days_until_expiry <= ($days | tonumber)) |
                "\(.domain): expires in \(.days_until_expiry) days"
            ')
            
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
    else
        echo "No API key configured. Cannot check certificate status."
        return 1
    fi
}

# Main script logic
case "${1:-help}" in
    "errors")
        check_recent_errors "${2:-60}"
        ;;
    "certs")
        check_certificate_expiration "${2:-30}"
        ;;
    "all")
        echo "Checking for recent errors..."
        check_recent_errors "${2:-60}"
        error_status=$?
        
        echo "Checking certificate expiration..."
        check_certificate_expiration "${3:-30}"
        cert_status=$?
        
        exit $((error_status + cert_status))
        ;;
    "help"|*)
        echo "HAProxy Manager Monitoring Script"
        echo ""
        echo "Usage: $0 {errors|certs|all} [minutes] [cert_warning_days]"
        echo ""
        echo "Commands:"
        echo "  errors [minutes]     Check for errors in the last N minutes (default: 60)"
        echo "  certs [days]         Check for certificates expiring within N days (default: 30)"
        echo "  all [minutes] [days] Check both errors and certificates"
        echo "  help                 Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  ALERT_EMAIL          Email address for alerts"
        echo "  WEBHOOK_URL          Webhook URL for alerts"
        echo "  HAPROXY_API_KEY      API key for certificate status checks"
        echo ""
        echo "Examples:"
        echo "  $0 errors 30         # Check for errors in last 30 minutes"
        echo "  $0 certs 7           # Check for certificates expiring in 7 days"
        echo "  $0 all 60 14         # Check both (60 min errors, 14 day certs)"
        ;;
esac 