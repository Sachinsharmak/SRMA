#!/bin/bash

check_alert_thresholds(){
    local json_file="$1"
    
    # Validate JSON file exists
    if [[ ! -f "$json_file" ]]; then
        log_message "ERROR" "JSON file not found: $json_file"
        return 1
    fi
    
    # Read data using jq with error handling
    local cpu mem disk
    cpu=$(jq -r '.data.cpu' "$json_file") || { log_message "ERROR" "Failed to parse CPU data"; return 1; }
    mem=$(jq -r '.data.mem' "$json_file") || { log_message "ERROR" "Failed to parse memory data"; return 1; }
    disk=$(jq -r '.data.disk' "$json_file") || { log_message "ERROR" "Failed to parse disk data"; return 1; }
    
    # Use bc for floating point comparison with proper error handling
    if (( $(echo "$cpu > $CPU_WARNING_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "CPU" "$cpu" "$CPU_WARNING_THRESHOLD" "warning"
    fi
    if (( $(echo "$cpu > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "CPU" "$cpu" "$CPU_THRESHOLD" "critical"
    fi
    
    if (( $(echo "$mem > $MEMORY_WARNING_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "Memory" "$mem" "$MEMORY_WARNING_THRESHOLD" "warning"
    fi
    if (( $(echo "$mem > $MEMORY_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "Memory" "$mem" "$MEMORY_THRESHOLD" "critical"
    fi
    
    if (( $(echo "$disk > $DISK_WARNING_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "Disk" "$disk" "$DISK_WARNING_THRESHOLD" "warning"
    fi
    if (( $(echo "$disk > $DISK_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        send_alerts "$json_file" "Disk" "$disk" "$DISK_THRESHOLD" "critical"
    fi
}