#!/bin/bash

send_alerts() {
    local json_file="$1"
    local resource="$2"
    local value="$3"
    local threshold="$4"
    local severity="$5"

    for method in $ALERT_METHODS; do
        case $method in
            email)
                echo "Sending email alert..."
                echo "[$severity] $resource usage is $value% (threshold: $threshold%)" | mail -s "SRMA Alert: $resource $severity" "$EMAIL"
                ;;
            syslog)
                logger -n "$SYSLOG_SERVER" -t SRMA "[$severity] $resource usage is $value% (threshold: $threshold%)"
                ;;
            *)
                log_message "WARNING" "Unknown alert method: $method"
                ;;
        esac
    done
}

check_alert_thresholds() {
    local json_file="$1"

    if [[ ! -f "$json_file" ]]; then
        log_message "ERROR" "JSON file not found: $json_file"
        return 1
    fi

    local cpu mem disk
    cpu=$(jq -r '.data.cpu' "$json_file")
    mem=$(jq -r '.data.mem' "$json_file")
    disk=$(jq -r '.data.disk' "$json_file")

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