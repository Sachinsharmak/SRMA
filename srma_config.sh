#!/bin/bash

CONFIG_FILE="./srma.conf"
LOG_FILE="/var/log/srma/srma.log"
TEMP_JSON_FILE="/tmp/srma_data_$$.json"

load_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_message "ERROR" "Config file not found: $CONFIG_FILE"
        return 1
    fi
    source "$CONFIG_FILE"

    required_params=("MONITOR_INTERVAL" "ALERT_METHODS" "EMAIL" "SYSLOG_SERVER" "CPU_THRESHOLD" "CPU_WARNING_THRESHOLD" "MEMORY_THRESHOLD" "MEMORY_WARNING_THRESHOLD" "DISK_THRESHOLD" "DISK_WARNING_THRESHOLD" "MONGO_URI" "MONGO_DB" "MONGO_COLLECTION")

    for param in "${required_params[@]}"; do
        if [[ -z "${!param}" ]]; then
            log_message "ERROR" "Missing required parameter: $param"
            return 1
        fi
    done

    valid_methods=("email" "syslog")
    for method in $ALERT_METHODS; do
        if [[ ! " ${valid_methods[@]} " =~ " $method " ]]; then
            log_message "ERROR" "Invalid alert method: $method"
            return 1
        fi
    done

    return 0
}

log_message() {
    local severity="$1"
    local message="$2"
    echo "$(date +"%Y-%m-%d %H:%M:%S") $severity: $message" | tee -a "$LOG_FILE"
}
