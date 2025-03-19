#!/bin/bash

insert_mongodb_data() {
    local json_file="$1"

    mongosh "$MONGO_URI" --quiet --eval "
        const data = $(cat "$json_file");
        db.getSiblingDB('$MONGO_DB').$MONGO_COLLECTION.insertOne(data);
    " || {
        log_message "ERROR" "Failed to insert data into MongoDB"
        return 1
    }
}

monitor_system_resources() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local cpu mem disk
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    disk=$(df / | grep / | awk '{print $5}' | sed 's/%//g')

    jq -n --arg ts "$timestamp" --argjson cpu "$cpu" --argjson mem "$mem" --argjson disk "$disk" '{timestamp: $ts, data: {cpu: $cpu, mem: $mem, disk: $disk}}' > "$TEMP_JSON_FILE"

    insert_mongodb_data "$TEMP_JSON_FILE" || {
        log_message "ERROR" "Failed to store data in MongoDB"
        rm -f "$TEMP_JSON_FILE"
        return 1
    }

    check_alert_thresholds "$TEMP_JSON_FILE"
    rm -f "$TEMP_JSON_FILE"
}