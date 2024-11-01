#!/bin/bash

# Function to insert data into MongoDB
insert_mongodb_data() {
    local json_file="$1"
    local mongo_uri="${MONGO_URI:-mongodb://localhost:27017}"
    
    # Attempt to insert the data into MongoDB
    mongosh "$mongo_uri" --quiet --eval "
        const data = $(cat "$json_file");
        db.getSiblingDB('srma').resource_data.insertOne(data);
    " || {
        log_message "ERROR" "Failed to insert data into MongoDB"
        return 1
    }
}

monitor_system_resources() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local resource_data
    resource_data=$(get_resource_data) || {
        log_message "ERROR" "Failed to retrieve resource data: $?"
        return 1
    }
    
    # Create valid JSON with proper escaping
    jq -n \
        --arg ts "$timestamp" \
        --argjson data "$resource_data" \
        '{timestamp: $ts, data: $data}' > "$TEMP_JSON_FILE"
    
    # Insert data into MongoDB
    insert_mongodb_data "$TEMP_JSON_FILE" || {
        log_message "ERROR" "Failed to store data in MongoDB"
        rm -f "$TEMP_JSON_FILE"
        return 1
    }
    
    check_alert_thresholds "$TEMP_JSON_FILE"
    rm -f "$TEMP_JSON_FILE"
}