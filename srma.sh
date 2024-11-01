#!/bin/bash

# Function to ensure we're running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi
}

# Function to set up logging
setup_logging() {
    local log_dir="/var/log/srma"
    mkdir -p "$log_dir"
    chown -R $SUDO_USER:$SUDO_USER "$log_dir"
    chmod 755 "$log_dir"
}

# Function to check if process is running
is_process_running() {
    local pname=$1
    pgrep -f "$pname" >/dev/null
    return $?
}

# Function to start the Flask app
start_flask_app() {
    if ! is_process_running "srma_web.py"; then
        echo "Starting Flask application..."
        su - $SUDO_USER -c "cd $(pwd) && python3 ./srma_web.py >> /var/log/srma/web.log 2>&1 &"
        sleep 2
        if is_process_running "srma_web.py"; then
            echo "Flask application started successfully"
        else
            echo "Failed to start Flask application"
            exit 1
        fi
    else
        echo "Flask application is already running"
    fi
}

# Function to start the monitoring
start_monitoring() {
    echo "Starting system monitoring..."
    while true; do
        source ./srma_config.sh || exit 1
        source ./srma_monitor.sh || exit 1
        source ./srma_alert.sh || exit 1
        
        if ! monitor_system_resources; then
            echo "System resource monitoring failed, retrying in 60 seconds..."
            sleep 60
            continue
        fi
        
        sleep "${MONITOR_INTERVAL:-60}"
    done >> /var/log/srma/monitor.log 2>&1 &
    echo "Monitoring started with PID $!"
}

# Function to stop all components
stop_application() {
    echo "Stopping SRMA..."
    pkill -f "srma_web.py"
    pkill -f "monitor_system_resources"
    echo "All components stopped"
}

# Function to get application status
get_application_status() {
    if is_process_running "srma_web.py" && is_process_running "monitor_system_resources"; then
        echo "SRMA is running"
        return 0
    else
        echo "SRMA is not running"
        return 1
    fi
}

# Main execution
check_root

case "${1:-start}" in
    start)
        setup_logging
        start_flask_app
        start_monitoring
        echo "SRMA started successfully"
        ;;
    stop)
        stop_application
        ;;
    restart)
        stop_application
        sleep 2
        setup_logging
        start_flask_app
        start_monitoring
        ;;
    status)
        get_application_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac