#!/bin/bash

PID_FILE="/var/run/srma.pid"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (use sudo)"
        exit 1
    fi
}

setup_logging() {
    mkdir -p "/var/log/srma"
    chown -R ${SUDO_USER:-$USER}:${SUDO_USER:-$USER} "/var/log/srma"
    chmod 755 "/var/log/srma"
}

is_process_running() {
    [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null 2>&1
}

start_flask_app() {
    if ! is_process_running; then
        echo "Starting Flask application..."
        su - ${SUDO_USER:-$USER} -c "cd $(pwd) && python3 ./srma_web.py >> /var/log/srma/web.log 2>&1 & echo \$! > $PID_FILE"
        sleep 2
        if is_process_running; then
            echo "Flask application started successfully"
        else
            echo "Failed to start Flask application"
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo "Flask application is already running"
    fi
}

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
    echo $! > "$PID_FILE"
    echo "Monitoring started with PID $(cat $PID_FILE)"
}

stop_application() {
    echo "Stopping SRMA..."
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") && rm -f "$PID_FILE"
        echo "Application stopped"
    else
        echo "PID file not found. Is SRMA running?"
    fi
}

get_application_status() {
    if is_process_running; then
        echo "SRMA is running"
    else
        echo "SRMA is not running"
    fi
}

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
