# SRMA - System Resource Monitoring Application

SRMA is a robust system resource monitoring application that provides real-time tracking of CPU, memory, and disk usage with configurable alerts and a web interface for visualization.

## Features

- Real-time system resource monitoring
- Configurable warning and critical thresholds
- Multiple alert methods (email and syslog)
- Web interface for data visualization
- MongoDB backend for historical data storage
- Health check endpoint
- Flexible configuration options

## Prerequisites

- Python 3.x
- MongoDB
- `jq` command-line JSON processor
- `bc` command-line calculator
- Modern web browser for the dashboard
- Root access for service management

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd srma
```

2. Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

3. Create and configure the configuration file:
```bash
cp srma.conf.example srma.conf
vim srma.conf
```

## Configuration

Edit `srma.conf` to set the following parameters:

- `MONITOR_INTERVAL`: Monitoring frequency in seconds
- `ALERT_METHODS`: Space-separated list of alert methods ("email" "syslog")
- `EMAIL`: Alert recipient email address
- `SYSLOG_SERVER`: Syslog server address
- `CPU_THRESHOLD`: Critical CPU usage threshold (%)
- `CPU_WARNING_THRESHOLD`: Warning CPU usage threshold (%)
- `MEMORY_THRESHOLD`: Critical memory usage threshold (%)
- `MEMORY_WARNING_THRESHOLD`: Warning memory usage threshold (%)
- `DISK_THRESHOLD`: Critical disk usage threshold (%)
- `DISK_WARNING_THRESHOLD`: Warning disk usage threshold (%)
- `MONGO_URI`: MongoDB connection string

## Usage

SRMA provides a simple command-line interface for management:

```bash
sudo ./srma.sh [command]
```

Available commands:
- `start`: Start the SRMA service
- `stop`: Stop the SRMA service
- `restart`: Restart the SRMA service
- `status`: Check the current status of SRMA

## Web Interface

Access the web dashboard at:
```
http://localhost:5000
```

The dashboard provides:
- Real-time resource usage graphs
- Historical data visualization
- System status overview

## API Endpoints

- `/`: Web dashboard
- `/api/data`: JSON endpoint for resource data
- `/health`: Service health check endpoint

## File Structure

```
srma/
├── srma.sh              # Main service control script
├── srma_config.sh       # Configuration management
├── srma_monitor.sh      # Resource monitoring
├── srma_alert.sh        # Alert handling
├── srma_web.py          # Web interface
├── srma.conf            # Configuration file
└── /var/log/srma/       # Log directory
    ├── srma.log         # Main log file
    └── web.log          # Web interface log
```

## Logging

Logs are stored in `/var/log/srma/`:
- `srma.log`: Main application logs
- `web.log`: Web interface logs

## Security Considerations

- The service requires root access for system monitoring
- MongoDB security should be configured according to your environment
- Web interface is accessible only from localhost by default
- Log directory permissions are managed automatically

## Troubleshooting

1. Check the logs in `/var/log/srma/`
2. Verify MongoDB connection
3. Ensure proper permissions
4. Check configuration file syntax
5. Verify all required dependencies are installed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[License Type] - See LICENSE file for details

## Support

For issues and feature requests, please create an issue in the GitHub repository.
