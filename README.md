# SRMA - System Resource Monitoring Application

SRMA is a real-time system resource monitoring and alerting web application built using **Flask**, **MongoDB Atlas**, and **JWT Authentication**. It provides detailed visualization of system metrics and automated alerts based on customizable thresholds, enabling proactive system health management.

---

## 🚀 Features

- **Real-time System Resource Monitoring**  
  Monitor CPU, memory, disk, network usage, system load, and temperatures in real-time.

- **Dynamic Dashboard with Interactive Charts**  
  Visualize system performance metrics through intuitive and interactive dashboards. Includes auto-refresh functionality.

- **User Authentication and Access Control**  
  Secure user authentication using JWT (JSON Web Token). Supports role-based access (Admin/User).

- **Automated Alert System**  
  Generate and send alerts for resource thresholds (warning/critical levels) via:
  - 📧 Email  
  - 📝 Syslog  
  - 🔗 Webhooks  

- **Background Data Collection**  
  Uses Python `threading` and `psutil` for accurate and continuous system resource monitoring.

- **API Key Management**  
  Supports API keys for secure machine-to-machine communication with optional expiration.

- **Modular and Scalable Architecture**  
  Easily extendable to add new resource metrics, alert channels, or data export features.

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask  
- **Frontend:** Bootstrap, Chart.js  
- **Database:** MongoDB Atlas  
- **Authentication:** JWT, Bcrypt  
- **Monitoring:** Psutil  
- **Automation & Scripts:** Bash, jq, mongosh  
- **Deployment:** Runs on Linux environment

---

## ⚙️ Setup and Installation

### Prerequisites
- Python 3.x
- MongoDB Atlas account
- Linux environment
- SMTP Server (Optional for email alerts)

### Installation Steps

1. **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/srma.git
    cd srma
    ```

2. **Create and Activate Virtual Environment**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set Environment Variables**
    Create a `.env` file or export manually:
    ```bash
    export MONGO_URI="your_mongodb_uri"
    export MONGO_DB="SRMA"
    export JWT_SECRET_KEY="your_jwt_secret_key"
    export ADMIN_PASSWORD="your_admin_password"
    ```

5. **Run the Application**
    ```bash
    python srma_web.py
    ```

6. **Access the App**  
    Visit `http://localhost:5000` in your browser.

---

## 📝 Configuration

Modify `srma.conf` for alert thresholds and monitoring parameters:
```bash
MONITOR_INTERVAL=60
EMAIL="admin@example.com"
SYSLOG_SERVER="localhost"
ALERT_METHODS="email syslog"
CPU_THRESHOLD=90
MEMORY_THRESHOLD=90
DISK_THRESHOLD=95
MONGO_URI="your_mongodb_uri"
MONGO_DB="SRMA"
