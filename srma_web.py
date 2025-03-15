import os
import sys
import logging
import psutil
import time
from datetime import datetime
from flask import Flask, render_template, jsonify
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from threading import Thread

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/srma/web.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Fetch MongoDB configuration from environment variables
MONGO_URI = os.environ.get('MONGO_URI', " ")  # Replace with actual URI if not using env vars
MONGO_DB = os.environ.get('MONGO_DB', " ")         # Default to "SRMA" if not set
MONGO_COLLECTION = os.environ.get('MONGO_COLLECTION', " ")  # Default to "alerts" if not set

def get_mongodb_client():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000, socketTimeoutMS=5000, retryWrites=True, w='majority')
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB Atlas")
        return client
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB Atlas: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB Atlas: {e}")
        return None

client = get_mongodb_client()
if client:
    db = client[MONGO_DB]
    collection = db[MONGO_COLLECTION]
else:
    logger.warning("Running without MongoDB connection. Data will not be persisted.")


def collect_and_store_data():
    while True:
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent

            #Get Network Interface
            addrs = psutil.net_if_addrs()
            interface_name = 'wlp1s0' # Replace with your interface name.  You may need to find the correct interface name based on your system.
            try:
                net_io = psutil.net_io_counters(pernic=True)[interface_name]
                net_rx = net_io.bytes_recv / (1024**2) # MB
                net_tx = net_io.bytes_sent / (1024**2) # MB
            except KeyError:
                logger.warning(f"Network interface '{interface_name}' not found. Using 0 for network stats.")
                net_rx = 0.0
                net_tx = 0.0
            except Exception as e:
                logger.error(f"Error getting network stats: {e}")
                net_rx = 0.0
                net_tx = 0.0



            data = {
                "timestamp": datetime.utcnow(),
                "data": {
                    "cpu": cpu,
                    "mem": mem,
                    "disk": disk,
                    "net_rx": net_rx,
                    "net_tx": net_tx
                }
            }

            if client:
                try:
                    collection.insert_one(data)
                except Exception as e:
                    logger.error(f"Error inserting data into MongoDB: {e}")

        except Exception as e:
            logger.error(f"Error collecting system data: {e}")

        time.sleep(60)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def api_data():
    try:
        if not client:
            return jsonify([]) # Return empty array if MongoDB is down

        data = list(collection.find({}, {'_id': 0}).sort([("timestamp", DESCENDING)]).limit(100))
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error in /api/data route: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health():
    try:
        status = {
            "mongodb_connected": client is not None,
            "timestamp": datetime.utcnow().isoformat()
        }
        if client:
            status["document_count"] = collection.count_documents({})
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    os.makedirs('/var/log/srma', exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    data_thread = Thread(target=collect_and_store_data, daemon=True)
    data_thread.start()
    logger.info(f"Starting Flask application on port {port}")
    app.run(debug=True, host='0.0.0.0', port=port)
