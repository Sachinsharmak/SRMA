import os
import sys
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify
import pymongo

# Set up logging
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

# MongoDB configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
logger.info(f"Using MongoDB URI: {MONGO_URI}")

# Initialize MongoDB connection
try:
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Test the connection
    client.server_info()
    db = client["srma"]
    collection = db["resource_data"]
    logger.info("Successfully connected to MongoDB")
except pymongo.errors.ServerSelectionTimeoutError as e:
    logger.error(f"Could not connect to MongoDB: {e}")
    # Don't exit, allow the application to run even if MongoDB is not available
    client = None
except Exception as e:
    logger.error(f"Unexpected error while connecting to MongoDB: {e}")
    client = None

@app.route('/')
def index():
    try:
        # Insert test data if no data exists
        if client and collection.count_documents({}) == 0:
            test_data = {
                "timestamp": datetime.utcnow(),
                "data": {
                    "cpu": 0.0,
                    "mem": 0.0,
                    "disk": 0.0,
                    "net_rx": 0,
                    "net_tx": 0
                }
            }
            collection.insert_one(test_data)
            logger.info("Inserted test data")
        
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return f"Error loading page: {str(e)}", 500

@app.route('/api/data')
def api_data():
    try:
        if not client:
            return jsonify([{
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "cpu": 0.0,
                    "mem": 0.0,
                    "disk": 0.0,
                    "net_rx": 0,
                    "net_tx": 0
                }
            }])

        data = list(collection.find({}, {'_id': 0}).sort([("timestamp", pymongo.DESCENDING)]).limit(100))
        for item in data:
            if isinstance(item['timestamp'], datetime):
                item['timestamp'] = item['timestamp'].isoformat()
        
        logger.debug(f"Returning {len(data)} records")
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error in api_data route: {e}")
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
    # Make sure the log directory exists
    os.makedirs('/var/log/srma', exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting Flask application on port {port}")
    app.run(debug=True, host='0.0.0.0', port=port)