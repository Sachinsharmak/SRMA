import os
import sys
import logging
import psutil
import time
import json
import secrets
import bcrypt
import jwt
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, abort
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from threading import Thread
from functools import wraps



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

CORS(app)  # Enable CORS for API access from different domains
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Fetch MongoDB configuration from environment variables
MONGO_URI = os.environ.get('MONGO_URI', "")
MONGO_DB = os.environ.get('MONGO_DB', "")
MONGO_COLLECTION = os.environ.get('MONGO_COLLECTION', "")

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
    resource_collection = db[MONGO_COLLECTION]
    alerts_collection = db["alerts"]
    users_collection = db["users"]
    settings_collection = db["settings"]
    api_keys_collection = db["api_keys"]
else:
    logger.warning("Running without MongoDB connection. Data will not be persisted.")

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in the headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        # Check if token is in the URL parameters
        if not token:
            token = request.args.get('token')
            
        # Check if token is in the cookies
        if not token:
            token = request.cookies.get('token')
            
        # Check if token is in the session
        if not token and 'token' in session:
            token = session['token']
            
        if not token:
            # For API endpoints, return JSON
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token is missing'}), 401
            # For frontend routes, redirect to login
            else:
                return redirect(url_for('login'))
        
        try:
            # Decode the token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'username': data['username']})
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# API Key authentication for machine-to-machine access
def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None
        
        # Check if API key is in the headers
        if 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']
        
        # Check if API key is in the URL parameters
        if not api_key:
            api_key = request.args.get('api_key')
            
        if not api_key:
            return jsonify({'message': 'API key is missing'}), 401
            
        # Check if API key exists in the database
        api_key_doc = api_keys_collection.find_one({'key': api_key})
        if not api_key_doc:
            return jsonify({'message': 'Invalid API key'}), 401
            
        # Check if API key is expired
        if 'expires_at' in api_key_doc and api_key_doc['expires_at'] < datetime.utcnow():
            return jsonify({'message': 'API key has expired'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

# System resource collection function
def collect_and_store_data():
    while True:
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            
            # Get process information
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'memory_percent': round(pinfo['memory_percent'], 2),
                        'cpu_percent': round(pinfo['cpu_percent'], 2)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort processes by CPU usage
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            top_processes = processes[:10]  # Get top 10 processes
            
            # Get Network Interface
            addrs = psutil.net_if_addrs()
            interface_name = 'wlp1s0'  # Replace with your interface name
            try:
                net_io = psutil.net_io_counters(pernic=True)[interface_name]
                net_rx = net_io.bytes_recv / (1024**2)  # MB
                net_tx = net_io.bytes_sent / (1024**2)  # MB
            except KeyError:
                logger.warning(f"Network interface '{interface_name}' not found. Using 0 for network stats.")
                net_rx = 0.0
                net_tx = 0.0
            except Exception as e:
                logger.error(f"Error getting network stats: {e}")
                net_rx = 0.0
                net_tx = 0.0

            # Get system temperature (if available)
            temperatures = {}
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        temperatures[name] = [{
                            'label': entry.label or name,
                            'current': entry.current,
                            'high': entry.high,
                            'critical': entry.critical
                        } for entry in entries]

            # Get system load
            load_avg = psutil.getloadavg()
            
            # Get total system uptime
            uptime = time.time() - psutil.boot_time()
            
            data = {
                "timestamp": datetime.utcnow(),
                "data": {
                    "cpu": cpu,
                    "mem": mem,
                    "disk": disk,
                    "net_rx": net_rx,
                    "net_tx": net_tx,
                    "load_avg": {
                        "1min": load_avg[0],
                        "5min": load_avg[1],
                        "15min": load_avg[2]
                    },
                    "uptime": uptime,
                    "temperatures": temperatures,
                    "top_processes": top_processes
                }
            }

            if client:
                try:
                    resource_collection.insert_one(data)
                    
                    # Check thresholds and create alerts if necessary
                    settings = settings_collection.find_one({"_id": "global"})
                    if settings:
                        if cpu > settings['thresholds']['cpu_critical']:
                            create_alert('CPU', cpu, settings['thresholds']['cpu_critical'], 'critical')
                        elif cpu > settings['thresholds']['cpu_warning']:
                            create_alert('CPU', cpu, settings['thresholds']['cpu_warning'], 'warning')
                            
                        if mem > settings['thresholds']['mem_critical']:
                            create_alert('Memory', mem, settings['thresholds']['mem_critical'], 'critical')
                        elif mem > settings['thresholds']['mem_warning']:
                            create_alert('Memory', mem, settings['thresholds']['mem_warning'], 'warning')
                            
                        if disk > settings['thresholds']['disk_critical']:
                            create_alert('Disk', disk, settings['thresholds']['disk_critical'], 'critical')
                        elif disk > settings['thresholds']['disk_warning']:
                            create_alert('Disk', disk, settings['thresholds']['disk_warning'], 'warning')
                except Exception as e:
                    logger.error(f"Error inserting resource data: {e}")
            
            logger.debug(f"Resource data collected: CPU: {cpu}%, Memory: {mem}%, Disk: {disk}%")
        except Exception as e:
            logger.error(f"Error collecting system resources: {e}")
        
        # Sleep for the configured interval
        time.sleep(5)  # Sleep for 60 seconds between data collections

# Function to create alerts
def create_alert(resource_type, value, threshold, severity):
    alert = {
        "timestamp": datetime.utcnow(),
        "resource": resource_type,
        "value": value,
        "threshold": threshold,
        "severity": severity,
        "acknowledged": False
    }
    
    try:
        alerts_collection.insert_one(alert)
        logger.warning(f"{severity.upper()} ALERT: {resource_type} at {value}% (threshold: {threshold}%)")
    except Exception as e:
        logger.error(f"Failed to create alert: {e}")

# Start the resource collection in a background thread
def start_resource_collection():
    if client:
        thread = Thread(target=collect_and_store_data)
        thread.daemon = True
        thread.start()
        logger.info("Resource collection thread started")
    else:
        logger.error("Cannot start resource collection: No MongoDB connection")

# Routes

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:  # Basic validation
            return render_template('signup.html', error="Username and password are required.")
        
        if users_collection.find_one({'username': username}):
            return render_template('signup.html', error="Username already exists.")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({'username': username, 'password': hashed_password})
        return redirect(url_for('login'))  # Redirect to login after signup

    return render_template('signup.html') # Create the signup template

@app.route('/')
@token_required
def index(current_user):
    return render_template('index.html', user=current_user)

# Add a fallback route for unauthenticated users
@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_collection.find_one({'username': username})
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # Generate JWT token
            token = jwt.encode({
                'username': username,
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            }, app.config['JWT_SECRET_KEY'])
            
            # Set token in session
            session['token'] = token
            
            # Also set token in cookie for backup
            response = redirect(url_for('index'))
            response.set_cookie('token', token, httponly=True, 
                               max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            return response
        
        return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))

@app.route('/api/health')
def health_check():
    status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'mongodb_connected': client is not None,
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent
    }
    return jsonify(status)

@app.route('/api/data')
@token_required
def get_data(current_user):
    try:
        # Get the last 100 data points, sorted by timestamp in descending order
        data_points = list(resource_collection.find().sort('timestamp', DESCENDING).limit(100))
        
        # Convert ObjectId to string for JSON serialization
        for point in data_points:
            point['_id'] = str(point['_id'])
            point['timestamp'] = point['timestamp'].isoformat()
            
        return jsonify(data_points)
    except Exception as e:
        logger.error(f"Error fetching data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/data/latest')
@token_required
def get_latest_data(current_user):
    try:
        # Get the most recent data point
        latest = resource_collection.find_one(sort=[('timestamp', DESCENDING)])
        
        if latest:
            latest['_id'] = str(latest['_id'])
            latest['timestamp'] = latest['timestamp'].isoformat()
            return jsonify(latest)
        else:
            return jsonify({'error': 'No data available'}), 404
    except Exception as e:
        logger.error(f"Error fetching latest data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
@token_required
def get_alerts(current_user):
    try:
        # Get query parameters
        severity = request.args.get('severity', None)
        acknowledged = request.args.get('acknowledged', None)
        limit = int(request.args.get('limit', 100))
        
        # Build query
        query = {}
        if severity:
            query['severity'] = severity
        if acknowledged is not None:
            query['acknowledged'] = acknowledged.lower() == 'true'
            
        # Get alerts from database
        alerts = list(alerts_collection.find(query).sort('timestamp', DESCENDING).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for alert in alerts:
            alert['_id'] = str(alert['_id'])
            alert['timestamp'] = alert['timestamp'].isoformat()
            
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
@token_required
def acknowledge_alert(current_user, alert_id):
    try:
        result = alerts_collection.update_one(
            {'_id': ObjectId(alert_id)},
            {'$set': {'acknowledged': True}}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Alert not found or already acknowledged'}), 404
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['GET'])
@token_required
def get_settings(current_user):
    try:
        settings = settings_collection.find_one({"_id": "global"})
        if settings:
            settings['_id'] = str(settings['_id'])
            return jsonify(settings)
        else:
            # Return default settings if none exist
            default_settings = {
                'thresholds': {
                    'cpu_warning': 70,
                    'cpu_critical': 90,
                    'mem_warning': 70,
                    'mem_critical': 90,
                    'disk_warning': 80,
                    'disk_critical': 95
                },
                'alert_methods': ['email', 'syslog'],
                'monitor_interval': 60
            }
            return jsonify(default_settings)
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['POST'])
@token_required
def update_settings(current_user):
    try:
        settings = request.get_json()
        
        # Validate settings
        if 'thresholds' not in settings:
            return jsonify({'error': 'Missing thresholds in settings'}), 400
            
        required_thresholds = ['cpu_warning', 'cpu_critical', 'mem_warning', 'mem_critical', 'disk_warning', 'disk_critical']
        for threshold in required_thresholds:
            if threshold not in settings['thresholds']:
                return jsonify({'error': f'Missing {threshold} in thresholds'}), 400
                
        # Update settings in database
        result = settings_collection.update_one(
            {"_id": "global"},
            {"$set": settings},
            upsert=True
        )
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    try:
        # Check if current user is admin
        if current_user.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
            
        users = list(users_collection.find({}, {'password': 0}))
        
        # Convert ObjectId to string for JSON serialization
        for user in users:
            user['_id'] = str(user['_id'])
            
        return jsonify(users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@token_required
def create_user(current_user):
    try:
        # Check if current user is admin
        if current_user.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
            
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['username', 'password', 'role']):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Check if username already exists
        if users_collection.find_one({'username': data['username']}):
            return jsonify({'error': 'Username already exists'}), 409
            
        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Create user
        new_user = {
            'username': data['username'],
            'password': hashed_password,
            'role': data['role'],
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_user)
        
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    try:
        # Check if current user is admin or updating their own account
        if current_user.get('role') != 'admin' and str(current_user['_id']) != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        data = request.get_json()
        updates = {}
        
        # Handle password update
        if 'password' in data:
            updates['password'] = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            
        # Handle role update (admin only)
        if 'role' in data and current_user.get('role') == 'admin':
            updates['role'] = data['role']
            
        if not updates:
            return jsonify({'error': 'No valid updates provided'}), 400
            
        # Update user
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': updates}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/api-keys', methods=['POST'])
@token_required
def create_api_key(current_user):
    try:
        data = request.get_json() or {}
        
        # Generate API key
        api_key = secrets.token_hex(32)
        
        # Set expiration if provided
        expires_at = None
        if 'expires_in_days' in data:
            expires_at = datetime.utcnow() + timedelta(days=int(data['expires_in_days']))
        
        # Create API key document
        new_api_key = {
            'key': api_key,
            'created_by': current_user['username'],
            'created_at': datetime.utcnow(),
            'description': data.get('description', ''),
            'expires_at': expires_at
        }
        
        result = api_keys_collection.insert_one(new_api_key)
        
        return jsonify({
            'key': api_key,
            'id': str(result.inserted_id),
            'expires_at': expires_at.isoformat() if expires_at else None
        })
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/api-keys', methods=['GET'])
@token_required
def list_api_keys(current_user):
    try:
        # Determine which API keys to show based on user role
        query = {}
        if current_user.get('role') != 'admin':
            query['created_by'] = current_user['username']
            
        api_keys = list(api_keys_collection.find(query, {'key': 0}))  # Don't return actual keys for security
        
        # Convert ObjectId to string for JSON serialization
        for key in api_keys:
            key['_id'] = str(key['_id'])
            if key.get('expires_at'):
                key['expires_at'] = key['expires_at'].isoformat()
            key['created_at'] = key['created_at'].isoformat()
            
        return jsonify(api_keys)
    except Exception as e:
        logger.error(f"Error listing API keys: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/api-keys/<key_id>', methods=['DELETE'])
@token_required
def revoke_api_key(current_user, key_id):
    try:
        # Determine which API keys the user can delete
        query = {'_id': ObjectId(key_id)}
        if current_user.get('role') != '':
            query['created_by'] = current_user['username']
            
        result = api_keys_collection.delete_one(query)
        
        if result.deleted_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'API key not found or unauthorized'}), 404
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['GET'])
@token_required
def export_data(current_user):
    try:
        # Get parameters
        data_type = request.args.get('type', 'resources')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        format = request.args.get('format', 'json')
        
        # Build query
        query = {}
        if start_date or end_date:
            query['timestamp'] = {}
            if start_date:
                try:
                    start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    query['timestamp']['$gte'] = start
                except ValueError:
                    return jsonify({'error': 'Invalid start_date format'}), 400
            if end_date:
                try:
                    end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    query['timestamp']['$lte'] = end
                except ValueError:
                    return jsonify({'error': 'Invalid end_date format'}), 400
        
        # Get data from appropriate collection
        if data_type == 'resources':
            collection = resource_collection
        elif data_type == 'alerts':
            collection = alerts_collection
        else:
            return jsonify({'error': 'Invalid data type'}), 400
            
        data = list(collection.find(query).sort('timestamp', DESCENDING))
        
        # Convert ObjectId to string for JSON serialization
        for item in data:
            item['_id'] = str(item['_id'])
            item['timestamp'] = item['timestamp'].isoformat()
        
        # Return data in requested format
        if format == 'json':
            return jsonify(data)
        elif format == 'csv':
            if not data:
                return jsonify({'error': 'No data to export'}), 404
                
            # Flatten nested data
            flattened_data = []
            for item in data:
                flat_item = {'_id': item['_id'], 'timestamp': item['timestamp']}
                
                if data_type == 'resources':
                    flat_item.update({
                        'cpu': item['data']['cpu'],
                        'mem': item['data']['mem'],
                        'disk': item['data']['disk'],
                        'net_rx': item['data']['net_rx'],
                        'net_tx': item['data']['net_tx'],
                        'load_1min': item['data']['load_avg']['1min'],
                        'load_5min': item['data']['load_avg']['5min'],
                        'load_15min': item['data']['load_avg']['15min'],
                        'uptime': item['data']['uptime']
                    })
                else:  # alerts
                    flat_item.update({
                        'resource': item['resource'],
                        'value': item['value'],
                        'threshold': item['threshold'],
                        'severity': item['severity'],
                        'acknowledged': item['acknowledged']
                    })
                
                flattened_data.append(flat_item)
            
            # Convert to CSV
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)
            
            # Create response
            response = app.response_class(
                response=output.getvalue(),
                status=200,
                mimetype='text/csv'
            )
            response.headers["Content-Disposition"] = f"attachment; filename={data_type}_export.csv"
            return response
        else:
            return jsonify({'error': 'Invalid format'}), 400
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return jsonify({'error': str(e)}), 500

# Initialize admin user if none exists
def initialize_admin_user():
    if client and users_collection.count_documents({}) == 0:
        admin_password = os.environ.get('ADMIN_PASSWORD', ' ')
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        
        admin_user = {
            'username': 'admin',
            'password': hashed_password,
            'role': 'admin',
            'created_at': datetime.utcnow()
        }
        
        users_collection.insert_one(admin_user)
        logger.info("Created default admin user")

# Initialize default settings if none exist
def initialize_settings():
    if client and settings_collection.count_documents({"_id": "global"}) == 0:
        default_settings = {
            "_id": "global",
            "thresholds": {
                "cpu_warning": 70,
                "cpu_critical": 90,
                "mem_warning": 70,
                "mem_critical": 90,
                "disk_warning": 80,
                "disk_critical": 95
            },
            "alert_methods": ["email", "syslog"],
            "monitor_interval": 60
        }
        
        settings_collection.insert_one(default_settings)
        logger.info("Created default settings")

# Main execution
if __name__ == '__main__':
    # Initialize data if needed
    if client:
        initialize_admin_user()
        initialize_settings()
    
    # Start resource collection thread
    start_resource_collection()
    
    # Start Flask application
    app.run(host='0.0.0.0', port=5000, debug=True)