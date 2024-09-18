import base64
import datetime
import json
import os
import aio_pika
import certifi
import bcrypt

from bson import ObjectId
from functools import wraps
from dotenv import load_dotenv
from pytz import utc
from datetime import datetime, timedelta
from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from pymongo import UpdateOne
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
uri = os.getenv('MONGO_URI')

# MongoDB setup
client = MongoClient(uri)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'), tlsCAFile=certifi.where())
                          
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# Modify the User class to include the last activity timestamp
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username 
        self.role = role  # List of role assigned to the user
        self.last_activity = datetime.now(utc)  # Initialize last activity time

    def get_id(self):
        return self.id

    def update_activity(self):
        self.last_activity = datetime.now(utc)

    def has_role(self, role):
        return role in self.role

# Load user from MongoDB
@login_manager.user_loader
def load_user(user_id):
    db = client['Accounts']
    collection = db['Credentials']
    user = collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return None
    role = user.get('role', [])  # Get role from the user document, defaulting to an empty list
    username = user.get('username')
    return User(str(user['_id']), username, role)

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(required_role):
                return render_template('forbidden.html')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session:
        print("User is already authenticated")
        # If user is already authenticated, redirect to the dashboard
        return redirect(url_for('dashboard'))
    
    db = client['Accounts']
    collection = db['Credentials']
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Query user from MongoDB
        user = collection.find_one({"username": username})
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            print("User authenticated successfully")
            role = user.get('role', []) 
            user_obj = User(str(user['_id']), user['username'], role)  # Pass user_id to User constructor
            user_obj.update_activity()  # Update user's last activity
            login_user(user_obj)
            session['last_activity'] = user_obj.last_activity  # Store last activity in session

            return redirect(url_for('dashboard'))
        elif user:
            return render_template('login.html', error='invalid_password')
        else:
            return render_template('login.html', error='no_user')
    return render_template('login.html')

# Create a custom decorator to check session timeout
def check_session_timeout():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            last_activity = session.get('last_activity')
            if last_activity is not None and datetime.now(utc) - last_activity > timedelta(minutes=60):
                logout_user() 
                session.pop('last_activity', None)  # Remove last activity from session
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.pop('last_activity', None)  # Remove last activity from session
    return redirect(url_for('login'))

@app.route('/dashboard')
@check_session_timeout()
def dashboard():
    if session:
        return render_template('dashboard.html', current_user=current_user)
    return redirect(url_for('login'))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/chargepoint/<sn>')
@check_session_timeout()
def sn(sn):
    return render_template('charge_point.html', sn=sn)

@app.route('/accounts', methods=['GET', 'POST'])
@check_session_timeout()
def accounts():
    db = client['Accounts']
    collectionCredentials = db['Credentials']

    dbEV = client['EV_Stations']
    collectionLogs = dbEV['logs']

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            collectionCredentials.insert_one({
                "username": username,
                "password": hashed_password.decode('utf-8'),
                "role": role
            })
            collectionLogs.insert_one({
                "username": current_user.username,
                "timeStamp": datetime.now(),
                "change": 'New account named: ' + username
            })
        elif action == 'edit':
            user_id = request.form['user_id']
            username = request.form['username']
            role = request.form['role']
            collectionCredentials.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": role}})
            collectionLogs.insert_one({
                "username": current_user.username,
                "timeStamp": datetime.now(),
                "change": 'Changed role for: ' + username + ' to: ' + role
            })
        elif action == 'delete':
            user_id = request.form['user_id']
            username = request.form['username']
            collectionCredentials.delete_one({"_id": ObjectId(user_id)})
            collectionLogs.insert_one({
                "username": current_user.username,
                "timeStamp": datetime.now(),
                "change": 'Account deleted: ' + username
            })
        elif action == 'change_password':
            user_id = request.form['user_id']
            username = request.form['username']
            new_password = request.form['new_password']
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            collectionCredentials.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password.decode('utf-8')}})
            collectionLogs.insert_one({
                "username": current_user.username,
                "timeStamp": datetime.now(),
                "change": 'Changed password for account named: ' + username
            })
        elif action == 'change_username':
            user_id = request.form['user_id']
            username = request.form['username']
            new_username = request.form['new_username']
            collectionCredentials.update_one({"_id": ObjectId(user_id)}, {"$set": {"username": new_username}})
            collectionLogs.insert_one({
                "username": current_user.username,
                "timeStamp": datetime.now(),
                "change": 'Changed username for account named: ' + username + ' to: ' + new_username
            })

        # Redirect to the GET route after handling the POST request
        return redirect(url_for('accounts'))

    users = list(collectionCredentials.find())
    return render_template('accounts.html', users=users, current_user=current_user)

@app.route('/send_message', methods=['POST'])
async def send_message():
    data = request.get_json()
    message_body = json.dumps(data)
    queue_selector = data.get('queue_selector', '1')
    change = data.get('change')

    connection = await aio_pika.connect_robust("amqp://guest:guest@localhost/")
    channel = await connection.channel()

    queues = [f"charge_point_queue_{queue}" for queue in queue_selector.split(',')]
    
    for queue_name in queues:
        await channel.declare_queue(queue_name)
        await channel.default_exchange.publish(
            aio_pika.Message(body=message_body.encode()),
            routing_key=queue_name
        )

    await connection.close()

    dbEV = client['EV_Stations']
    collectionLogs = dbEV['logs']

    collectionLogs.insert_one({
        "username": current_user.username,
        "timeStamp": datetime.now(),
        "change": change
    })

    return jsonify({'success': True})

@app.route('/get_transactions')
def get_transactions():
    db = client['EV_Stations']
    collectionTransactions = db['transactions']
    collectionStations = db['stations']

    transactions = list(collectionTransactions.find())

    # Retrieve all stations data
    stations = {station['sn']: station for station in collectionStations.find()}

    # Combine transactions with their corresponding station data
    combined_data = []
    for transaction in transactions:
        station = stations.get(transaction['sn'], {})
        combined_data.append({
            'name': station.get('name', 'Unknown'),
            'sn': station.get('sn'),
            'kwPrice': transaction['kwPrice'],
            'finalAmount': transaction['finalAmount'],
            'TransactionID': transaction['TransactionID'],
            'StopTime': transaction['StopTime']
        })

    return jsonify(combined_data)

@app.route('/messages')
def messages():
    return render_template('messages.html')

@app.route('/get_data')
async def get_data():
    db = client['EV_Stations']
    collection = db['stations']

    # Retrieve data from MongoDB
    data = list(collection.find())

    # Convert MongoDB documents to JSON
    json_data = []
    for item in data:
        json_data.append({
            'name': item['name'],
            'sn': item['sn'],
            'kwPrice': item['kwPrice'],
            'series': item['series']
        })

    return jsonify(json_data)

@app.route('/get_status')
async def get_status():
    db = client['EV_Stations']
    collection = db['stations']

    # Retrieve data from MongoDB
    data = list(collection.find())

    # Convert MongoDB documents to JSON
    json_data = []
    for item in data:
        json_data.append({
            'name': item['name'],
            'sn': item['sn'],
            'kwPrice': item['kwPrice'],
            'status': item['status']
        })

    return jsonify(json_data)

@app.route('/update_kw_price', methods=['POST'])
def update_kw_price():
    db = client['EV_Stations']
    collection = db['stations']
    try:
        data = request.json
        object_name = data.get('name')
        new_kw_price = data.get('kwPrice')

        # Find the object in the database with the matching name
        target_object = next((obj for obj in collection.find({'name': object_name})), None)

        if target_object:
            # Update the kwPrice for the found object
            collection.update_one({'name': object_name}, {'$set': {'kwPrice': new_kw_price}})
            return jsonify({'message': 'Successfully updated kwPrice in the database'})
        else:
            return jsonify({'error': f'Object with name {object_name} not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/get_sn_values')
def get_sn_values():
    db = client['EV_Stations']
    collection = db['stations']
    # Retrieve objects from MongoDB collection
    objects = collection.find()

    # Extract 'sn' property values and create a comma-separated string
    sn_values = ",".join(str(obj.get('sn')) for obj in objects)

    # You can use sn_values in your application as needed
    return f"SN Values: {sn_values}"

@app.route('/add_item', methods=['POST'])
def add_item():
    try:
        data = request.get_json()
        new_item_name = data.get('name')
        new_item_sn = data.get('sn')
        new_item_kwPrice = data.get('kwPrice')
        new_series = data.get('series')

        if not new_item_name or not new_item_sn or not new_item_kwPrice or not new_series:
            return jsonify({"error": "All inputs are required"}), 400

        db = client['EV_Stations']
        collection = db['stations']
        new_item = {
            'name': new_item_name,
            'sn': new_item_sn,
            'kwPrice': new_item_kwPrice,
            'status': "disconnected",
            'series': new_series,
            'increment': 0
        }
        result = collection.insert_one(new_item)

        dbEV = client['EV_Stations']
        collectionLogs = dbEV['logs']

        collectionLogs.insert_one({
            "username": current_user.username,
            "timeStamp": datetime.now(),
            "change": 'New station added named: ' + new_item_name + ' with SN: ' + new_item_sn
        })

        return jsonify({"message": "Item added successfully", "inserted_id": str(result.inserted_id)}), 201
    except Exception as e:
        print(f"Error adding item: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/submit_report', methods=['POST'])
def submit_report():
    data = request.get_json()
    transactionId = data.get('transaction_id')
    transactions(transactionId)

    return jsonify({'status': 'success', 'transactionId': transactionId})

def transactions(transactionId):
    db = client['EV_Stations']
    collection = db['transactions']

    transactionId = int(transactionId)

    transactionDetails = collection.find_one({"TransactionID": transactionId})

    db = client['EV_Stations']
    collection = db['stations']

    station = collection.find_one({"sn": transactionDetails["sn"]})
    name = station["name"]

    # Get the current date
    formatted_time = transactionDetails["StopTime"]
    # Parse the input string into a datetime object
    parsed_time = datetime.strptime(formatted_time, "%Y-%m-%dT%H:%M:%SZ")
    # Format the datetime object in the desired format
    current_date = parsed_time.strftime("%d/%m/%Y %H:%M")

    with open('../frontend/images/logo_nobg.png', 'rb') as f:
        image_data = f.read()

    # Convert image data to base64-encoded string
    base64_image = base64.b64encode(image_data).decode('utf-8')

    # Render the HTML template for the invoice and pass session storage data
    html = render_template('transactions.html', image_data=base64_image, name=name, current_date=current_date, transactionDetails=transactionDetails)

    # Send the PDF file as a downloadable attachment
    return send_file(f"transactions/tranzactia_{transactionId}.pdf", as_attachment=True)
 
@app.route('/change_station_name', methods=['POST'])
def change_station_name():
    data = request.get_json()
    station_name = data.get('stationName')
    sn_value = data.get('snValue')

    if not station_name or not sn_value:
        return jsonify({"error": "Invalid data"}), 400

    db = client['EV_Stations']
    collection = db['stations']

    # Update the station name in the database
    result = collection.update_one(
        {'sn': sn_value},
        {'$set': {'name': station_name}}
    )

    dbEV = client['EV_Stations']
    collectionLogs = dbEV['logs']

    collectionLogs.insert_one({
        "username": current_user.username,
        "timeStamp": datetime.now(),
        "change": 'Changed name of station: ' + sn_value + ' with name: ' + station_name
    })

    if result.matched_count > 0:
        return jsonify({"success": True, "message": "Station name updated successfully"})
    else:
        return jsonify({"success": False, "message": "Station not found"}), 404

@app.route('/change_station_series', methods=['POST'])
def change_station_series():
    data = request.get_json()
    series = data.get('series')
    sn_value = data.get('snValue')

    if not series or not sn_value:
        return jsonify({"error": "Invalid data"}), 400

    db = client['EV_Stations']
    collection = db['stations']

    # Update the station name in the database
    result = collection.update_one(
        {'sn': sn_value},
        {'$set': {'series': series}}
    )

    dbEV = client['EV_Stations']
    collectionLogs = dbEV['logs']

    collectionLogs.insert_one({
        "username": current_user.username,
        "timeStamp": datetime.now(),
        "change": 'Changed series of station: ' + sn_value + ' with series: ' + series
    })

    if result.matched_count > 0:
        return jsonify({"success": True, "message": "Station name updated successfully"})
    else:
        return jsonify({"success": False, "message": "Station not found"}), 404

@app.route('/add_id_tag', methods=['POST'])
def add_id_tag():
    db = client['EV_Stations']
    banned_collection = db['banned']

    data = request.json  # Get the JSON data sent in the POST request
    id_tag = data.get('idTag')

    if not id_tag:
        return jsonify({"error": "No ID tag provided"}), 400
    
    # Insert the idTag into the banned collection as a new document
    banned_collection.insert_one({"Idtag": id_tag})

    dbEV = client['EV_Stations']
    collectionLogs = dbEV['logs']

    collectionLogs.insert_one({
        "username": current_user.username,
        "timeStamp": datetime.now(),
        "change": 'Banned ID tag: ' + id_tag
    })
    
    return jsonify({"message": "ID tag added successfully"}), 201

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False, threaded=False)
