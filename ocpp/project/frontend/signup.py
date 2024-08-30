import certifi
import bcrypt

from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://raresgoiceanu:YuWNxuLNwVnMvNfd@csms.bxk3l53.mongodb.net/?retryWrites=true&w=majority&appName=CSMS"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'), tlsCAFile=certifi.where())
db = client['Accounts']
credentials_collection = db['Credentials']

def hash_password(password):
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def add_credentials(username, password):
    # Check if the username already exists in the database
    existing_user = credentials_collection.find_one({'username': username})
    if existing_user:
        print(f"Username '{username}' already exists. Please choose a different username.")
        return
    
    # Hash the password before storing it
    hashed_password = hash_password(password)

    # Insert the new credentials into the database
    new_credentials = {'username': username, 'password': hashed_password}
    credentials_collection.insert_one(new_credentials)

    print(f"Credentials for '{username}' added successfully.")

if __name__ == '__main__':
    # Get input from the console
    new_username = input("Enter a new username: ")
    new_password = input("Enter a password: ")

    # Add the new credentials to the database
    add_credentials(new_username, new_password)
