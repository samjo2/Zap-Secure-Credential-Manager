from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from web3 import Web3
import os
import secrets
import re
import uuid
from datetime import datetime, timedelta
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Connect to Ethereum Rinkeby testnet
w3 = Web3(Web3.HTTPProvider('https://rinkeby.infura.io/v3/YOUR_INFURA_PROJECT_ID'))
contract_address = '0xd9145CCE52D386f254917e481eB44e9943F39138'
contract_abi = [
    {
        "inputs": [{"internalType": "string", "name": "hash", "type": "string"}],
        "name": "storeHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getHash",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Simulated database (replace with actual database later)
users = {}
credentials = {}
password_reset_tokens = {}

# Constants
PASSWORD_REGEX = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME = 15  # minutes

# Track login attempts
login_attempts = {}

# Generate and store the encryption key securely (e.g., environment variable)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Example for Gmail
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Your email password
mail = Mail(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Validate password
        if not re.match(PASSWORD_REGEX, password):
            flash("Password must be at least 8 characters and include letters, numbers, and symbols.")
            return redirect(url_for('register'))
        
        # Check if username or email already exists
        if username in users or any(user['email'] == email for user in users.values()):
            flash("Username or email already exists")
            return redirect(url_for('register'))
        
        # Store user data
        users[username] = {
            "email": email,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user is locked out
        if username in login_attempts:
            attempts, lockout_time = login_attempts[username]
            if attempts >= MAX_LOGIN_ATTEMPTS:
                if datetime.utcnow() < lockout_time + timedelta(minutes=LOCKOUT_TIME):
                    remaining = (lockout_time + timedelta(minutes=LOCKOUT_TIME) - datetime.utcnow()).seconds // 60
                    flash(f"Account is locked. Try again in {remaining} minutes.")
                    return redirect(url_for('login'))
                else:
                    # Reset attempts after lockout period
                    login_attempts.pop(username)

        if username in users and check_password_hash(users[username]['password'], password):
            # Reset login attempts on successful login
            if username in login_attempts:
                login_attempts.pop(username)
            
            session['user'] = username
            users[username]['last_login'] = datetime.utcnow()
            return redirect(url_for('home'))
        else:
            # Track failed login attempts
            if username not in login_attempts:
                login_attempts[username] = [1, datetime.utcnow()]
            else:
                attempts, _ = login_attempts[username]
                login_attempts[username] = [attempts + 1, datetime.utcnow()]
            
            flash("Invalid credentials")
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/generate_password')
def generate_password():
    password = secrets.token_urlsafe(16)
    return jsonify({"password": password})

@app.route('/add_credential', methods=['POST'])
def add_credential():
    if 'user' not in session:
        return "Unauthorized", 401
    service = request.form['service']
    username = request.form['username']
    password = request.form['password']
    
    # Encrypt the password before storing
    encrypted_password = cipher_suite.encrypt(password.encode())
    
    if session['user'] not in credentials:
        credentials[session['user']] = {}
    credentials[session['user']][service] = {
        "username": username,
        "password": encrypted_password.decode()  # Store as string
    }
    
    # Generate the hash for the credential
    credential_hash = Web3.keccak(text=f"{service}:{username}:{password}").hex()
    
    # Store the hash in the smart contract
    tx_hash = contract.functions.storeHash(credential_hash).transact({'from': w3.eth.defaultAccount})
    w3.eth.waitForTransactionReceipt(tx_hash)

    return "Credential added", 201

@app.route('/get_credentials')
def get_credentials():
    if 'user' not in session:
        return "Unauthorized", 401
    user_credentials = credentials.get(session['user'], {})
    decrypted_credentials = {}
    for service, cred in user_credentials.items():
        # Decrypt the password before returning without mutating stored data
        decrypted_credentials[service] = {
            "username": cred["username"],
            "password": cipher_suite.decrypt(cred["password"].encode()).decode(),
        }
    return jsonify(decrypted_credentials)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Find user by email
        user = next((username for username, data in users.items() 
                    if data['email'] == email), None)
        
        if user:
            # Generate reset token
            token = str(uuid.uuid4())
            password_reset_tokens[token] = {
                'username': user,
                'created_at': datetime.utcnow()
            }
            
            # In a real application, send email with reset link
            # For now, just print it
            print(f"Password reset link: http://localhost:5000/reset-password/{token}")
            flash("If an account exists with that email, you will receive reset instructions.")
        else:
            # Don't reveal if email exists or not
            flash("If an account exists with that email, you will receive reset instructions.")
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/send_reset_email', methods=['POST'])
def send_reset_email():
    email = request.form['email']
    user = next((username for username, data in users.items() if data['email'] == email), None)
    
    if user:
        token = str(uuid.uuid4())
        password_reset_tokens[token] = {'username': user, 'created_at': datetime.utcnow()}
        reset_link = f"http://localhost:5000/reset_password/{token}"
        
        msg = Message("Password Reset Request", sender='your_email@gmail.com', recipients=[email])
        msg.body = f"To reset your password, visit the following link: {reset_link}"
        mail.send(msg)
        
        flash("If an account exists with that email, you will receive reset instructions.")
    else:
        flash("If an account exists with that email, you will receive reset instructions.")
    
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)