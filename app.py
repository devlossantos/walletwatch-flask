# Import required libraries
from flask import Flask, render_template, request, jsonify, session
from flask import redirect, url_for
import jwt
from datetime import datetime, timedelta
import mysql.connector
import bcrypt

# Create a Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cct'

# MySQL configuration
db = mysql.connector.connect(
    host="localhost",
    user="cct",
    password="cctcollege2023*",
    database="walletwatch_db"
)
cursor = db.cursor()

# Function to get logged-in user's ID
def get_logged_in_user_id():
    token = session.get('token')
    if token:
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return decoded_token.get('user_id')
        except jwt.ExpiredSignatureError:
            # Token has expired
            return None
    return None

# User Registration route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the email is already taken
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        if cursor.fetchone():
            return jsonify({'message': 'Email already exists'}), 409
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the users table
        query = "INSERT INTO users (email, password) VALUES (%s, %s)"
        cursor.execute(query, (email, hashed_password))
        db.commit()

        return jsonify({'message': 'User registered successfully'})

    return render_template('signup.html')

# User Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Validate the email
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        # If user exist within the database
        if user:
            stored_password = user[2]

            # Verify password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                # Password matches

                # Get the user_id
                user_id = user[0]
                
                # Generate JWT token
                token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
                session['token'] = token

                return jsonify({'token': token}), 200
                         
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # User does not exist
        return jsonify({'message': 'User does not exist'}), 401

    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    # Add your code for the dashboard functionality here
    return render_template('dashboard.html')

# Expenses route
@app.route('/expenses')
def expenses():
    # Add your code for the expenses functionality here
    return render_template('expenses.html')

# Wallets route
# Wallets route
@app.route('/wallets', methods=['GET', 'POST'])
def wallets():
    if request.method == 'POST':
        wallet_name = request.form['walletName']
        user_id = get_logged_in_user_id()

        if user_id is not None:
            # Check if the user_id exists in the users table
            query = "SELECT * FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            user = cursor.fetchone()

            if user:
                # Insert the new wallet into the wallets table
                query = "INSERT INTO wallets (name, status, user_id) VALUES (%s, 'Active', %s)"
                cursor.execute(query, (wallet_name, user_id))
                db.commit()

                return jsonify({'message': 'Wallet added successfully'})
            else:
                return jsonify({'message': 'User does not exist'}), 401
        else:
            return jsonify({'message': 'Invalid user'}), 401

    user_id = get_logged_in_user_id()

    if user_id is not None:
        wallets = get_wallets()  # Fetch and sort the wallets

        return render_template('wallets.html', wallets=wallets)
    else:
        return jsonify({'message': 'Invalid user'}), 401

# Sort wallets to display newer wallet next to the add new wallet button
def get_wallets():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        # Fetch the wallets for the logged-in user from the database
        #query = "SELECT * FROM wallets WHERE user_id = %s OR user_id IN (SELECT wallet_id FROM wallets_users WHERE user_id = %s) ORDER BY created_at DESC"

        # Fetch the wallets for the logged-in user and shared wallets from the database
        query = """
        SELECT DISTINCT w.* FROM wallets AS w LEFT JOIN wallets_users AS u ON w.wallet_id = u.wallet_id
        WHERE w.user_id = %s OR u.user_id = %s
        ORDER BY w.created_at DESC
        """
        cursor.execute(query, (user_id,user_id))
        wallets = cursor.fetchall()

        return wallets
    else:
        return []  # Return an empty list if the user is not logged in


@app.route('/wallets/<string:wallet_name>', methods=['GET', 'POST'])
def wallet_details(wallet_name):
    wallet = get_wallet_by_name(wallet_name)
    if wallet:
        return render_template('wallet_details.html', wallet=wallet)
    else:
        return jsonify({'message': 'Wallet not found'}), 404

def get_wallet_by_name(wallet_name):
    user_id = get_logged_in_user_id()

    if user_id is not None:
        # Fetch the wallet details from the database based on the wallet name and user_id
        query = "SELECT * FROM wallets WHERE name = %s AND user_id = %s"
        cursor.execute(query, (wallet_name, user_id))
        wallet = cursor.fetchone()

        if wallet:
            # If the wallet exists, return it as a dictionary
            wallet_dict = {
                'id': wallet[0],
                'name': wallet[1],
                'status': wallet[2],
                'user_id': wallet[3],
                'created_at': wallet[4]
            }
            return wallet_dict

    # If the wallet doesn't exist or the user is not logged in, return None
    return None

# Analytics route
@app.route('/analytics')
def analytics():
    # Add your code for the analytics functionality here
    return render_template('analytics.html')

# Settings route
@app.route('/settings')
def settings():
    # Add your code for the settings functionality here
    return render_template('settings.html')     

# Logout route
@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))  

# Run the app
if __name__ == '__main__':
    app.run()