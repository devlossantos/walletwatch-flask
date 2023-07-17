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
    database="walletwatch_db",
    buffered=True
)

cursor = db.cursor()

# Function to check if the user is logged in
def check_login():
    if not get_logged_in_user_id():
        return redirect(url_for('login'))

# Register the before_request function to run before each request
@app.before_request
def before_request():
    check_login()

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

@app.route('/')
def home():
    return render_template('dashboard.html')   

# User Registration route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the email is already taken
        query = "SELECT * FROM users WHERE email = %s"
        cursor = db.cursor()
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
        cursor = db.cursor()
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
    user_id = get_logged_in_user_id()

    if user_id is not None:
        return render_template('dashboard.html')
    else:
        return render_template('login.html')

# Expenses route
@app.route('/expenses')
def expenses():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        return render_template('expenses.html')
    else:
        return render_template('login.html')

# Wallets route
@app.route('/wallets', methods=['GET', 'POST'])
def wallets():
    user_id = get_logged_in_user_id()

    if request.method == 'POST':
        wallet_name = request.form['walletName']

        if user_id is not None:
            # Check if the user_id exists in the users table
            query = "SELECT * FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            user = cursor.fetchone()

            if user:
                # Check if the wallet name already exists for the user
                query = "SELECT * FROM wallets WHERE name = %s AND user_id = %s"
                cursor.execute(query, (wallet_name, user_id))
                existing_wallet = cursor.fetchone()

                if existing_wallet:
                    return jsonify({'message': 'That wallet already exists, try a different name'}), 409

                # Insert the new wallet into the wallets table
                query = "INSERT INTO wallets (name, status, user_id) VALUES (%s, 'Active', %s)"
                cursor.execute(query, (wallet_name, user_id))
                db.commit()

                # Get the wallet_id of the newly created wallet
                wallet_id = cursor.lastrowid

                # Insert the new wallet into the wallets_users table
                query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
                cursor.execute(query, (wallet_id, user_id))
                db.commit()

                return jsonify({'message': 'Wallet added successfully'})
            else:
                return jsonify({'message': 'User does not exist'}), 401
        else:
            return render_template('login.html')

    else:  # Request method is GET
        wallets = get_wallets()  # Fetch and sort the wallets

        return render_template('wallets.html', wallets=wallets)

def get_wallets():
    user_id = get_logged_in_user_id()

    if user_id is not None:

        # Fetch the wallets for the logged-in user
        query = """
        SELECT DISTINCT w.* 
        FROM wallets AS w 
        LEFT JOIN wallets_users AS u ON w.wallet_id = u.wallet_id
        WHERE w.user_id = %s OR u.user_id = %s
        ORDER BY w.created_at DESC
        """
        try:
            cursor.execute(query, (user_id, user_id))
            wallets = cursor.fetchall()
            return wallets
        except Exception as e:
            print("Error executing SQL query:", e)
            return []
    else:
        return render_template('login.html')

@app.route('/wallets/<string:wallet_name>', methods=['GET', 'POST'])
def wallet_details(wallet_name):
    user_id = get_logged_in_user_id()
    wallet = get_wallet_by_name(wallet_name)

    if user_id is not None:

        if wallet:
            is_owner = wallet['user_id'] == user_id if user_id is not None else False
            shared_users = get_shared_users(cursor, wallet['wallet_id'])

            return render_template('wallet_details.html', wallet=wallet, is_owner=is_owner, shared_users=shared_users, wallet_id=wallet['wallet_id'], users=shared_users)
        else:
            return render_template('login.html')

    # Return a valid response in case user_id is None
    return redirect(url_for('login'))

@app.route('/delete_wallet', methods=['POST'])
def delete_wallet():
    wallet_id = request.json.get('wallet_id')

    if wallet_id:

        # Delete the wallet from the wallets_users table
        query = "DELETE FROM wallets_users WHERE wallet_id = %s"
        cursor.execute(query, (wallet_id,))
        db.commit()

        # Delete the wallet from the wallets table
        query = "DELETE FROM wallets WHERE wallet_id = %s"
        cursor.execute(query, (wallet_id,))
        db.commit()

        return jsonify({'message': 'Wallet deleted successfully'})

    # Wallet ID not provided
    return jsonify({'message': 'Wallet not found'}), 404

def get_shared_users(cursor, wallet_id):
    # Fetch the shared users for the given wallet ID
    owner_id = get_logged_in_user_id()

    query = """
    SELECT email 
    FROM users
    INNER JOIN wallets_users ON users.user_id = wallets_users.user_id 
    WHERE wallets_users.wallet_id = %s AND wallets_users.user_id != %s
    """
    
    cursor.execute(query, (wallet_id, owner_id))
    shared_users = [user[0] for user in cursor.fetchall()]

    return shared_users

def get_wallet_by_name(wallet_name):
    user_id = get_logged_in_user_id()

    if user_id is not None:
        
        # Fetch the wallet details from the database based on the wallet name and user_id
        query = """
        SELECT w.*
        FROM wallets AS w
        LEFT JOIN wallets_users AS u ON w.wallet_id = u.wallet_id
        WHERE w.name = %s AND (w.user_id = %s OR u.user_id = %s)
        """
        cursor.execute(query, (wallet_name, user_id, user_id))
        wallet = cursor.fetchone()

        if wallet:
            # If the wallet exists, return it as a dictionary
            wallet_dict = {
                'wallet_id': wallet[0],
                'name': wallet[1],
                'status': wallet[2],
                'user_id': wallet[3],
                'created_at': wallet[4]
            }

            return wallet_dict
        
    # If the wallet doesn't exist or the user is not logged in, return None
    return render_template('login.html')

# Add User route
@app.route('/add_user', methods=['POST'])
def add_user():
    user_email = request.json.get('email')
    wallet_id = request.json.get('wallet_id')  # Get the wallet ID from the request JSON
    user_id = get_logged_in_user_id()

    if user_email and wallet_id and user_id is not None:
        # Check if the user exists
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (user_email,))
        existing_user = cursor.fetchone()

        if existing_user:
            # Check if the user already has access to the wallet
            query = "SELECT * FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
            cursor.execute(query, (wallet_id, existing_user[0]))
            existing_wallet_user = cursor.fetchone()

            if existing_wallet_user:
                return jsonify({'message': 'User already has access to this wallet'}), 409

            # Insert the new user into the wallets_users table
            query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
            cursor.execute(query, (wallet_id, existing_user[0]))
            db.commit()

            return jsonify({'message': 'User added successfully'})

        # User does not exist
        return jsonify({'message': 'User does not exist'}), 404

    # User email not provided
    return jsonify({'message': 'Email required'}), 400

# Delete user route
@app.route('/delete_user', methods=['POST'])
def delete_user():
    user_email = request.json.get('email')
    wallet_id = request.json.get('wallet_id')  # Get the wallet ID from the request JSON
    owner_id = get_logged_in_user_id()

    if user_email and wallet_id and owner_id is not None:

        # Check if the user to be deleted exists
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (user_email,))
        user = cursor.fetchone()

        if user:
            # Check if the logged-in user is the owner of the wallet
            query = "SELECT * FROM wallets WHERE wallet_id = %s AND user_id = %s"
            cursor.execute(query, (wallet_id, owner_id))
            wallet = cursor.fetchone()

            if wallet:
                # Check if the user to be deleted is a shared user of the wallet
                query = "SELECT * FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
                cursor.execute(query, (wallet_id, user[0]))
                wallet_user = cursor.fetchone()

                if wallet_user:
                    # Delete the user from the wallets_users table
                    query = "DELETE FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
                    cursor.execute(query, (wallet_id, user[0]))
                    db.commit()

                    return jsonify({'message': 'User deleted successfully'})

                # User is not a shared user of the wallet
                return jsonify({'message': 'User is not associated with this wallet'}), 404

            # User is not the owner of the wallet
            return jsonify({'message': 'You do not have permission to delete users from this wallet'}), 403

        # User does not exist
        return jsonify({'message': 'User does not exist'}), 404

    # User email or wallet ID not provided
    return jsonify({'message': 'Invalid request'}), 400

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