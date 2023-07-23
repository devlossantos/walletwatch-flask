# Import required libraries
from flask import Flask, render_template, request, jsonify, session
from flask import redirect, url_for
import jwt
from functools import wraps
from datetime import datetime, timedelta
import mysql.connector
import bcrypt

# Custom decorator to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            # Redirect to the login page if the token is missing
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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
@login_required
def home():
    return render_template('dashboard.html')   

# User Registration route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_email = request.form['user_email']
        user_password = request.form['user_password']

        # Check if the email is already taken
        query = "SELECT * FROM users WHERE user_email = %s"
        cursor = db.cursor()
        cursor.execute(query, (user_email,))
        if cursor.fetchone():
            return jsonify({'message': 'Email already exists'}), 409
        
        # Hash the password
        hashed_password = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the users table
        query = "INSERT INTO users (user_email, user_password) VALUES (%s, %s)"
        cursor.execute(query, (user_email, hashed_password))
        db.commit()

        return jsonify({'message': 'User registered successfully'})

    return render_template('signup.html')

# User Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_email = request.form['user_email']
        user_password = request.form['user_password']

        # Validate the email
        query = "SELECT * FROM users WHERE user_email = %s"
        cursor = db.cursor()
        cursor.execute(query, (user_email,))
        user = cursor.fetchone()

        # If user exist within the database
        if user:
            stored_password = user[2]

            # Verify password using bcrypt
            if bcrypt.checkpw(user_password.encode('utf-8'), stored_password.encode('utf-8')):
                # Password matches

                # Get the user_id
                user_id = user[0]
                
                # Generate JWT token
                token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
                session['token'] = token

                # Check if the user has a wallet named "Main"
                query = "SELECT * FROM wallets WHERE wallet_user_id = %s AND wallet_name = %s"
                cursor.execute(query, (user_id, "Main"))
                main_wallet = cursor.fetchone()

                if not main_wallet:
                    # If the user doesn't have a wallet named "Main", create one for them

                    # Insert the new wallet into the wallets table
                    query = "INSERT INTO wallets (wallet_name, wallet_status, wallet_user_id) VALUES (%s, 'Active', %s)"
                    cursor.execute(query, ("Main", user_id))
                    db.commit()

                    # Get the wallet_id of the newly created wallet
                    wallet_id = cursor.lastrowid

                    # Insert the new wallet into the wallets_users table
                    query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
                    cursor.execute(query, (wallet_id, user_id))
                    db.commit()

                return jsonify({'token': token}), 200
                         
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # User does not exist
        return jsonify({'message': 'User does not exist'}), 401

    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        return render_template('dashboard.html')
    else:
        return render_template('login.html')

# Wallets route
@app.route('/wallets', methods=['GET', 'POST'])
@login_required
def wallets():
    user_id = get_logged_in_user_id()

    if request.method == 'POST':
        wallet_name = request.form['wallet_name']

        if user_id is not None:
            # Check if the user_id exists in the users table
            query = "SELECT * FROM users WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            user = cursor.fetchone()

            if user:
                # Check if the wallet name already exists for the user
                query = "SELECT * FROM wallets WHERE wallet_name = %s AND wallet_user_id = %s"
                cursor.execute(query, (wallet_name, user_id))
                existing_wallet = cursor.fetchone()

                if existing_wallet:
                    return jsonify({'message': 'That wallet already exists, try a different name'}), 409

                # Insert the new wallet into the wallets table
                query = "INSERT INTO wallets (wallet_name, wallet_status, wallet_user_id) VALUES (%s, 'Active', %s)"
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
        WHERE w.wallet_user_id = %s OR u.user_id = %s
        ORDER BY w.wallet_name = 'Main' DESC, w.wallet_creation_date DESC
        """
        try:
            cursor.execute(query, (user_id, user_id))
            wallets = cursor.fetchall()
            
            # Find the index of the "Main" wallet, if it exists
            main_wallet_index = None
            for i, wallet in enumerate(wallets):
                if wallet[1] == 'Main':
                    main_wallet_index = i
                    break

            if main_wallet_index is not None:
                # Move the "Main" wallet to the first position in the list
                main_wallet = wallets.pop(main_wallet_index)
                wallets.insert(0, main_wallet)

            return wallets
        except Exception as e:
            print("Error executing SQL query:", e)
            return []

    else:
        return render_template('login.html')

@app.route('/wallets/<string:wallet_name>', methods=['GET', 'POST'])
@login_required
def wallet_details(wallet_name):
    user_id = get_logged_in_user_id()
    wallet = get_wallet_by_name(wallet_name)

    if user_id is not None:

        if wallet:
            is_owner = wallet['wallet_user_id'] == user_id if user_id is not None else False
            shared_users = get_shared_users(cursor, wallet['wallet_id'])

            return render_template('wallet_details.html', wallet=wallet, is_owner=is_owner, shared_users=shared_users, wallet_id=wallet['wallet_id'], users=shared_users)
        else:
            return render_template('login.html')

    # Return a valid response in case user_id is None
    return redirect(url_for('login'))

@app.route('/delete_wallet', methods=['POST'])
@login_required
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
    SELECT user_email 
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
        WHERE w.wallet_name = %s AND (w.wallet_user_id = %s OR u.user_id = %s)
        """
        cursor.execute(query, (wallet_name, user_id, user_id))
        wallet = cursor.fetchone()

        if wallet:
            # If the wallet exists, return it as a dictionary
            wallet_dict = {
                'wallet_id': wallet[0],
                'wallet_name': wallet[1],
                'wallet_status': wallet[2],
                'wallet_user_id': wallet[3],
                'wallet_creation_date': wallet[4]
            }

            return wallet_dict
        
    # If the wallet doesn't exist or the user is not logged in, return None
    return render_template('login.html')

# Add User route
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')  # Get the wallet ID from the request JSON
    user_id = get_logged_in_user_id()

    if user_email and wallet_id and user_id is not None:
        # Check if the user exists
        query = "SELECT * FROM users WHERE user_email = %s"
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
@login_required
def delete_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')  # Get the wallet ID from the request JSON
    owner_id = get_logged_in_user_id()

    if user_email and wallet_id and owner_id is not None:

        # Check if the user to be deleted exists
        query = "SELECT * FROM users WHERE user_email = %s"
        cursor.execute(query, (user_email,))
        user = cursor.fetchone()

        if user:
            # Check if the logged-in user is the owner of the wallet
            query = "SELECT * FROM wallets WHERE wallet_id = %s AND wallet_user_id = %s"
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

@app.route('/add_money', methods=['POST'])
@login_required
def add_money():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        data = request.get_json()
        fund_amount = data.get('fund_amount')

        # Validate the entered amount
        if not fund_amount or fund_amount == '0.00':
            return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400

        try:
            # Convert the amount to a decimal value for storage in the funds table
            decimal_amount = float(fund_amount.replace(',', '').replace('.', '')) / 100

            # Insert the amount into the funds table
            query = "INSERT INTO funds (fund_user_id, fund_amount) VALUES (%s, %s)"
            cursor.execute(query, (user_id, decimal_amount))
            db.commit()

            return jsonify({'success': True, 'message': 'Amount added successfully'})
        except Exception as e:
            print("Error adding amount to earnings:", e)
            return jsonify({'success': False, 'message': 'An error occurred while adding the amount.'}), 500

    # User is not logged in
    return jsonify({'success': False, 'message': 'User not logged in.'}), 401

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        data = request.get_json()
        amount = data.get('amount')
        name = data.get('name')
        type = data.get('type')

        type_id = get_type_id_by_name(type)

        balance = get_balance()

        # Validate the entered amount
        if not amount or amount == '0.00':
            return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400
        
        # Validate the name
        if not name or name.strip() == '':
            return jsonify({'success': False, 'message': 'Please enter a valid name.'}), 400
        
        # Validate the type
        if not type_id:
            return jsonify({'success': False, 'message': 'Please enter a valid type.'}), 400
        
        if balance < float(amount):
            return jsonify({'success': False, 'message': 'Insufficient funds.'}), 400

        try:
            # Convert the amount to a decimal value for storage in the expenses table
            decimal_amount = float(amount.replace(',', '').replace('.', '')) / 100

            # Get the wallet_id for the wallet named "Main"
            wallet_id = get_wallet_id_by_name("Main", user_id)

            # Get the type_id for the selected expense type
            type_id = get_type_id_by_name(type)

            # Insert the expense into the expenses table
            query = "INSERT INTO expenses (expense_user_id, expense_wallet_id, expense_type_id, expense_amount, expense_name) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (user_id, wallet_id, type_id, decimal_amount, name))
            db.commit()

            return jsonify({'success': True, 'message': 'Expense added successfully'})
        except Exception as e:
            print("Error adding expense:", e)
            return jsonify({'success': False, 'message': 'An error occurred while adding the expense.'}), 500

    # User is not logged in
    return jsonify({'success': False, 'message': 'User not logged in.'}), 401

# Function to get the wallet ID based on the wallet name and user ID
def get_wallet_id_by_name(wallet_name, user_id):
    query = "SELECT wallet_id FROM wallets WHERE wallet_name = %s AND wallet_user_id = %s"
    cursor.execute(query, (wallet_name, user_id))
    result = cursor.fetchone()
    if result:
        return result[0]
    return None

# Function to get the type ID based on the type name
def get_type_id_by_name(expense_type):
    query = "SELECT type_id FROM types WHERE type_name = %s"
    cursor.execute(query, (expense_type,))
    result = cursor.fetchone()
    if result:
        return result[0]
    return None

@app.route('/get_balance', methods=['GET'])
@login_required
def current_balance():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        try:

            balance = get_balance()

            return jsonify({'success': True, 'balance': balance})
        
        except Exception as e:
            print("Error fetching balance:", e)
            return jsonify({'success': False, 'message': 'An error occurred while fetching the balance.'}), 500

    # User is not logged in
    return jsonify({'success': False, 'message': 'User not logged in.'}), 401

def get_balance():
    user_id = get_logged_in_user_id()

    if user_id is not None:

        try:
            # Fetch the sum of incomes (funds added) for the logged-in user from the funds table
            funds_query = "SELECT IFNULL(SUM(fund_amount), 0) AS available_funds FROM funds WHERE fund_user_id = %s"
            cursor.execute(funds_query, (user_id,))
            funds_query_result = cursor.fetchone()
            funds = float(funds_query_result[0])

            # Fetch the sum of expenses for the logged-in user from the expenses table
            expenses_query = "SELECT IFNULL(SUM(expense_amount), 0) AS expenses FROM expenses WHERE expense_user_id = %s"
            cursor.execute(expenses_query, (user_id,))
            expenses_query_result = cursor.fetchone()
            expenses = float(expenses_query_result[0])

            # Calculate the balance by subtracting expenses from funds
            balance = funds - expenses

            return balance
        except Exception as e:
            print("Error fetching balance:", e)
            return None
        
    # User is not logged in
    return jsonify({'success': False, 'message': 'User not logged in.'}), 401

# Endpoint to retrieve types data from the "types" table
@app.route('/get_expense_types', methods=['GET'])
@login_required
def get_names():
    try:
        # Fetch the names from the "types" table
        query = "SELECT type_name FROM types"
        cursor.execute(query)
        names = [type_info[0] for type_info in cursor.fetchall()]

        return jsonify({"success": True, "names": names})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# Logout route
@app.route('/logout')
@login_required
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))  

# Run the app
if __name__ == '__main__':
    app.run()