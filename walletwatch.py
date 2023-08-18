from flask import Flask, render_template, request, jsonify, session
from flask import redirect, url_for
import jwt
from functools import wraps
from datetime import datetime, timedelta
from mysql.connector import pooling
import bcrypt

# Create a Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cct'

# MySQL configuration
db = {
    "host": "localhost",
    "user": "cct",
    "password": "cctcollege2023*",
    "database": "walletwatch_db",
    "pool_size": 10,
}

def create_tables():
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SHOW TABLES LIKE 'users'")
                table_exists = cursor.fetchone()

        if not table_exists:
            with open('walletwatch_db.sql', 'r') as sql_file:
                sql_script = sql_file.read()

            with connection_pool.get_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql_script)
                    connection.commit()

            print("Tables created successfully")
    except Exception as e:
        print("Error creating tables:", e)

connection_pool = pooling.MySQLConnectionPool(**db)

def get_connection():
    return connection_pool.get_connection()

def execute_query(query, params=None, commit=False):
    connection = get_connection()
    cursor = connection.cursor()
    
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        if commit:
            connection.commit()
            last_row_id = cursor.lastrowid
            return last_row_id
        
        if query.strip().lower().startswith('select'):
            result = cursor.fetchall()
            return result
    
    except Exception as e:
        print("Database error:", e)
        connection.rollback()
    
    finally:
        cursor.close()
        connection.close()

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

        query = "SELECT * FROM users WHERE user_email = %s"
        existing_user = execute_query(query, (user_email,))

        if existing_user:
            return jsonify({'message': 'Email already exists'}), 409
        
        hashed_password = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())

        query = "INSERT INTO users (user_email, user_password) VALUES (%s, %s)"
        execute_query(query, (user_email, hashed_password), commit=True)

        return jsonify({'message': 'User registered successfully'})

    return render_template('signup.html')

# User Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_email = request.form['user_email']
        user_password = request.form['user_password']

        query = "SELECT * FROM users WHERE user_email = %s"
        user = execute_query(query, (user_email,))

        if user:
            stored_password = user[0][2]
            if bcrypt.checkpw(user_password.encode('utf-8'), stored_password.encode('utf-8')):
                user_id = user[0][0]
                token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
                session['token'] = token

                query = "SELECT * FROM wallets WHERE wallet_user_id = %s AND wallet_name = %s"
                main_wallet = execute_query(query, (user_id, "Main"))

                if not main_wallet:
                    query = "INSERT INTO wallets (wallet_name, wallet_status, wallet_user_id) VALUES (%s, 'Open', %s)"
                    wallet_id = execute_query(query, ("Main", user_id), commit=True)

                    query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
                    execute_query(query, (wallet_id, user_id), commit=True)

                return jsonify({'token': token}), 200
                         
            return jsonify({'message': 'Invalid email or password'}), 401
        
        return jsonify({'message': 'User does not exist'}), 401

    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/wallets', methods=['GET', 'POST'])
@login_required
def wallets():
    user_id = get_logged_in_user_id()

    if request.method == 'POST':
        wallet_name = request.form['wallet_name']

        try:
            with connection_pool.get_connection() as connection:
                with connection.cursor() as cursor:

                    # Check if the wallet name already exists for the user
                    query = """
                        SELECT w.wallet_id
                        FROM wallets w
                        LEFT JOIN wallets_users wu ON w.wallet_id = wu.wallet_id
                        WHERE (w.wallet_name = %s AND w.wallet_user_id = %s)
                        OR (wu.user_id = %s AND w.wallet_name = %s) limit 1
                    """

                    cursor.execute(query, (wallet_name, user_id, user_id, wallet_name))
                    existing_wallet = cursor.fetchone()

                    if existing_wallet is not None:
                        return jsonify({'message': 'That wallet already exists, try a different name'}), 409

                    # Insert the new wallet into the wallets table
                    query = "INSERT INTO wallets (wallet_name, wallet_status, wallet_user_id) VALUES (%s, 'Open', %s)"
                    cursor.execute(query, (wallet_name, user_id))
                    connection.commit()

                    # Get the wallet_id of the newly created wallet
                    wallet_id = cursor.lastrowid

                    # Insert the new wallet into the wallets_users table
                    query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
                    cursor.execute(query, (wallet_id, user_id))
                    connection.commit()

            return jsonify({'message': 'Wallet added successfully'})
        except Exception as e:
            return jsonify({'message': 'An error occurred while adding the wallet.'}), 500

    else:  # Request method is GET
        wallets = get_wallets()  # Fetch and sort the wallets

        return render_template('wallets.html', wallets=wallets)

def get_wallets():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        try:
            with connection_pool.get_connection() as connection:
                with connection.cursor() as cursor:
                    # Fetch the wallets for the logged-in user
                    query = """
                    SELECT DISTINCT w.* 
                    FROM wallets AS w 
                    LEFT JOIN wallets_users AS u ON w.wallet_id = u.wallet_id
                    WHERE w.wallet_user_id = %s OR u.user_id = %s
                    ORDER BY w.wallet_name = 'Main' DESC, w.wallet_creation_date DESC
                    """

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

@app.route('/wallets/<wallet_name>', methods=['GET', 'POST'])
@login_required
def wallet_details(wallet_name):
    user_id = get_logged_in_user_id()
    wallet = get_wallet_by_name(wallet_name)

    if wallet:
        is_owner = wallet['wallet_user_id'] == user_id if user_id is not None else False
        shared_users = get_shared_users(wallet['wallet_id'])

        return render_template('wallet_details.html', wallet_status=wallet['wallet_status'], wallet_name=wallet_name, wallet=wallet, is_owner=is_owner, shared_users=shared_users, wallet_id=wallet['wallet_id'], users=shared_users)
    else:
        return render_template('login.html')

@app.route('/close_wallet/<wallet_id>', methods=['POST'])
@login_required
def close_wallet(wallet_id):
    try:
        # Get the wallet_name associated with the wallet_id
        wallet_name = get_wallet_name_by_id(wallet_id)

        # Check if the wallet_name is "Main"
        if wallet_name == "Main":
            return jsonify({'message': 'Your Main wallet cannot be closed.'}), 400

        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                # Update the wallet status to 'Closed'
                query = "UPDATE wallets SET wallet_status = 'Closed' WHERE wallet_id = %s"
                cursor.execute(query, (wallet_id,))
                connection.commit()

            return jsonify({'message': 'Wallet closed successfully'})

    except Exception as e:
        return jsonify({'message': 'An error occurred while closing the wallet.'}), 500

@app.route('/open_wallet/<wallet_id>', methods=['POST'])
@login_required
def open_wallet(wallet_id):
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                # Update the wallet status to 'Open'
                query = "UPDATE wallets SET wallet_status = 'Open' WHERE wallet_id = %s"
                cursor.execute(query, (wallet_id,))
                connection.commit()

            return jsonify({'message': 'Wallet opened successfully'})

    except Exception as e:
        return jsonify({'message': 'An error occurred while opening the wallet.'}), 500

def get_shared_users(wallet_id):
    owner_id = get_logged_in_user_id()
    
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                query = """
                SELECT user_email 
                FROM users
                INNER JOIN wallets_users ON users.user_id = wallets_users.user_id 
                WHERE wallets_users.wallet_id = %s AND wallets_users.user_id != %s
                """
                cursor.execute(query, (wallet_id, owner_id))
                shared_users = [user[0] for user in cursor.fetchall()]

        return shared_users
    except Exception as e:
        print("Error fetching shared users:", e)
        return []

def get_wallet_by_name(wallet_name):
    user_id = get_logged_in_user_id()

    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:

                # Fetch the wallet details from the database based on the wallet name and user_id
                query = """
                SELECT w.*
                FROM wallets AS w
                LEFT JOIN wallets_users AS u ON w.wallet_id = u.wallet_id
                WHERE w.wallet_name = %s AND (w.wallet_user_id = %s OR u.user_id = %s) limit 1
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
        
    except Exception as e:
        print("Error fetching wallet:", e)
        return None
    
def get_wallet_name_by_id(wallet_id):
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                query = "SELECT wallet_name FROM wallets WHERE wallet_id = %s"
                cursor.execute(query, (wallet_id,))
                wallet_data = cursor.fetchone()
                if wallet_data:
                    return wallet_data[0]
                else:
                    return None
    except Exception as e:
        print("Error getting wallet name:", e)
        return None

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')  # Get the wallet ID from the request JSON
    user_id = get_logged_in_user_id()

    if user_email and wallet_id and user_id is not None:

        try:
            with connection_pool.get_connection() as connection:
                with connection.cursor() as cursor:
                    # Check if the user exists
                    query = "SELECT * FROM users WHERE user_email = %s"
                    cursor.execute(query, (user_email,))
                    existing_user = cursor.fetchone()

            if existing_user:

                with connection_pool.get_connection() as connection:
                    with connection.cursor() as cursor:
                        # Check if the user already has access to the wallet
                        query = "SELECT * FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
                        cursor.execute(query, (wallet_id, existing_user[0]))
                        existing_wallet_user = cursor.fetchone()

                if existing_wallet_user:
                    return jsonify({'message': 'User already has access to this wallet'}), 409

                with connection_pool.get_connection() as connection:
                    with connection.cursor() as cursor:
                        # Insert the new user into the wallets_users table
                        query = "INSERT INTO wallets_users (wallet_id, user_id) VALUES (%s, %s)"
                        cursor.execute(query, (wallet_id, existing_user[0]))
                        connection.commit()

                return jsonify({'message': 'User added successfully'})

            # User does not exist
            return jsonify({'message': 'User does not exist'}), 404

        except Exception as e:
            print("Error adding user:", e)
            return jsonify({'message': 'An error occurred while adding the user.'}), 500

    # User email not provided
    return jsonify({'message': 'Email required'}), 400

@app.route('/remove_user', methods=['POST'])
@login_required
def remove_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')
    owner_id = get_logged_in_user_id()

    if user_email and wallet_id and owner_id is not None:

        try:
            with connection_pool.get_connection() as connection:
                with connection.cursor() as cursor:
                    # Check if the user to be removed exists
                    query = "SELECT * FROM users WHERE user_email = %s"
                    cursor.execute(query, (user_email,))
                    user = cursor.fetchone()

            if user:
                with connection_pool.get_connection() as connection:
                    with connection.cursor() as cursor:
                        # Check if the user to be removed is a shared user of the wallet
                        query = "SELECT * FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
                        cursor.execute(query, (wallet_id, user[0]))
                        wallet_user = cursor.fetchone()

                    if wallet_user:
                        with connection_pool.get_connection() as connection:
                            with connection.cursor() as cursor:
                            # Remove the user from the wallets_users table
                                query = "DELETE FROM wallets_users WHERE wallet_id = %s AND user_id = %s"
                                cursor.execute(query, (wallet_id, user[0]))
                                connection.commit()

                        return jsonify({'message': 'User removed successfully'})

                    # User is not a shared user of the wallet
                    return jsonify({'message': 'User is not associated with this wallet'}), 404

            # User does not exist
            return jsonify({'message': 'User does not exist'}), 404

        except Exception as e:
            print("Error deleting user:", e)
            return jsonify({'message': 'An error occurred while deleting the user.'}), 500

    # User email or wallet ID not provided
    return jsonify({'message': 'Invalid request'}), 400

@app.route('/add_money', methods=['POST'])
@login_required
def add_money():
    user_id = get_logged_in_user_id()

    data = request.get_json()
    fund_amount = data.get('fund_amount')

    # Validate the entered amount
    if not fund_amount or fund_amount == '0.00':
        return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400

    try:
        # Convert the amount to a decimal value for storage in the funds table
        decimal_amount = float(fund_amount.replace(',', '').replace('.', '')) / 100

        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                # Insert the amount into the funds table
                query = "INSERT INTO funds (fund_user_id, fund_amount) VALUES (%s, %s)"
                cursor.execute(query, (user_id, decimal_amount))
                connection.commit()

        return jsonify({'success': True, 'message': 'Amount added successfully'})
    except Exception as e:
        print("Error adding money", e)
        return jsonify({'success': False, 'message': 'An error occurred while adding the amount.'}), 500

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    user_id = get_logged_in_user_id()

    data = request.get_json()
    amount = data.get('amount')
    name = data.get('name')
    expense_type = data.get('type')
    expense_wallet = data.get('wallet')

    type_id = get_type_id_by_name(expense_type)

    wallet_id = get_wallet_id_by_name(expense_wallet)

    balance = get_balance(user_id)

    # Validate the entered amount
    if not amount or amount == '0.00':
        return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400
        
    # Validate the name
    if not name or name.strip() == '':
        return jsonify({'success': False, 'message': 'Please enter a valid name.'}), 400
        
    # Validate the type
    if not type_id:
        return jsonify({'success': False, 'message': 'Please enter a valid type.'}), 400

    # Check if the wallet is open
    wallet_status = get_wallet_status(wallet_id)
    if wallet_status != 'Open':
        return jsonify({'success': False, 'message': 'You can only add expenses to open wallets.'}), 403

    if balance < float(amount.replace(',', '')):
        return jsonify({'success': False, 'message': 'Insufficient funds.'}), 400

    try:
        # Convert the amount to a decimal value for storage in the expenses table
        decimal_amount = float(amount.replace(',', '').replace('.', '')) / 100

        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                # Insert the expense into the expenses table
                query = "INSERT INTO expenses (expense_user_id, expense_wallet_id, expense_type_id, expense_amount, expense_name) VALUES (%s, %s, %s, %s, %s)"
                cursor.execute(query, (user_id, wallet_id, type_id, decimal_amount, name))
                connection.commit()

        return jsonify({'success': True, 'message': 'Expense added successfully'})
    except Exception as e:
        print("Error adding expense:", e)
        return jsonify({'success': False, 'message': 'An error occurred while adding the expense.'}), 500

def get_wallet_status(wallet_id):
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                query = "SELECT wallet_status FROM wallets WHERE wallet_id = %s"
                cursor.execute(query, (wallet_id,))
                wallet_data = cursor.fetchone()
                if wallet_data:
                    return wallet_data[0]
                else:
                    return None
    except Exception as e:
        print("Error getting wallet status:", e)
        return None

def get_wallet_id_by_name(expense_wallet):
    try:
        user_id = get_logged_in_user_id()
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                query = """
                    SELECT wu.wallet_id
                    FROM wallets_users wu
                    INNER JOIN wallets w ON wu.wallet_id = w.wallet_id
                    WHERE w.wallet_name = %s AND wu.user_id = %s
                """
                cursor.execute(query, (expense_wallet,user_id))
                result = cursor.fetchone()

            if result:
                    return result[0]
            return None
    except Exception as e:
        print("Error retrieving wallet ID by name:", e)
        return None

# Function to get the type ID based on the type name
def get_type_id_by_name(expense_type):
    try:
        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                query = "SELECT type_id FROM types WHERE type_name = %s"
                cursor.execute(query, (expense_type,))
                result = cursor.fetchone()

        if result:
            return result[0]
        return None
    except Exception as e:
        print("Error fetching expense type ID:", e)
        return None

@app.route('/get_balance', methods=['GET'])
@login_required
def current_balance():
    try:
        user_id = get_logged_in_user_id()

        balance = get_balance(user_id)

        return jsonify({'success': True, 'balance': balance})
        
    except Exception as e:
        print("Error fetching balance:", e)
        return jsonify({'success': False, 'message': 'An error occurred while fetching the balance.'}), 500

def get_balance(user_id):
    try:
        query = """
            SELECT IFNULL(SUM(fund_amount), 0) - IFNULL(
                (SELECT SUM(expense_amount) 
                FROM expenses 
                WHERE expense_user_id = %s 
                AND MONTH(expense_date) = MONTH(CURDATE()) 
                AND YEAR(expense_date) = YEAR(CURDATE())), 0) AS balance
            FROM funds
            WHERE fund_user_id = %s
            AND MONTH(fund_date) = MONTH(CURDATE()) 
            AND YEAR(fund_date) = YEAR(CURDATE())
        """

        balance_query_result = execute_query(query, (user_id, user_id))
        balance = float(balance_query_result[0][0])

        return balance
    except Exception as e:
        print("Error fetching balance:", e)
        return None
    
@app.route('/get_expenses', methods=['GET'])
@login_required
def current_expenses():
    try:
        user_id = get_logged_in_user_id()

        expenses = get_expenses(user_id)

        return jsonify({'success': True, 'expenses': expenses})
        
    except Exception as e:
        print("Error fetching expenses:", e)
        return jsonify({'success': False, 'message': 'An error occurred while fetching expenses.'}), 500

def get_expenses(user_id):
    try:
        query = """
            SELECT IFNULL(SUM(expense_amount), 0) AS expenses 
            FROM expenses 
            WHERE expense_user_id = %s 
            AND MONTH(expense_date) = MONTH(CURDATE()) 
            AND YEAR(expense_date) = YEAR(CURDATE())
        """

        expenses_query_result = execute_query(query, (user_id,))
        expenses = float(expenses_query_result[0][0])

        return expenses
    except Exception as e:
        print("Error fetching expenses:", e)
        return None
     
@app.route('/get_expense_types', methods=['GET'])
@login_required
def get_names():
    try:
        query = "SELECT type_name FROM types"

        result = execute_query(query)
        names = [type_info[0] for type_info in result]

        return jsonify({"success": True, "names": names})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    
@app.route('/get_wallets_list', methods=['GET'])
@login_required
def get_wallets_list():
    try:
        user_id = get_logged_in_user_id()

        query = """
            SELECT DISTINCT w.wallet_name, w.wallet_status
            FROM wallets AS w
            LEFT JOIN wallets_users AS wu ON w.wallet_id = wu.wallet_id
            WHERE w.wallet_user_id = %s OR wu.user_id = %s
        """

        result = execute_query(query, (user_id, user_id))
        
        open_wallets = []
        for wallet_info in result:
            wallet_name, wallet_status = wallet_info
            if wallet_status == 'Open':
                open_wallets.append(wallet_name)

        return jsonify({"success": True, "wallets": open_wallets})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# Get the percentages amount by querying the database funds and expenses table
@app.route('/get_percentages', methods=['GET'])
@login_required
def get_percentages():
    try:
        user_id = get_logged_in_user_id()

        funds_query = """
        SELECT IFNULL(SUM(fund_amount), 0) AS total_funds
        FROM funds
        WHERE fund_user_id = %s AND MONTH(fund_date) = MONTH(CURDATE()) AND YEAR(fund_date) = YEAR(CURDATE())
        """

        expenses_query = """
        SELECT 
            IFNULL(SUM(CASE WHEN expense_type_id = %s THEN IFNULL(expense_amount, 0) ELSE 0 END), 0) AS needs_sum,
            IFNULL(SUM(CASE WHEN expense_type_id = %s THEN IFNULL(expense_amount, 0) ELSE 0 END), 0) AS wants_sum,
            IFNULL(SUM(CASE WHEN expense_type_id = %s THEN IFNULL(expense_amount, 0) ELSE 0 END), 0) AS savings_debt_sum
        FROM expenses
        WHERE expense_user_id = %s AND MONTH(expense_date) = MONTH(CURDATE()) AND YEAR(expense_date) = YEAR(CURDATE())
        """

        with connection_pool.get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(funds_query, (user_id,))
                total_funds_ = cursor.fetchone()

                cursor.execute(expenses_query, (1, 2, 3, user_id))
                expenses_sums = cursor.fetchone()

                total_funds = float(total_funds_[0])
                needs_sum, wants_sum, savings_debt_sum = map(float, expenses_sums)

        needs_percentage = "{:.2f}".format(round((needs_sum / total_funds) * 100, 2)) if total_funds != 0 else "0.00"
        wants_percentage = "{:.2f}".format(round((wants_sum / total_funds) * 100, 2)) if total_funds != 0 else "0.00"
        savings_debt_percentage = "{:.2f}".format(round((savings_debt_sum / total_funds) * 100, 2)) if total_funds != 0 else "0.00"

        return jsonify({
            'needs': needs_percentage,
            'wants': wants_percentage,
            'savingsDebt': savings_debt_percentage
        }), 200

    except Exception as e:
        print("Error fetching percentages:", e)
        return jsonify({'message': 'An error occurred while fetching percentages.'}), 500
    
# Get the list of expenses to fill the table inside each wallet
@app.route('/get_expenses_list/<wallet_id>', methods=['GET'])
@login_required
def get_expenses_list(wallet_id):
    try:
        query = """
            SELECT e.expense_id, e.expense_name, e.expense_amount, et.type_name, e.expense_date, u.user_email
            FROM expenses e
            JOIN types et ON e.expense_type_id = et.type_id
            JOIN users u ON e.expense_user_id = u.user_id
            WHERE e.expense_wallet_id = %s
            ORDER BY e.expense_date ASC
        """

        result = execute_query(query, (wallet_id,))

        expenses_list = [
            {
                "expense_id": expense[0],
                "name": expense[1],
                "amount": expense[2],
                "type": expense[3],
                "date": str(expense[4]),
                "user": expense[5]
            }
            for expense in result
        ]

        return jsonify({"success": True, "expenses_list": expenses_list})
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
    create_tables()
    app.run(host='0.0.0.0', port=5000, debug=True)