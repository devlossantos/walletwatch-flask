from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import jwt
from functools import wraps
from datetime import datetime, timedelta
import bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.decimal128 import Decimal128
import time

# Create a Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cct'

# MongoDB configuration
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['walletwatch_db']

# Read speed measurement
start_time = time.time()
documents = db.expenses.find().limit(10)
result = list(documents)
end_time = time.time()
read_time = end_time - start_time

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_logged_in_user_id():
    token = session.get('token')
    if token:
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return decoded_token.get('user_id')
        except jwt.ExpiredSignatureError:
            return None
    return None

@app.route('/')
@login_required
def home():
    print('Mongodb read speed time: ',read_time)
    return render_template('dashboard.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user_email = request.form['user_email']
        user_password = request.form['user_password']

        existing_user = db.users.find_one({'user_email': user_email})
        if existing_user:
            return jsonify({'message': 'Email already exists'}), 409
        
        hashed_password = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())

        user_data = {
            'user_email': user_email,
            'user_password': hashed_password
        }
        db.users.insert_one(user_data)

        return jsonify({'message': 'User registered successfully'})
    
    return render_template('signup.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_email = request.form['user_email']
        user_password = request.form['user_password']

        user = db.users.find_one({'user_email': user_email})

        if user:
            stored_password = user['user_password']
            if bcrypt.checkpw(user_password.encode('utf-8'), stored_password):
                user_id = str(user['_id'])
                token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])

                session['token'] = token

                main_wallet = db.wallets.find_one({'wallet_user_id': user_id, 'wallet_name': 'Main'})
                if not main_wallet:
                    wallet_data = {
                        'wallet_name': 'Main',
                        'wallet_status': 'Open',
                        'wallet_user_id': user_id
                    }
                    db.wallets.insert_one(wallet_data)

                    wallet_id = str(wallet_data['_id'])
                    wallets_users_data = {
                        'wallet_id': wallet_id,
                        'user_id': user_id
                    }
                    db.wallets_users.insert_one(wallets_users_data)

                return jsonify({'token': token}), 200
            else:
                return jsonify({'message': 'Invalid email or password'}), 401
        else:
            return jsonify({'message': 'User does not exist'}), 401

    return render_template('login.html')

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

        existing_wallet = db.wallets.find_one({
            '$or': [
                {'wallet_name': wallet_name, 'wallet_user_id': user_id}
            ]
        })

        if existing_wallet:
            return jsonify({'message': 'That wallet already exists, try a different name'}), 409

        new_wallet_data = {
            'wallet_name': wallet_name,
            'wallet_status': 'Open',
            'wallet_user_id': user_id
        }
        db.wallets.insert_one(new_wallet_data)

        new_wallet_id = str(new_wallet_data['_id'])

        wallets_users_data = {
            'wallet_id': new_wallet_id,
            'wallet_user_id': user_id
        }
        db.wallets_users.insert_one(wallets_users_data)

        return jsonify({'message': 'Wallet added successfully'})

    else:  # Request method is GET
        wallets = get_wallets()

        return render_template('wallets.html', wallets=wallets)

def get_wallets():
    user_id = get_logged_in_user_id()

    if user_id is not None:
        try:
            wallets = db.wallets.aggregate([
                {
                    '$lookup': {
                        'from': 'wallets_users',
                        'localField': '_id',
                        'foreignField': 'wallet_id',
                        'as': 'users'
                    }
                },
                {
                    '$match': {
                        '$or': [
                            {'wallet_user_id': user_id},
                            {'users.user_id': user_id}
                        ]
                    }
                },
                {
                    '$sort': {
                        'wallet_name': 1
                    }
                }
            ])

            return list(wallets)
        except Exception as e:
            print("Error querying MongoDB:", e)
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
        shared_users = get_shared_users(wallet['_id'])

        return render_template('wallet_details.html', wallet_status=wallet['wallet_status'], wallet_name=wallet_name, wallet=wallet, is_owner=is_owner, shared_users=shared_users, wallet_id=str(wallet['_id']), users=shared_users)
    else:
        return render_template('login.html')

def get_wallet_by_name(wallet_name):
    return db.wallets.find_one({'wallet_name': wallet_name})

def get_shared_users(wallet_id):
    return list(db.wallets_users.find({'_id': wallet_id}))

@app.route('/close_wallet/<wallet_id>', methods=['POST'])
@login_required
def close_wallet(wallet_id):
    try:
        wallet_name = get_wallet_name_by_id(wallet_id)

        if wallet_name == "Main":
            return jsonify({'message': 'Your Main wallet cannot be closed.'}), 400

        db.wallets.update_one({'_id': ObjectId(wallet_id)}, {'$set': {'wallet_status': 'Closed'}})

        return jsonify({'message': 'Wallet closed successfully'})

    except Exception as e:
        return jsonify({'message': 'An error occurred while closing the wallet.'}), 500

def get_wallet_name_by_id(wallet_id):
    wallet = db.wallets.find_one({'_id': ObjectId(wallet_id)})
    if wallet:
        return wallet['wallet_name']
    return None

@app.route('/open_wallet/<wallet_id>', methods=['POST'])
@login_required
def open_wallet(wallet_id):
    try:
        db.wallets.update_one({'_id': ObjectId(wallet_id)}, {'$set': {'wallet_status': 'Open'}})

        return jsonify({'message': 'Wallet opened successfully'})

    except Exception as e:
        return jsonify({'message': 'An error occurred while opening the wallet.'}), 500

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')
    owner_id = get_logged_in_user_id()

    if user_email and wallet_id and owner_id is not None:
        existing_user = db.users.find_one({"user_email": user_email})

        if existing_user:
            existing_wallet_user = db.wallets_users.find_one({"wallet_id": wallet_id, "user_id": existing_user["_id"]})
            
            if existing_wallet_user:
                return jsonify({'message': 'User already has access to this wallet'}), 409

            db.wallets_users.insert_one({"wallet_id": wallet_id, "user_id": existing_user["_id"]})

            return jsonify({'message': 'User added successfully'})
        else:
            return jsonify({'message': 'User does not exist'}), 404

    return jsonify({'message': 'Email and wallet_id required'}), 400

@app.route('/remove_user', methods=['POST'])
@login_required
def remove_user():
    user_email = request.json.get('user_email')
    wallet_id = request.json.get('wallet_id')
    owner_id = get_logged_in_user_id()

    if user_email and wallet_id and owner_id is not None:
        try:
            user = db.users.find_one({'user_email': user_email})

            if user:
                wallet_user = db.wallets_users.find_one({'wallet_id': wallet_id, 'user_id': user['_id']})

                if wallet_user:
                    db.wallets_users.delete_one({'wallet_id': wallet_id, 'user_id': user['_id']})

                    return jsonify({'message': 'User removed successfully'})

                return jsonify({'message': 'User is not associated with this wallet'}), 404

            return jsonify({'message': 'User does not exist'}), 404

        except Exception as e:
            print("Error deleting user:", e)
            return jsonify({'message': 'An error occurred while deleting the user.'}), 500

    return jsonify({'message': 'Invalid request'}), 400

@app.route('/add_money', methods=['POST'])
@login_required
def add_money():
    user_id = get_logged_in_user_id()

    data = request.get_json()
    fund_amount = data.get('fund_amount')

    if not fund_amount or fund_amount == '0.00':
        return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400

    try:
        decimal_amount = float(fund_amount.replace(',', '').replace('.', '')) / 100

        fund_data = {
            'fund_user_id': user_id,
            'fund_amount': decimal_amount,
            'fund_date': datetime.utcnow()
        }

        db.funds.insert_one(fund_data)

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

    if not amount or amount == '0.00':
        return jsonify({'success': False, 'message': 'Please enter a valid amount.'}), 400
        
    if not name or name.strip() == '':
        return jsonify({'success': False, 'message': 'Please enter a valid name.'}), 400
        
    if not type_id:
        return jsonify({'success': False, 'message': 'Please enter a valid type.'}), 400

    wallet_status = get_wallet_status(wallet_id)
    if wallet_status != 'Open':
        return jsonify({'success': False, 'message': 'You can only add expenses to open wallets.'}), 403

    if balance < float(amount.replace(',', '')):
        return jsonify({'success': False, 'message': 'Insufficient funds.'}), 400

    try:
        decimal_amount = float(amount.replace(',', '').replace('.', '')) / 100

        expense_data = {
            'expense_user_id': user_id,
            'expense_wallet_id': wallet_id,
            'expense_type_id': type_id,
            'expense_amount': decimal_amount,
            'expense_name': name,
            'expense_date': datetime.utcnow()
        }
        db.expenses.insert_one(expense_data)

        return jsonify({'success': True, 'message': 'Expense added successfully'})
    except Exception as e:
        print("Error adding expense:", e)
        return jsonify({'success': False, 'message': 'An error occurred while adding the expense.'}), 500

def get_wallet_status(wallet_id):
    try:
        wallet_data = db.wallets.find_one({'_id': wallet_id}, {'wallet_status': 1})
        if wallet_data:
            return wallet_data['wallet_status']
        else:
            return None
    except Exception as e:
        print("Error getting wallet status:", e)
        return None

def get_wallet_id_by_name(expense_wallet):
    try:
        query = {
            'wallet_name': expense_wallet
        }
        wallet_data = db.wallets.find_one(query, {'_id': 1})

        if wallet_data:
            wallet_id = wallet_data['_id']
            return wallet_id
        return None
    except Exception as e:
        print("Error retrieving wallet ID by name:", e)
        return None

def get_type_id_by_name(expense_type):
    try:
        query = {
            'type_name': expense_type
        }
        type_data = db.types.find_one(query, {'_id': 1})

        if type_data:
            type_id = type_data['_id']
            return type_id
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
        funds_query = {
            'fund_user_id': user_id
        }
        total_funds = db.funds.aggregate([
            {'$match': funds_query},
            {'$group': {'_id': None, 'total_amount': {'$sum': '$fund_amount'}}}
        ])
        total_funds_amount = total_funds.next()['total_amount'] if total_funds.alive else 0

        expenses_query = {
            'expense_user_id': user_id
        }
        total_expenses = db.expenses.aggregate([
            {'$match': expenses_query},
            {'$group': {'_id': None, 'total_amount': {'$sum': '$expense_amount'}}}
        ])
        total_expenses_amount = total_expenses.next()['total_amount'] if total_expenses.alive else 0

        balance = total_funds_amount - total_expenses_amount
        return balance
        
    except Exception as e:
        print("Error calculating balance:", e)
        return 0

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
        expenses_query = [
            {
                '$match': {
                    'expense_user_id': user_id,
                    'expense_date': {
                        '$gte': datetime(datetime.now().year, datetime.now().month, 1),
                        '$lt': datetime(datetime.now().year, datetime.now().month + 1, 1)
                    }
                }
            },
            {
                '$group': {
                    '_id': None,
                    'total_expenses': {'$sum': '$expense_amount'}
                }
            }
        ]

        expenses_result = list(db.expenses.aggregate(expenses_query))
        total_expenses = expenses_result[0]['total_expenses'] if expenses_result else Decimal128('0.00')

        return total_expenses
    except Exception as e:
        print("Error fetching expenses:", e)
        return None

def get_type_name_by_id(type_id):
    try:
        expense_type_doc = db.expense_types.find_one({'_id': type_id})
        if expense_type_doc:
            return expense_type_doc['type_name']
        return None
    except Exception as e:
        print("Error fetching expense type name:", e)
        return None

@app.route('/get_expense_types', methods=['GET'])
@login_required
def get_names():
    try:
        expense_types = db.types.find({}, {'_id': 0, 'type_name': 1})
        names = [expense_type['type_name'] for expense_type in expense_types]

        return jsonify({"success": True, "names": names})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/get_wallets_list', methods=['GET'])
@login_required
def get_wallets_list():
    try:
        user_id = get_logged_in_user_id()

        query = {
            '$or': [
                {'wallet_user_id': user_id},
                {'shared_users.user_id': user_id}
            ]
        }

        result = db.wallets.find(query, {'_id': 0, 'wallet_name': 1, 'wallet_status': 1, 'shared_users.user_id': 1})

        open_wallets = []
        for wallet_info in result:
            wallet_name = wallet_info['wallet_name']
            wallet_status = wallet_info['wallet_status']
            shared_users = wallet_info.get('shared_users', [])
            
            if wallet_status == 'Open' or any(user.get('user_id') == user_id for user in shared_users):
                open_wallets.append(wallet_name)

        return jsonify({"success": True, "wallets": open_wallets})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/get_percentages', methods=['GET'])
@login_required
def get_percentages():
    try:
        user_id = get_logged_in_user_id()

        funds_query = [
            {
                '$match': {
                    'fund_user_id': user_id,
                    'fund_date': {
                        '$gte': datetime(datetime.now().year, datetime.now().month, 1),
                        '$lt': datetime(datetime.now().year, datetime.now().month + 1, 1)
                    }
                }
            },
            {
                '$group': {
                    '_id': None,
                    'total_funds': {'$sum': '$fund_amount'}
                }
            }
        ]

        expenses_query = [
            {
                '$match': {
                    'expense_user_id': user_id,
                    'expense_date': {
                        '$gte': datetime(datetime.now().year, datetime.now().month, 1),
                        '$lt': datetime(datetime.now().year, datetime.now().month + 1, 1)
                    }
                }
            },
            {
                '$group': {
                    '_id': None,
                    'needs_sum': {'$sum': {'$cond': [{'$eq': ['$expense_type_id', ObjectId('64e2a3666fa5cc36f4803a6a')]}, '$expense_amount', 0]}},
                    'wants_sum': {'$sum': {'$cond': [{'$eq': ['$expense_type_id', ObjectId('64e2a3666fa5cc36f4803a6b')]}, '$expense_amount', 0]}},
                    'savings_debt_sum': {'$sum': {'$cond': [{'$eq': ['$expense_type_id', ObjectId('64e2a3666fa5cc36f4803a6c')]}, '$expense_amount', 0]}}
                }
            }
        ]

        total_funds_result = list(db.funds.aggregate(funds_query))
        total_funds = total_funds_result[0]['total_funds'] if total_funds_result else 0

        expenses_result = list(db.expenses.aggregate(expenses_query))
        expenses_sums = expenses_result[0] if expenses_result else {
            'needs_sum': 0,
            'wants_sum': 0,
            'savings_debt_sum': 0
        }

        needs_sum = expenses_sums['needs_sum']
        wants_sum = expenses_sums['wants_sum']
        savings_debt_sum = expenses_sums['savings_debt_sum']

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

@app.route('/get_expenses_list/<wallet_id>', methods=['GET'])
@login_required
def get_expenses_list(wallet_id):
    try:
        expenses = db.expenses.aggregate([
            {
                '$match': {
                    'expense_wallet_id': ObjectId(wallet_id)
                }
            },
            {
                '$lookup': {
                    'from': 'types',
                    'localField': 'expense_type_id',
                    'foreignField': 'type_id',
                    'as': 'expense_type'
                }
            },
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'expense_user_id',
                    'foreignField': 'user_id',
                    'as': 'expense_user'
                }
            },
            {
                '$unwind': '$expense_type'
            },
            {
                '$unwind': '$expense_user'
            },
            {
                '$project': {
                    'expense_id': 1,
                    'expense_name': 1,
                    'expense_amount': 1,
                    'expense_date': 1,
                    'type_name': '$expense_type.type_name',
                    'user_email': '$expense_user.user_email'
                }
            },
            {
                '$sort': {
                    'expense_date': 1
                }
            }
        ])

        expenses_list = [
            {
                "expense_id": str(expense['_id']),
                "name": expense['expense_name'],
                "amount": expense['expense_amount'],
                "type": expense['type_name'],
                "date": str(expense['expense_date']),
                "user": expense['user_email']
            }
            for expense in expenses
        ]

        return jsonify({"success": True, "expenses_list": expenses_list})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/logout')
@login_required
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))  

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)