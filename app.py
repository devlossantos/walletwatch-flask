from flask import Flask, render_template, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from config.config import get_config
import logging
import os

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config.from_object(get_config())

# Set the logging level to capture all messages
logging.basicConfig(level=logging.DEBUG)

# Create a logger instance for your application
logger = app.logger

try:
    mysql = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        port=app.config['MYSQL_PORT'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    logger.info("Database connection established")

    # Read and execute the SQL file to create tables
    with app.open_resource('sql/create_tables.sql', mode='r') as f:
        with mysql.cursor() as cursor:
            cursor.execute(f.read())

    jwt = JWTManager(app)

except Exception as e:
    logger.error("An error occurred during database connection: %s", str(e))

# User model
class User:
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

# Database queries
def get_user(email):
    cursor = mysql.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user_data = cursor.fetchone()
    cursor.close()
    if user_data:
        return User(user_data['id'], user_data['email'], user_data['password'])
    return None

def create_user(email, password):
    cursor = mysql.cursor()
    cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, generate_password_hash(password)))
    mysql.commit()
    cursor.close()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
        return jsonify({'msg': 'Invalid email or password'}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if get_user(email):
            return jsonify({'msg': 'User already exists'}), 400
        create_user(email, password)
        return jsonify({'msg': 'User created successfully'}), 201
    return render_template('signup.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return render_template('dashboard.html', user=current_user)

@app.route('/expenses')
@jwt_required()
def expenses():
    current_user = get_jwt_identity()
    return render_template('expenses.html', user=current_user)

@app.route('/analytics')
@jwt_required()
def analytics():
    current_user = get_jwt_identity()
    return render_template('analytics.html', user=current_user)

@app.route('/settings')
@jwt_required()
def settings():
    current_user = get_jwt_identity()
    return render_template('settings.html', user=current_user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)