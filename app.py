from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from functools import wraps  # Importing wraps
from flask_cors import CORS
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
import os
from dotenv import load_dotenv

load_dotenv()

# Configuring Flask app
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure secret key
jwt = JWTManager(app)



# Dummy user data for demonstration
users = {
    'user1': {'password': 'password1', 'role': 'user'},
    'admin': {'password': 'adminpassword', 'role': 'admin'}
}

# Role check decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify(msg='You are not allowed to see this, you are not an admin!'), 403
        return fn(*args, **kwargs)
    return wrapper

# Public route
@app.route('/')
def public():
    return jsonify(msg="This is a public endpoint, accessible by everyone.")

# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = users.get(username, None)
    if not user or user['password'] != password:
        return jsonify(msg="Bad username or password"), 401

    access_token = create_access_token(identity=username, additional_claims={"role": user['role']})
    return jsonify(access_token=access_token)

# Protected route
@app.route('/protected')
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(msg=f"Hello {current_user}, you are logged in and can access this route.")

# Admin-only route
@app.route('/adminonly')
@admin_required
def admin_only():
    return jsonify(msg="Welcome, admin. This is an admin-only endpoint.")

if __name__ == "__main__":
    app.run(port=os.getenv('PORT'), debug=True, host="0.0.0.0")
