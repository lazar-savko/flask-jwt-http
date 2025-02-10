from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from functools import wraps
from flask_cors import CORS
import os
from dotenv import load_dotenv
import sys

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ✅ Fix: Ensure JWT_SECRET_KEY is set
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')  # Use a strong secret key

# ✅ Configure CORS to allow credentials
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])

# ✅ Fix: Ensure Flask uses correct cookie settings
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'  # Matches Postman's stored cookie
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

jwt = JWTManager(app)

# Dummy user data for demonstration
users = {
    'user1': {'password': 'password1', 'role': 'user'},
    'admin': {'password': 'adminpassword', 'role': 'admin'}
}


# ✅ Fix: Admin role check decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('role') != 'admin':
            return jsonify(msg='You are not allowed to see this, you are not an admin!'), 403
        return fn(*args, **kwargs)

    return wrapper


# ✅ Public Route
@app.route('/')
def public():
    return jsonify(msg="This is a public endpoint, accessible by everyone.")


# ✅ Secure Login Route (Sets JWT in HTTP-Only Cookie)
@app.route('/login', methods=['POST'])
def login():
    print("🔹 Received login request")
    sys.stdout.flush()  # Ensures print output is shown

    username = request.json.get('username')
    password = request.json.get('password')

    user = users.get(username, None)
    if not user or user['password'] != password:
        print("❌ Invalid credentials")
        sys.stdout.flush()
        return jsonify(msg="Bad username or password"), 401

    access_token = create_access_token(identity=username, additional_claims={"role": user['role']})

    # ✅ Fix: Set the cookie name correctly
    response = make_response(jsonify(msg="Login successful"))
    response.set_cookie(
        app.config['JWT_ACCESS_COOKIE_NAME'], access_token,
        httponly=True, secure=app.config['JWT_COOKIE_SECURE'], samesite='None'
    )

    print(f"✅ Set-Cookie Header: {response.headers.get('Set-Cookie')}")  # Debugging
    sys.stdout.flush()

    return response


# ✅ Secure Logout Route (Clears JWT Cookie)
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify(msg="Logged out successfully"))
    response.set_cookie(
        app.config['JWT_ACCESS_COOKIE_NAME'], '',
        httponly=True, secure=app.config['JWT_COOKIE_SECURE'], expires=0
    )  # Clears the cookie
    return response


# ✅ Protected Route Using HTTP-Only Cookie
@app.route('/protected')
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(msg=f"Hello {current_user}, you are logged in and can access this route.")


# ✅ Admin-only Route
@app.route('/adminonly')
@admin_required
def admin_only():
    return jsonify(msg="Welcome, admin. This is an admin-only endpoint.")


# ✅ Run Server
if __name__ == "__main__":
    app.run(port=int(os.getenv('PORT', 5000)), debug=True, host="0.0.0.0")
