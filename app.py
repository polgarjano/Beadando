from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import redis
import datetime
from passlib.hash import bcrypt
from enum import Enum


class Permissions(Enum):
    ADMINISTRATOR = "administrator"
    COACH = "coach"


class Personal_data(Enum):
    PASSWORD = "password"
    CLUB = "club"
    SESSION = "session"


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '0123'  # Use a strong, random key
jwt = JWTManager(app)

master = redis.Redis(host='localhost', port=6379, db=0)

slaves = []

slaves.append(redis.Redis(host='localhost', port=6479, db=0))
slaves.append(redis.Redis(host='localhost', port=6579, db=0))

actual_slave = 0


def get_slave():
    global actual_slave
    actual_slave = actual_slave + 1
    if actual_slave >= len(slaves):
        actual_slave = 0
    return slaves[actual_slave]


def permission_validation(actual_user, permisons):
    keys = actual_user.keys()
    for p in permisons:
        if not (p in keys and actual_user[p] == '1'):
            return False
    return True


def authorization(actual_user, permisons):
    # Ensure the session is valid by checking Redis
    keys = ["session"] + permisons
    user_info = master.hmget(actual_user, ["session"] + permisons)

    user_info = {keys[i]: user_info[i].decode() for i in range(len(user_info)) if user_info[i] != None}

    if not ("session" in user_info.keys() and user_info["session"] == request.headers.get('Authorization').split(" ")[
        1]):
        return (False, jsonify(message='Unauthorized'), 401)

    if not permission_validation(user_info, permisons):
        return (False, jsonify(message='Unauthorized'), 401)

    return (True, user_info)


@app.route('/')
def home():
    return "Hello"


# User registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    club_name = data.get('club_name')
    print(username, password)

    if not username or not password or not club_name:
        return jsonify(message='Username , password and club name are required'), 400

    with master.pipeline() as pipe:
        try:
            pipe.watch(username)
            pipe.watch(club_name)
            if pipe.hexists(username, "password"):
                return jsonify(message='Username already exists'), 409

            if pipe.hexists(club_name, "activ"):
                return jsonify(message='club name already exists'), 409

            # Hash the password before storing
            pipe.multi()
            hashed_password = bcrypt.hash(password)
            pipe.hset(username, "password", hashed_password)
            pipe.hset(username, "club", club_name)
            pipe.hset(username, Permissions.ADMINISTRATOR.value, 1)

            pipe.hset(club_name, "activ", "1")
            results = pipe.execute()
            print(results)
        except Exception as e:
            # If there's an error (like WatchError or other Redis errors), the transaction failed
            return jsonify(message=e), 409

    return jsonify(message='User registered successfully'), 201


# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if user exists in Redis
    if not master.hexists(username, "password"):
        return jsonify(message='Invalid password or username'), 404

    stored_hashed_password = master.hget(username, "password").decode()

    if stored_hashed_password == "":
        return jsonify(message='Invalid password or username'), 404

    # Verify the hashed password
    if not bcrypt.verify(password, stored_hashed_password):
        return jsonify(message='Invalid password or username'), 401

    # Create a JWT token with user identity
    access_token = create_access_token(identity=username)

    # Store token in Redis to track user session
    master.hset(username, "session", access_token)

    return jsonify(access_token=access_token), 200


# Protected endpoint
@app.route('/protected/coach', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def protected_coach():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    return jsonify(message=f'Hello, {current_user}'), 200


# Protected endpoint
@app.route('/protected/admin', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def protected_administrator():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.ADMINISTRATOR.value])
    if aut[0] == False:
        return aut[1], aut[2]

    return jsonify(message=f'Hello, {current_user}'), 200


# Logout endpoint
@app.route('/logout', methods=['POST'])
@jwt_required()  # User must be logged in to log out
def logout():
    current_user = get_jwt_identity()

    # Remove the session from Redis to log out
    master.hdel(current_user, "session")

    return jsonify(message='Logged out successfully'), 200


# coach registration endpoint
@app.route('/register/coach', methods=['POST'])
@jwt_required()
def register_coach():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    # Ensure the session is valid by checking Redis
    aut = authorization(current_user, [Permissions.ADMINISTRATOR.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    club_name = master.hget(username, "club")
    print(username, password)

    if not username or not password or not club_name:
        return jsonify(message='Username and password name are required'), 400

    with master.pipeline() as pipe:
        try:
            pipe.watch(username)

            if pipe.hexists(username, "password"):
                return jsonify(message='Username already exists'), 409

            # Hash the password before storing
            pipe.multi()
            hashed_password = bcrypt.hash(password)
            pipe.hset(username, "password", hashed_password)
            pipe.hset(username, "club", club_name)
            pipe.hset(username, Permissions.COACH.value, 1)

            results = pipe.execute()
            print(results)
        except Exception as e:
            # If there's an error (like WatchError or other Redis errors), the transaction failed
            return jsonify(message=e), 409

    return jsonify(message='User registered successfully'), 201


# Competitor registration endpoint
@app.route('/register/competitor', methods=['POST'])
@jwt_required()
def register_compatitor():
    # Get the user identity from the token
    current_user = get_jwt_identity()
    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    bibn = data.get('bibn')
    name = data.get('name')
    coach = current_user

    if not bibn or not name:
        return jsonify(message='BIBno and Name  are required'), 400

    with master.pipeline() as pipe:
        try:
            pipe.watch(bibn)

            if pipe.hexists(bibn, "password"):
                return jsonify(message='competitor already exists'), 409

            # Hash the password before storing
            pipe.multi()
            hashed_password = ""
            pipe.hset(bibn, "password", hashed_password)
            pipe.hset(coach, bibn, name)
            results = pipe.execute()
            print(results)
        except Exception as e:
            # If there's an error (like WatchError or other Redis errors), the transaction failed
            return jsonify(message="Something went wrong"), 409

    return jsonify(message='Competitor registered successfully'), 201


@app.route('/coach/all_competitor', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def all_competitor_for_coach():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    slave = get_slave()

    user_info = slave.hgetall(current_user)

    personol_data = [s.value for s in Personal_data] + [s.value for s in Permissions]

    user_info = {key.decode(): value.decode() for key, value in user_info.items() if key.decode() not in personol_data}


    return jsonify(message=user_info), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
