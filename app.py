from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import redis
import re
from passlib.hash import bcrypt
from enum import Enum
from user_managment.Permissions import Permissions
from user_managment.Personal_data import Personal_data
from user_managment.System_data import System_data
from user_managment.app_regexps import PASSWORD_REGEXP, DATE_REGEXP
from user_managment.user_managment import register_user, register_entyty, authorization as aut_app, \
    logout as logout_app, login as login_app
from user_managment.app_transaction import AppTransaction


class COMPETITION_EVENTS(Enum):
    Air_Pistol_Men = "Air_Pistol_Man"
    Air_Pistol_Women_Junior = "Air_Pistol_Women_Junior"


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '0123'  # Use a strong, random key
jwt = JWTManager(app)

master = redis.Redis(host='localhost', port=6379, db=0)
master_results = redis.Redis(host='localhost', port=6379, db=1)

slaves = []
slaves_results = []

slaves.append(redis.Redis(host='localhost', port=6479, db=0))
slaves.append(redis.Redis(host='localhost', port=6579, db=0))

slaves_results.append(redis.Redis(host='localhost', port=6479, db=1))
slaves_results.append(redis.Redis(host='localhost', port=6579, db=1))

actual_slave = 0
actual_slave_results = 0


def get_slave():
    global actual_slave
    actual_slave = actual_slave + 1
    if actual_slave >= len(slaves):
        actual_slave = 0
    return slaves[actual_slave]


def get_slave_results():
    global actual_slave_results
    actual_slave_results = actual_slave_results + 1
    if actual_slave_results >= len(slaves_results):
        actual_slave_results = 0
    return slaves_results[actual_slave_results]


def permission_validation(actual_user, permisons):
    keys = actual_user.keys()
    for p in permisons:
        if not (p in keys and actual_user[p] == '1'):
            return False
    return True


def authorization(actual_user, permissions):
    aut_result = aut_app(master, actual_user, permissions, request.headers.get('Authorization').split(" ")[1])
    # Ensure the session is valid by checking Redis
    if aut_result == False:
        return (False, jsonify(message='Unauthorized'), 401)
    return (True, "")


@app.route('/')
def home():
    return "Hello"


# User registration endpoint
@app.route('/register', methods=['POST'])
def register_administrator():
    data = request.get_json()
    username = data.get('username')
    password = data.get(System_data.PASSWORD.value)
    club_name = data.get(Personal_data.CLUB.value)

    if not username or not password or not club_name:
        return jsonify(message='Username , password and club name are required'), 400

    at = AppTransaction(master.pipeline())
    user_data = {Personal_data.CLUB.value: club_name}
    register_user(at, username, password, [Permissions.ADMINISTRATOR.value, Permissions.USER.value], user_data)
    register_entyty(at, club_name, {"active": 1}, "Club already exists")
    result = at.execute()

    if result[1] == 200:
        return jsonify(message='User registered successfully'), 201

    return jsonify(message=result[0]), result[1]


# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    result = login_app(master, username, password, create_access_token, [], {"identity": username})
    # Check if user exists in Redis and can login

    if not result[0]:
        return jsonify(message='Invalid password or username'), 404

    return jsonify(access_token=result[1]), 200


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
    logout_app(master, current_user)
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
    password = data.get(System_data.PASSWORD.value)
    club_name = master.hget(current_user, Personal_data.CLUB.value)
    print(username, password)
    print(club_name)
    if not username or not password or not club_name:
        return jsonify(message='Username and password name are required'), 400

    at = AppTransaction(master.pipeline())
    user_data = {Personal_data.CLUB.value: club_name}
    register_user(at, username, password, [Permissions.COACH.value, Permissions.USER.value], user_data)
    result = at.execute()

    if result[1] == 200:
        return jsonify(message='User registered successfully'), 201

    return jsonify(message=result[0]), result[1]


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

    club_name = get_slave().hget(coach, Personal_data.CLUB.value)

    if not bibn or not name:
        return jsonify(message='BIBno and Name  are required'), 400

    if not bool(re.match(r"^\d+$", bibn)):
        return jsonify(message='BIBno can only contain numbers'), 400

    at = AppTransaction(master.pipeline())
    user_data = {Personal_data.CLUB.value: club_name}
    register_user(at, bibn, "123abcEFG?", [], user_data)
    result = at.execute()

    if result[1] == 200:
        master.hset(coach, "_" + bibn, name)
        master.hset(bibn, "name", name)
        return jsonify(message='User registered successfully'), 201

    return jsonify(message=result[0]), result[1]


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

    personol_data = [s.value for s in Personal_data] + [s.value for s in Permissions] + [s.value for s in System_data]

    user_info = {key.decode(): value.decode() for key, value in user_info.items() if key.decode() not in personol_data}

    return jsonify(message=user_info), 200


@app.route('/coach/competitor', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def competitor_for_coach():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    bibn = str(data.get('bibn'))

    slave = get_slave()
    if slave.hexists(current_user, "_" + bibn):
        user_info = slave.hgetall(bibn)
        black_list = [s.value for s in Permissions] + [s.value for s in System_data]
        user_info = {key.decode(): value.decode() for key, value in user_info.items() if key.decode() not in black_list}

        return jsonify(message={bibn: user_info}), 200

    return jsonify(message="Competitor not found"), 404


@app.route('/events', methods=['GET'])
def evets():
    return jsonify(message=[s.value for s in COMPETITION_EVENTS]), 200


@app.route('/coach/competitor/result', methods=['POST'])
@jwt_required()  # This decorator requires a valid JWT token
def add_result():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    result_data = {}
    result_data["bibn"] = data.get('bibn')
    result_data["date"] = data.get('date')
    result_data["result"] = data.get('result')
    result_data["event"] = data.get('event')

    for k in result_data:
        if not result_data[k]:
            return jsonify(message='BIBno, date, result and event  are required'), 400
        result_data[k] = str(result_data[k])

    if not bool(re.match(r"^\d+$", result_data["result"])):
        return jsonify(message='result can only contain numbers'), 400

    if not bool(re.match(DATE_REGEXP, result_data["date"])):
        return jsonify(message='date is in wrong format '), 400
    valid = False
    for e in COMPETITION_EVENTS:
        if e.value == result_data["event"]:
            valid = True
    if not valid:
        return jsonify(message='Unknown event'), 400

    # TODO input validation
    slave = get_slave()
    if not slave.hexists(current_user, "_" + result_data["bibn"]):
        return jsonify(message="Competitor not found"), 404

    id = str(master_results.incr("_" + result_data["bibn"] + "_No"))
    master_results.sadd("_" + result_data["bibn"] + "_Events", result_data["event"])
    bibn = result_data.pop("bibn")
    event = result_data.pop("event")
    result_data = {(id + "_" + k): v for k, v in result_data.items()}
    master_results.hset(("_" + bibn + "_" + event), mapping=result_data)

    return jsonify(message="New result added"), 201


@app.route('/coach/competitor/events', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def get_events_for_competitor():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    bibn = str(data.get('bibn'))

    slave = get_slave()
    if slave.hexists(current_user, "_" + bibn):
        slave = get_slave_results()
        events = slave.smembers("_" + bibn + "_Events")
        events = [e.decode() for e in events]
        return jsonify(message=events), 200

    return jsonify(message="Competitor not found"), 404


@app.route('/coach/competitor/result', methods=['GET'])
@jwt_required()  # This decorator requires a valid JWT token
def get_results_for_competitor():
    # Get the user identity from the token
    current_user = get_jwt_identity()

    aut = authorization(current_user, [Permissions.COACH.value])
    if aut[0] == False:
        return aut[1], aut[2]

    data = request.get_json()
    bibn = str(data.get('bibn'))
    event = data.get('event')

    if not event:
        return jsonify(message='event  is required'), 400

    slave = get_slave()
    if slave.hexists(current_user, "_" + bibn):
        slave = get_slave_results()
        events = slave.hgetall("_" + bibn + "_" + event)
        events = {k.decode(): v.decode() for k, v in events.items()}
        return jsonify(message=events), 200

    return jsonify(message="Competitor not found"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
