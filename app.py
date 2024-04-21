from flask import Flask, request, jsonify
import redis

app = Flask(__name__)

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


@app.route('/')
def home():
    return "Hello"


@app.route('/data', methods=['POST'])
def create_data():
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')

    if key and value:
        master.set(key, value)
        return jsonify({'message': 'Key-value pair created'}), 201
    else:
        return jsonify({'error': 'Invalid data'}), 400


@app.route('/data/<key>', methods=['GET'])
def get_data(key):
    value = get_slave().get(key)
    print(actual_slave)

    if value:
        return jsonify({'key': key, 'value': value.decode('utf-8')})
    else:
        return jsonify({'error': 'Key not found'}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
