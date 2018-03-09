from flask import abort, Flask, jsonify, request
from os import urandom
from struct import unpack
from simon import SimonCipher
import json


def randomUint64():
    return unpack("<Q", urandom(8))[0]


# k = (randomUint64() << 64) + randomUint64()
k = int(json.load(open("./key")), 2)
print('k={0:0128b}'.format(k))
simon = SimonCipher(k)

app = Flask(__name__)


@app.route('/')
def index():
    num = request.args.get('num', '')
    try:
        num = int(num)
    except ValueError:
        abort(400)
    if (num > 10000):
        abort(400)

    samples = []
    for i in range(num):
        m = (randomUint64() << 64) + randomUint64()
        c, l = simon.encrypt(m)
        samples.append((m, l))

    return jsonify(samples)


if __name__ == '__main__':
    app.run(port=3000)
