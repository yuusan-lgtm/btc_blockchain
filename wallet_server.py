from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request

import wallet

app = Flask(__name__, template_folder='./templates')

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/wallet', methods=['POST'])
def create_wallet():
    my_wallet = wallet.Wallet()
    response = {
        'private_key': my_wallet.private_key,
        'public_key': my_wallet.public_key,
        'blockchain_address': my_wallet.blockchain_address,

    }
    return jsonify(response), 200

@app.route('/transaction', method=['POST'])
def create_transaction():
    request_json = request.json
    required = (
        'sender_private_key',
        'sender_blockchain_address',
        'recipient_blockchain_address',
        'value',
        'sender_public_key',
        'signature'
    )
    if not all(k in request_json for k in required):
        return jsonify({'message': 'missing values'}), 400

    sender_private_key = request_json['sender_private_key']
    sender_blockchain_address = request_json['sender_blockchain_address']
    recipient_blockchain_address = request_json['recipient_blockchain_address']
    value = request_json['value']
    sender_public_key = request_json['sender_public_key']
    signature = request_json['signature']

    transaction = wallet.Transaction(
        sender_private_key,
        sender_blockchain_address,
        recipient_blockchain_address,
        value,
        sender_public_key,
        signature
    )


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080,
                        type=int, help='port to listen on')
    parser.add_argument('-g', '--gw', default='http://127.0.0.1:5000',
                        type=str, help='blockchain gateway')
    args = parser.parse_args()
    port = args.port
    app.config['gw'] = args.gw

    app.run(host='0.0.0.0', port=port, threaded=True, debug=True)