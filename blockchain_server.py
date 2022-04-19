import blockchain
import wallet
import blockchain
import jinja2

from flask import Flask
from flask import jsonify

app = Flask(__name__)

cache = {}

def get_blockchain():
    cached_blockchain = cache.get('blockchain')
    if not cached_blockchain:
        miners_wallet = wallet.Wallet()
        cache['blockchain'] = blockchain.BlockChain(
            blockchain_address = miners_wallet.blockchain_address,
            port=app.config['port']
        )
        app.logger.warning({
            'private_key': miners_wallet.private_key,
            'public_key': miners_wallet.public_key,
            'blockchain_address': miners_wallet.blockchain_address
        })
        return chahe['blockchain']


@app.route('/hello')
def hello_world():
    return 'Hello, World!'

@app.route('/', methods=['GET'])
def get_chain():
    block_chain = get_blockchain()
    response = {
    'blockchain': block_chain.chain
    }
    return jsonify(response),200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, threaded=True, debug=True)
