import logging
import sys
import time
import pprint
import hashlib
import json
import utils
import ecdsa



logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = not logging.getLogger(__name__)

Mining_Difficulty = 3
Mining_Sender = 'Blockchain'
Mining_Reward = 1.0

class BlockChain(object):
    def __init__(self, blockchain_address=None, port=None):
        self.transaction_pool = []
        self.chain = []
        self.create_block(0, self.hash({}))
        self.blockchain_address = blockchain_address
        self.port = port

    def create_block(self, nonce, previous_hash):
        block = utils.sorted_by_key({
            'timestamp': time.time(),
            'transaction': self.transaction_pool,
            'nonce': nonce,
            'previous': previous_hash
        })
        self.chain.append(block)
        self.transaction_pool = []
        return block

    def hash(self, block):
        sorted_block = json.dumps(block, sort_keys=True)
        return hashlib.sha256(sorted_block.encode()).hexdigest()

    def add_transaction(self, sender_blockchain_address, receive_blockchain_address, value,
                        sender_publickey=None, signature=None):
        transaction = utils.sorted_by_key({
            '送信者': sender_blockchain_address,
            '受信者': receive_blockchain_address,
            '価格': float(value)
        })

        if sender_blockchain_address == Mining_Sender:
            self.transaction_pool.append(transaction)
            return True

        if self.verify_transaction_signature(
                sender_publickey, signature, transaction):
            self.transaction_pool.append(transaction)
            return True
        return False

    def verify_transcation_signature(self, sender_publickey, signature, transaction):
        sha256 = hashlib.sha256()
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        signature_bytes = bytes().fromhex(signature)
        verifying_key = ecdsa.VerifyingKey.from_string(
            bytes().fromhex(sender_publickey), curve=ecdsa.NIST256p
        )
        verified_key = verifying_key.verify(signature_bytes, message)
        return verified_key


    def valid_proof(self, transaction, previous_hash, nonce, difficulty=Mining_Difficulty):
        guess_block = utils.sorted_by_key({
            'transaction': transaction,
            'previous_hash': previous_hash,
            'nonce': nonce
        })
        guess_hash = self.hash(guess_block)
        return guess_hash[:difficulty] == '0'*difficulty

    def proof_of_work(self):
        transaction = self.transaction_pool.copy()
        previous_hash = self.hash(self.chain[-1])
        nonce = 0
        while self.valid_proof(transaction,previous_hash,nonce) is False:
            nonce += 1
        return nonce

    def mining(self):
        self.add_transaction(
            sender_blockchain_address=Mining_Sender,
            receive_blockchain_address=self.blockchain_address,
            value=Mining_Reward
        )
        nonce = self.proof_of_work()
        previous_hash = self.hash(self.chain[-1])
        self.create_block(nonce,previous_hash)
        # logger.info({'action':'mining', 'status':'success'})
        logging.info('Mining success')
        return True

    def calculate_total_price(self, blockchain_address):
        total_price = 0.0
        for i in self.chain:
            for j in i['transactions']:
                value = float(j['value'])
                if blockchain_address == j['sender_blockchain_address']:
                    total_price -= value
                if blockchain_address == j['receive_blockchain_address']:
                    total_price += value
        return total_price




if __name__ == '__main__':
    my_blockchain_address = 'my_blockchain_address'
    block_chain = BlockChain(blockchain_address=my_blockchain_address)
    pprint.pprint(block_chain.chain)
    print(f'{"-"*50}')

    # block_chain.add_transaction('tom','jenny',1.0)
    previous_hash = block_chain.hash(block_chain.chain[-1])
    nonce = block_chain.proof_of_work()
    block_chain.create_block(nonce, previous_hash)
    pprint.pprint(block_chain.chain)
    print(f'{"-" * 50}')

    block_chain.add_transaction('brown', 'jenny', 1.0)
    block_chain.add_transaction('brown', 'jenny', 1.0)
    previous_hash = block_chain.hash(block_chain.chain[-1])
    block_chain.create_block(nonce, previous_hash)
    pprint.pprint(block_chain.chain)

    print(f'{"-" * 50}')
    block_chain.add_transaction('tom', 'jenny', 1.0)
    previous_hash = block_chain.hash(block_chain.chain[-1])
    nonce = block_chain.proof_of_work()
    block_chain.create_block(nonce, previous_hash)
    block_chain.minig()
    pprint.pprint(block_chain.chain)

    # print('my : ', block_chain.calculate_total_price(my_blockchain_address))
    print('tom : ', block_chain.calculate_total_price('tom'))
    # print('my : ', block_chain.calculate_total_price(my_blockchain_address))







