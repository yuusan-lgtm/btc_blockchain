import pprint

import base58
import codecs
import hashlib
import utils
import pprint
import ecdsa

# privke = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)

class  Wallet(object):

    def __init__(self):
        self._privkey= ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        self._publkey = self._privkey.get_verifying_key()
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def privkey(self):
        return self._privkey.to_string().hex()

    @property
    def publkey(self):
        return self._publkey.to_string().hex()

    @property
    def blockchain_address(self):
        return self._blockchain_address

    def generate_blockchain_address(self):
        public_key_bytes = self._publkey.to_string()
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()

        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk.digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk.digest, 'hex')

        byte = b'00'
        bitcoin_publickey = byte + ripemd160_bpk_hex
        bitcoin_publickey_byte = codecs.decode(bitcoin_publickey, 'hex')

        sha256_bpk = hashlib.sha256(bitcoin_publickey_byte)
        sha256_bpk_digest = sha256_bpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_bpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')

        checksum = sha256_hex[:8]

        address_hex = (bitcoin_publickey + checksum).decode('utf-8')

        blockchain_address = base58.b58decode(address_hex).decode('utf-8')
        return blockchain_address

class Transaction(object):

    def __init__(self, sender_privkey, sender_publickey, sender_blockchain_address,
                 receve_blockchain_address,value):
        self.sender_private_key = sender_privkey
        self.sender_public_key = sender_publickey
        self.sender_blockchain_address = sender_blockchain_address
        self.receve_blockchain_address = receve_blockchain_address
        self.value = value

    def generate_signature(self):
        sha256 = hashlib.sha256()
        transaction = utils.sorted_by_key({
            'sender_blockchain_address ' : self.sender_blockchain_address,
            'receve_blockchain_address': self.receve_blockchain_address,
            'value': self.value
        })
        sha256.update(str(transaction).encode('utf-8'))
        message = sha256.digest()
        private_key = ecdsa.SigningKey.from_string(
            bytes().fromhex(self.sender_private_key), curve=ecdsa.NIST256p)
        private_key_sign = private_key.sign(message)
        signature = private_key_sign.hex()
        return signature

if __name__ == '__main__':
    wallet_mining = Wallet()
    wallet_accout1 = Wallet()
    wallet_accout2 = Wallet()
    t = Transaction(
        wallet_accout1.privkey, wallet_accout1.publkey, wallet_accout1.blockchain_address,
        wallet_accout2.blockchain_address,1.0)


    import blockchain
    block_chain = blockchain.BlockChain(
        blockchain_address=wallet_mining.blockchain_address
    )
    is_added = block_chain.add_transaction(
        wallet_accout1.blockchain_address,
        wallet_accout2.blockchain_address,
        1.0,
        wallet_accout1.publkey_key,
        t.generate_signature())
    print('Added?', is_added)
    block_chain.minig()
    pprint.pprint(block_chain.chain)

    print('A', block_chain.calculate_total_price(wallet_accout1.blockchain_address))
    print('B', block_chain.calculate_total_price(wallet_accout2.blockchain_address))









# if __name__ == '__main__':
