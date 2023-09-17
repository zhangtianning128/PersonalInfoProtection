import hashlib
import json
import os
import pickle
import time
import requests

def hash_block(block):
    block_string = json.dumps(block.__dict__, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()

class Block:
    def __init__(self, transactions=None, previous_hash=None, nonce=0):
        self.transactions = transactions if transactions else []
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        transactions_string = json.dumps([tx.__dict__ for tx in self.transactions], sort_keys=True)
        block_string = f'{transactions_string}{self.previous_hash}{self.nonce}'
        return hashlib.sha256(block_string.encode()).hexdigest()

    def proof_of_work(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()


class Blockchain:
    def __init__(self, blockchain_id, creator_public_key, creator_signature, difficulty=2):
        self.creator_public_key = creator_public_key
        self.creator_signature = creator_signature
        self.blockchain_id = blockchain_id
        self.difficulty = difficulty
        self.nodes = set()

        self.chain = []
        self.pending_transactions = []

        # Try to load the blockchain from disk
        self.load()

        # If the blockchain is empty (i.e., it's not on disk), create the genesis block
        if len(self.chain) == 0:
            self.create_genesis_block()

#    def create_genesis_block(self):
#        transactions = []
#        genesis_block = Block(transactions, "0")
#        genesis_block.proof_of_work(self.difficulty)
#        self.chain.append(genesis_block)
    def create_genesis_block(self):
        creator_transaction = Transaction(
            transaction_type="create",
            public_key=self.creator_public_key,
            signature=self.creator_signature,
            reason="Genesis Block"
        )
        transactions = [creator_transaction]
        genesis_block = Block(transactions, "0")
        genesis_block.proof_of_work(self.difficulty)
        self.chain.append(genesis_block)

    def add_block(self, block):
        if len(self.chain) > 0:
            block.previous_hash = self.chain[-1].hash
        block.proof_of_work(self.difficulty)
        self.chain.append(block)

        # Save the blockchain to disk every time a new block is added
        self.save()

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine(self):
        if not self.pending_transactions:
            return False

        new_block = Block(transactions=self.pending_transactions)
        self.add_block(new_block)
        self.pending_transactions = []
        return True

    def register_node(self, node):
        self.nodes.add(node)

    def is_chain_valid(self, chain):
        for i in range(1, len(chain)):
            block = chain[i]
            previous_block = chain[i - 1]
            if block.previous_hash != previous_block.hash:
                return False
            if block.hash != block.calculate_hash():
                return False
        return True

    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain

        if longest_chain:
            self.chain = longest_chain
            return True

        return False

    def save(self):
        with open(f'blockchain_{self.blockchain_id}.pkl', 'wb') as f:
            pickle.dump(self, f)

    def load(self):
        try:
            with open(f'blockchain_{self.blockchain_id}.pkl', 'rb') as f:
                data = pickle.load(f)
                self.chain = data.chain
                self.pending_transactions = data.pending_transactions
        except FileNotFoundError:
            pass


class Transaction:
    def __init__(self, transaction_type, timestamp=None, url=None, public_key=None, signature=None, reason=None, access_type=None, access_grant=None, encrypted_info=None, hash_val=None):
        self.transaction_type = transaction_type
        self.timestamp = timestamp if timestamp else time.time()
        
        if transaction_type == "request":
            self.url = url
            self.public_key = public_key
            self.signature = signature
            self.reason = reason
            self.access_type = access_type
        elif transaction_type == "response":
            self.access_grant = access_grant
            self.encrypted_info = encrypted_info
            self.hash_val = hash_val
        elif transaction_type == "create":
            self.public_key = public_key
            self.signature = signature
            self.reason = reason
        else:
            raise ValueError("Transaction type must be within ['request', 'response', 'create']")

    def to_dict(self):
        if self.transaction_type == "request":
            return {
                'transaction_type': self.transaction_type,
                'timestamp': self.timestamp,
                'url': self.url,
                'public_key': self.public_key,
                'signature': self.signature,
                'reason': self.reason
            }
        elif self.transaction_type == "response":
            return {
                'transaction_type': self.transaction_type,
                'timestamp': self.timestamp,
                'encrypted_info': self.encrypted_info,
                'hash_val': self.hash_val
            }
        elif self.transaction_type == "create":
            return {
                'transaction_type': self.transaction_type,
                'timestamp': self.timestamp,
                'public_key': self.public_key,
                'signature': self.signature,
                'reason': self.reason
            }
        else:
            raise ValueError("Transaction type must be within ['request', 'response', 'create']")

