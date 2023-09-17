from flask import Flask, request, jsonify
from blockchain import Blockchain, Transaction
import uuid
import sys
import requests  # 导入requests模块来发送HTTP请求
import os
import pickle
import threading

app = Flask(__name__)

blockchains = {}
known_nodes = ["http://localhost:5001", "http://localhost:5002"] 

def load_all_blockchains_from_disk():
    for filename in os.listdir('.'):
        if filename.startswith('blockchain_') and filename.endswith('.pkl'):
            with open(filename, 'rb') as f:
                blockchain = pickle.load(f)
                blockchains[blockchain.blockchain_id] = blockchain

load_all_blockchains_from_disk()

def generate_blockchain_id():
    return str(uuid.uuid4())

@app.route('/blockchain/new', methods=['POST'])
def new_blockchain():
    request_data = request.get_json()
    creator_public_key = request_data.get('public_key')
    creator_signature = request_data.get('signature')
    
    # Ensure the public key and signature are provided
    if not creator_public_key or not creator_signature:
        return jsonify({'message': 'Missing public key or signature'}), 400

    blockchain_id = generate_blockchain_id()
    blockchain = Blockchain(blockchain_id, creator_public_key, creator_signature)

    # Create the genesis block
#    blockchain.create_genesis_block()
    blockchains[blockchain_id] = blockchain
    blockchain.save()

    # Notify all known nodes
    for node in known_nodes:
        try:
            requests.get(f"{node}/blockchain/sync", headers={"Blockchain-ID": blockchain_id})
        except:
            pass  # If the request fails, move to the next node
    return jsonify({'message': 'New blockchain created', 'blockchain_id': blockchain_id}), 201

@app.route('/blockchain/sync', methods=['GET'])
def sync_blockchain():
    blockchain_id = request.headers.get('Blockchain-ID')
    if not blockchain_id in blockchains:
        blockchain = Blockchain(blockchain_id)
        blockchain.create_genesis_block()
        blockchains[blockchain_id] = blockchain
        return "Blockchain synced", 201
    return "Blockchain already exists", 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    blockchain_id = request.headers.get('Blockchain-ID')
    blockchain = blockchains.get(blockchain_id)
    if not blockchain:
        return "Error: Blockchain ID not found", 404

    transaction_data = request.get_json()
    transaction = Transaction(**transaction_data)
    blockchain.add_transaction(transaction)
    blockchain.save()

    miner_thread = threading.Thread(target=background_mine, args=(blockchain,))
    miner_thread.start()
    return "Transaction added", 201

def background_mine(blockchain):
    if blockchain.mine():
        blockchain.save()
        return "New block mined", 200
    else:
        return "No transaction to mine", 400
    
#@app.route('/mine', methods=['GET'])
#def mine():
#    blockchain_id = request.headers.get('Blockchain-ID')
#    blockchain = blockchains.get(blockchain_id)
#    if not blockchain:
#        return "Error: Blockchain ID not found", 404

#    if blockchain.mine():
#        blockchain.save()
#        return "New block mined", 200
#    else:
#        return "No transaction to mine", 400

@app.route('/chain', methods=['GET'])
def full_chain():
    blockchain_id = request.headers.get('Blockchain-ID')
    blockchain = blockchains.get(blockchain_id)
    if not blockchain:
        return "Error: Blockchain ID not found", 404

#    response = {
#        'chain': [block.__dict__ for block in blockchain.chain],
#        'length': len(blockchain.chain),
#    }
    response = {
            'chain': [
                {
                    **block.__dict__,
                    'transactions': [tx.to_dict() for tx in block.transactions]
                }
                for block in blockchain.chain
            ],
            'length': len(blockchain.chain),
        }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    blockchain_id = request.headers.get('Blockchain-ID')
    blockchain = blockchains.get(blockchain_id)
    if not blockchain:
        return "Error: Blockchain ID not found", 404

    nodes = request.get_json().get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        blockchain.register_node(node)
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    blockchain_id = request.headers.get('Blockchain-ID')
    blockchain = blockchains.get(blockchain_id)
    if not blockchain:
        return "Error: Blockchain ID not found", 404

    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': [block.__dict__ for block in blockchain.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': [block.__dict__ for block in blockchain.chain]
        }
    return jsonify(response), 200

#if __name__ == '__main__':
#    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(host='127.0.0.1', port=port)
