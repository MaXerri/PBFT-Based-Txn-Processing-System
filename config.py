from cryptography.hazmat.primitives import serialization
from blspy import AugSchemeMPL, G1Element, PrivateKey
import pickle


NUM_NODES = 7
nodes_info = {i: ("127.0.0.1", 5000 + i) for i in range(1, NUM_NODES + 1)}
NUM_CLIENTS = 10  
latencies = []



with open("keys.pkl", "rb") as f:
    node_keys_bytes, client_keys_bytes, all_public_keys_bytes, bls_node_keys_bytes, bls_node_public_keys_bytes = pickle.load(f)

# Convert back to actual key objects
node_keys = {
    i: serialization.load_pem_private_key(v, password=None)
    for i, v in node_keys_bytes.items()
}

client_keys = {
    k: serialization.load_pem_private_key(v, password=None)
    for k, v in client_keys_bytes.items()
}

all_public_keys = {
    k: serialization.load_pem_public_key(v)
    for k, v in all_public_keys_bytes.items()
}

# --- Reconstruct BLS keys from bytes ---
bls_node_keys = {
    i: PrivateKey.from_bytes(v) for i, v in bls_node_keys_bytes.items()
}

bls_node_public_keys = {
    i: G1Element.from_bytes(v) for i, v in bls_node_public_keys_bytes.items()
}

