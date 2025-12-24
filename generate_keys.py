import pickle
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hashlib import sha256
from blspy import AugSchemeMPL, G1Element, PrivateKey

NUM_NODES = 7
NUM_CLIENTS = 10

node_keys = {}
client_keys = {}
all_public_keys = {}

# Threshold BLS keys (store serialized bytes)
bls_node_keys_bytes = {}
bls_node_public_keys_bytes = {}

# --- Helper to generate and serialize ECDSA keypairs ---
def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return priv_bytes, pub_bytes

# --- Generate keys for nodes ---
for i in range(1, NUM_NODES + 1):
    # ECDSA keys
    priv_bytes, pub_bytes = generate_keypair()
    node_keys[i] = priv_bytes
    all_public_keys[i] = pub_bytes

    # BLS threshold keys
    seed = sha256(f"node-{i}-bls-key".encode()).digest()
    bls_sk = AugSchemeMPL.key_gen(seed)
    bls_pk = bls_sk.get_g1()

    # Serialize using bytes()
    bls_node_keys_bytes[i] = bytes(bls_sk)
    bls_node_public_keys_bytes[i] = bytes(bls_pk)

# --- Generate keys for clients ---
for i in range(NUM_CLIENTS):
    cid = chr(ord("A") + i)
    priv_bytes, pub_bytes = generate_keypair()
    client_keys[cid] = priv_bytes
    all_public_keys[cid] = pub_bytes

# --- Save to pickle ---
with open("keys.pkl", "wb") as f:
    pickle.dump(
        (
            node_keys,
            client_keys,
            all_public_keys,
            bls_node_keys_bytes,
            bls_node_public_keys_bytes,
        ),
        f,
    )

print("Keys (ECDSA + Threshold BLS serialized) saved to keys.pkl")