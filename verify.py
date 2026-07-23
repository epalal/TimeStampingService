import json
import os
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def verify_timestamp(pubKts):
    file_path = input("Insert the path of the file to verify: ")
    if not os.path.exists(file_path):
        print("File not found.")
        return
    timestamp_path = input("Insert the path of the timestamp file: ")
    if not os.path.exists(timestamp_path):
        print("Timestamp file not found.")
        return
    with open(timestamp_path, "r") as f:
        try:
            timestamp_data = json.load(f)
        except json.JSONDecodeError:
            print("Invalid timestamp file format.")
            return
    with open(file_path, "rb") as f:
        digest = hashes.Hash(hashes.SHA256())
        while chunk := f.read(8192):
            digest.update(chunk)
        file_hash = digest.finalize()

    if file_hash.hex() == timestamp_data["hash"]:
        msg_to_verify = bytes.fromhex(timestamp_data["hash"]) + struct.pack(">Q", timestamp_data["time"])
        signature = bytes.fromhex(timestamp_data["signature"])
        try:
            pubKts.verify(signature, msg_to_verify, ec.ECDSA(hashes.SHA256()))
            print("Timestamp is valid and signature is verified.")
        except InvalidSignature:
            print("Invalid signature. Timestamp verification failed.")
    else:
        print("File hash does not match the hash in the timestamp. Verification failed.")


if __name__ == '__main__':
    with open("keys/pubKts.pem", "rb") as f:
        pubKts = serialization.load_pem_public_key(f.read())
    verify_timestamp(pubKts)
