import socket
import time
import os

from cryptography.exceptions import InvalidSignature

from shared import unpack_message, MSG_TYPE_HANDSHAKE, pack_message, SecureChannel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from shared import pack_message, MSG_TYPE_HANDSHAKE

def main():
    host = '127.0.0.1'
    port = 65432

    with open("keys/pubKc.pem", "rb") as f:
        pubKc = serialization.load_pem_public_key(
            f.read())
        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to server at {host}:{port}")
        client_nonce = os.urandom(32)
        eph_priv_c = ec.generate_private_key(ec.SECP256R1())
        client_eph_pub_bytes = eph_priv_c.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        payload_out = client_eph_pub_bytes + client_nonce
        s.sendall(pack_message(MSG_TYPE_HANDSHAKE, payload_out))

        msg_type, payload_in = unpack_message(s)
        if msg_type != MSG_TYPE_HANDSHAKE:
            print("[-] Errore: Messaggio inatteso dal server.")
            return
    
        server_nonce = payload_in[:32]
        server_eph_pub_bytes = payload_in[32:97]
        signature = payload_in[97:]

        transcript = client_eph_pub_bytes + client_nonce + server_nonce + server_eph_pub_bytes
        try:
            pubKc.verify(signature, transcript, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("[-] Errore CRITICO: Firma del server non valida. Possibile attacco MITM.")
            return
        pubKc.verify(signature,transcript, ec.ECDSA(hashes.SHA256()))

        server_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            server_eph_pub_bytes
        )

        shared_secret = eph_priv_c.exchange(ec.ECDH(), server_eph_pub)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=client_nonce + server_nonce,
            info=b"TSS v1 session key"
        )
        session_key = hkdf.derive(shared_secret)
        secure_channel = SecureChannel(s, session_key, SecureChannel.ROLE_CLIENT)

        print("Handshake Completed. Perfect Forward Secrecy guaranteed.")

        print("Test: Invio un ping cifrato al server...")

        # Usiamo un MSG_TYPE fittizio (es. 99) per testare l'invio cifrato
        secure_channel.send_secure(99, b"Ping dal tunnel AES-GCM!")

if __name__ == '__main__':
    main()