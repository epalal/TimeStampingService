import os
import socket
from shared import unpack_message, MSG_TYPE_HANDSHAKE, pack_message, SecureChannel, MSG_TYPE_AUTH, MSG_TYPE_AUTH_FAILED, \
    MSG_TYPE_INFO, MSG_TYPE_ERROR
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from db import create_db, find_user
import threading


STATE_HANDSHAKE = 0
STATE_LOGIN = 1
STATE_READY = 2


def handshake_protocol(client_nonce: bytes, client_eph_pub_bytes: bytes, privKc: ec.EllipticCurvePrivateKey):
    server_nonce = os.urandom(32)
    eph_priv = ec.generate_private_key(ec.SECP256R1())
       # !!! mismatch with the one used in line 68 ec.SECP256R1 MUST BE CORRECTED
    eph_pub = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    msg = client_eph_pub_bytes + client_nonce + server_nonce + eph_pub_bytes

    sign = privKc.sign(
        msg,
        ec.ECDSA(hashes.SHA256())
    )

    payload = server_nonce + eph_pub_bytes + sign

    return payload, eph_priv, server_nonce


class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, privKc: ec.EllipticCurvePrivateKey):
        super().__init__()
        self.username = None
        self.secure_channel = None
        self.conn = conn
        self.addr = addr
        self.privKc = privKc
        self.state = STATE_HANDSHAKE
        self.session_key = None
        self.conn.settimeout(60.0)

    def run(self):
        with self.conn:
            while True:
                if self.state == STATE_HANDSHAKE:
                    msg_type, payload = unpack_message(self.conn)
                if msg_type is None:
                    print(f"[{self.addr}] Disconnected")
                    break
                if self.state == STATE_HANDSHAKE:
                    if msg_type != MSG_TYPE_HANDSHAKE:
                        print(f"[{self.addr}] Expected handshake message, got {msg_type}")
                        break
                    print(f"[{self.addr}] Received handshake message")

                    client_eph_pub_bytes = payload[:65]
                    client_nonce = payload[65:97]
                    payload, eph_priv, server_nonce = handshake_protocol(
                        client_nonce,
                        client_eph_pub_bytes,
                        self.privKc
                    )

                    self.conn.sendall(pack_message(MSG_TYPE_HANDSHAKE,payload))

                    eph_pub_c = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_eph_pub_bytes)
                    shared_secret = eph_priv.exchange(ec.ECDH(), eph_pub_c)

                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=client_nonce + server_nonce,
                        info=b"TSS v1 session key"
                    )

                    self.session_key = hkdf.derive(shared_secret)
                    self.secure_channel = SecureChannel(self.conn, self.session_key, SecureChannel.ROLE_SERVER)
                    self.state = STATE_LOGIN
                    print(f"[{self.addr}] Handshake completed")
                    msg = self.secure_channel.recv_secure()

                elif self.state == STATE_LOGIN:
                    print(f"[{self.addr}] State login: ask for username")
                    is_credential_wrong = True
                    while is_credential_wrong:
                        username = self.secure_channel.recv_secure()
                        print(f"[{self.addr}] State login: Username received. Ask for password")
                        password = self.secure_channel.recv_secure()
                        if find_user(username, password):
                            print(f"[{self.addr}] User {username} logged")
                            self.username = username
                            is_credential_wrong = False
                            self.state = STATE_READY
                        else:
                            print(f"[{self.addr}] Wrong credentials")
                            self.secure_channel.send_secure(MSG_TYPE_AUTH_FAILED, b"Wrong credentials. Try again.")
                            is_credential_wrong = True

                elif self.state == STATE_READY:
                    while True:
                        self.secure_channel.send_secure(MSG_TYPE_INFO,f"Welcome {self.username}!\n Digit:\n 1 - Balance\n 2 - Timestamp")
                        msg = self.secure_channel.recv_secure()

def main():
    host = '127.0.0.1'
    port = 65432

    create_db()

    with open("keys/privKc.pem", "rb") as f:
        privKc = serialization.load_pem_private_key(f.read(), password=None)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        while True:
            print(f"Server listening on {host}:{port}")
            conn, addr = s.accept()
            print(f"Connected by {addr}")
            client_handler = ClientHandler(conn, addr, privKc)
            client_handler.start()


if __name__ == '__main__':
    main()