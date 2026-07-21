import socket
import os
import struct
import json
from cryptography.exceptions import InvalidSignature
from shared import MSG_TYPE_AUTH_FAILED, MSG_TYPE_BALANCE, SecureChannel, pack_message, unpack_message, MSG_TYPE_HANDSHAKE, MSG_TYPE_AUTH, MSG_TYPE_TIMESTAMP, \
    MSG_TYPE_AUTH_SUCCESS
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

STATE_HANDSHAKE = 0
STATE_LOGIN = 1
STATE_READY = 2

class TSSClient:
    def __init__(self, host: str, port: int, pubKc_path: str):
        self.host = host
        self.port = port
        self.state = STATE_HANDSHAKE
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_channel = None
        
        with open(pubKc_path, "rb") as f:
            self.pubKc = serialization.load_pem_public_key(f.read())

    def run(self):
        self.sock.connect((self.host, self.port))
        try:
            while True:
                if self.state == STATE_HANDSHAKE:
                    self._handshake()
                elif self.state == STATE_LOGIN:
                    self._login()
                elif self.state == STATE_READY:
                    self._ready()
        except KeyboardInterrupt:
            print("Exiting...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.sock.close()

    def _handshake(self):
        client_nonce = os.urandom(32)
        eph_priv_c = ec.generate_private_key(ec.SECP256R1())
        client_eph_pub_bytes = eph_priv_c.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        payload_out = client_eph_pub_bytes + client_nonce
        self.sock.sendall(pack_message(MSG_TYPE_HANDSHAKE, payload_out))
        msg_type, payload_in = unpack_message(self.sock)
        if msg_type != MSG_TYPE_HANDSHAKE:
            print("Error: Unexpected message from server.")
            return
        server_nonce = payload_in[:32]
        server_eph_pub_bytes = payload_in[32:97]
        signature = payload_in[97:]

        transcript = client_eph_pub_bytes + client_nonce + server_nonce + server_eph_pub_bytes
        try:
            self.pubKc.verify(signature, transcript, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("Invalid signature.")
            return

        server_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            server_eph_pub_bytes
        )
        shared_secret = eph_priv_c.exchange(ec.ECDH(), server_eph_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, #64???
            salt=client_nonce + server_nonce,
            info=b"TSS v1 session key"
        )
        session_key = hkdf.derive(shared_secret)
        self.session_key = session_key
        self.secure_channel = SecureChannel(self.sock, self.session_key, SecureChannel.ROLE_CLIENT)
        print("Handshake completed. Perfect Forward Secrecy guaranteed.")
        self.state = STATE_LOGIN

    def _login(self):
        username = input("Username: ")
        password = input("Password: ")
        payload = f"{username}\x00{password}".encode('utf-8')
        self.secure_channel.send_secure(MSG_TYPE_AUTH, payload)
        msg_type, response = self.secure_channel.recv_secure()
        if msg_type == MSG_TYPE_AUTH_SUCCESS:
            print("Succesful Login!")
            self.state = STATE_READY
        elif msg_type == MSG_TYPE_AUTH_FAILED:
            print("Login failed.")
        else:
            print("Error.")

    def _ready(self):
        print("\n--- MENU ---")
        print("1. Request Timestamp")
        print("2. Balance")
        print("3. Logout")
        choice = input("Scelta: ")
        
        if choice == "1":
            self._request_timestamp()
        elif choice == "2":
            self._request_balance()
        elif choice == "3":
            print("Logging out...")
            self.state = STATE_LOGIN
        else:
            print("Invalid choice. Please try again.")

    def _request_timestamp(self):
        filepath = input("Insert the path of the file to timestamp: ")
        if not os.path.exists(filepath):
            print("File not found.")
            return

        digest = hashes.Hash(hashes.SHA256())
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                digest.update(chunk)
            file_hash = digest.finalize()
            print(f"Calculated Hash, to certify: {file_hash.hex()}")

        self.secure_channel.send_secure(MSG_TYPE_TIMESTAMP, file_hash)
        msg_type, response = self.secure_channel.recv_secure()
        if msg_type == MSG_TYPE_TIMESTAMP:
            time_bytes = response[2:10]
            timestamp = struct.unpack(">Q", time_bytes)[0]
            signature = response[10:]

            token_data = {
                    "hash": file_hash.hex(),
                    "time": timestamp,
                    "signature": signature.hex()
                }
            output_path = filepath + ".tsr"
            with open(output_path, "w") as f:
                json.dump(token_data, f, indent=4)
            print(f"Timestamp recieved and saved in {output_path}")
        else:
            print(f"Error from server: {response.decode()}")

    def _request_balance(self):
        self.secure_channel.send_secure(MSG_TYPE_BALANCE, b"")
        msg_type, response = self.secure_channel.recv_secure()
        if msg_type == MSG_TYPE_BALANCE and len(response) == 8:
            nc, nr = struct.unpack('>II', response)
            print(f"Timestamp consumed: {nc}, Timestamp available: {nr}")

if __name__ == '__main__':
    client = TSSClient('127.0.0.1', 65432, "keys/pubKc.pem")
    client.run()