import socket
import time

from shared import pack_message, MSG_TYPE_HANDSHAKE

def main():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        while True:
            message = "Hello, from Bob!"
            packed_message = pack_message(MSG_TYPE_HANDSHAKE, message.encode())
            s.sendall(packed_message)
            print(f"Sent to server: {message}")
            time.sleep(1)

if __name__ == '__main__':
    main()
