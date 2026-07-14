import socket
from shared import unpack_message
import threading

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__()
        self.conn = conn
        self.addr = addr

    def run(self):
        with self.conn:
            while True:
                msg_type, payload = unpack_message(self.conn)
                if msg_type is None:
                    break
                print(f"Received message type: {msg_type}")
                print(f"Received payload: {payload.decode()}")



def main():
    host = '127.0.0.1'
    port = 65432


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        while True:
            s.listen()
            print(f"Server listening on {host}:{port}")
            conn, addr = s.accept()
            print(f"Connected by {addr}")
            client_handler = ClientHandler(conn, addr)
            client_handler.start()

if __name__ == '__main__':
    main()
