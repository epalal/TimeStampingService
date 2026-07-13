import socket
from shared import unpack_message


def main():
    """
    Main function to run the TimeStamping Server.
    """
    host = '127.0.0.1'  # Standard loopback interface address (localhost)
    port = 65432        # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                msg_type, payload = unpack_message(conn)
                if msg_type is None:
                    break
                print(f"Received message type: {msg_type}")
                print(f"Received payload: {payload.decode()}")
                # Message handling logic will go here
                # ciao

if __name__ == '__main__':
    main()
