import socket
from shared import pack_message, MSG_TYPE_HANDSHAKE

def main():
    """
    Main function for the TimeStamping Client.
    """
    host = '127.0.0.1'  # The server's hostname or IP address
    port = 65432        # The port used by the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to server at {host}:{port}")
        
        message = "Hello, World!"
        packed_message = pack_message(MSG_TYPE_HANDSHAKE, message.encode())
        s.sendall(packed_message)
        print(f"Sent to server: {message}")

if __name__ == '__main__':
    main()
