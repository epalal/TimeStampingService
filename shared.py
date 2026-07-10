import struct

# Message types
MSG_TYPE_HANDSHAKE = 1
MSG_TYPE_AUTH = 2
MSG_TYPE_BALANCE = 3
MSG_TYPE_TIMESTAMP = 4

HEADER_FORMAT = "!BI"  # 1 byte for type, 4 bytes for length
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def pack_message(msg_type, payload):
    """Packs a message with a header."""
    return struct.pack(HEADER_FORMAT, msg_type, len(payload)) + payload

def unpack_message(conn):
    """Unpacks a message from a socket."""
    header = conn.recv(HEADER_SIZE)
    if not header:
        return None, None
    msg_type, payload_len = struct.unpack(HEADER_FORMAT, header)
    payload = conn.recv(payload_len)
    return msg_type, payload
