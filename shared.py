import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Message types
MSG_TYPE_HANDSHAKE = 1
MSG_TYPE_AUTH = 2
MSG_TYPE_BALANCE = 3
MSG_TYPE_TIMESTAMP = 4
MSG_TYPE_AUTH_FAILED = 5
MSG_TYPE_TIMESTAMP_ERROR = 6

HEADER_FORMAT = "!BI"  # 1 byte for type, 4 bytes for length
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def pack_message(msg_type, payload):
    """Packs a message with a header."""
    return struct.pack(HEADER_FORMAT, msg_type, len(payload)) + payload


def recv_exact(conn, n):
    """Legge esattamente n byte dalla socket."""
    data = bytearray()
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def unpack_message(conn):
    """Unpacks a message from a socket."""
    header = recv_exact(conn, HEADER_SIZE)
    if not header:
        return None, None
    msg_type, payload_len = struct.unpack(HEADER_FORMAT, header)

    payload = recv_exact(conn, payload_len)
    if payload is None:
        return None, None

    return msg_type, payload


class SecureChannel:
    ROLE_SERVER = 0
    ROLE_CLIENT = 1

    def __init__(self, conn, session_key: bytes, role: int):
        if len(session_key) != 32:
            raise ValueError("La chiave di sessione per AES-256-GCM deve essere di 32 byte.")
        self.conn = conn
        self.aesgcm = AESGCM(session_key)
        self.role = role
        self.send_seq = 0
        self.recv_seq = 0
        self.peer_role = self.ROLE_CLIENT if role == self.ROLE_SERVER else self.ROLE_SERVER

    def _build_iv(self, role: int, seqno: int) -> bytes:
        return struct.pack('!B 3x Q', role, seqno)

    def send_secure(self, msg_type: int, payload: bytes):
        cleartext_msg = pack_message(msg_type, payload)
        iv = self._build_iv(self.role, self.send_seq)

        aad = struct.pack('!Q', self.send_seq)
        encrypted_record = self.aesgcm.encrypt(iv, cleartext_msg, aad)

        frame_len = len(encrypted_record)
        frame_header = struct.pack('!I', frame_len)

        self.conn.sendall(frame_header + encrypted_record)

        self.send_seq += 1

    def recv_secure(self) -> tuple[int, bytes]:
        frame_header = recv_exact(self.conn, 4)
        if not frame_header:
            return None, None

        frame_len = struct.unpack('!I', frame_header)[0]

        encrypted_record = recv_exact(self.conn, frame_len)
        if not encrypted_record:
            return None, None

        expected_iv = self._build_iv(self.peer_role, self.recv_seq)
        expected_aad = struct.pack('!Q', self.recv_seq)


        try:
            cleartext_msg = self.aesgcm.decrypt(expected_iv, encrypted_record, expected_aad)
        except Exception as e:
            print(f"[-] SecureChannel: Errore di decifratura/autenticazione: {e}")
            return None, None

        self.recv_seq += 1

        msg_type, payload_len = struct.unpack(HEADER_FORMAT, cleartext_msg[:HEADER_SIZE])
        payload = cleartext_msg[HEADER_SIZE:HEADER_SIZE + payload_len]

        return msg_type, payload