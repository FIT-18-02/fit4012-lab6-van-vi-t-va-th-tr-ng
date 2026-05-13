import struct
import socket
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# =========================
# CONSTANTS
# =========================

BLOCK_SIZE = 16
LENGTH_HEADER_SIZE = 4
IV_SIZE = 16
VALID_KEY_SIZES = (16, 32)
SOCKET_TIMEOUT = 10


# =========================
# PKCS#7 PADDING
# =========================

def pad(data: bytes) -> bytes:
    """
    PKCS#7 padding:
    Đưa dữ liệu về bội số của 16 byte.
    """

    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """
    Gỡ và kiểm tra PKCS#7 padding.
    """

    if not data:
        raise ValueError("Dữ liệu rỗng.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding không hợp lệ.")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Sai cấu trúc PKCS#7 padding.")

    return data[:-pad_len]


# =========================
# KEY + IV
# =========================

def generate_aes_key(size: int = 32) -> bytes:
    """
    Sinh AES key:
    - 16 byte = AES-128
    - 32 byte = AES-256
    """

    if size not in VALID_KEY_SIZES:
        raise ValueError("AES key phải dài 16 hoặc 32 byte.")

    return get_random_bytes(size)


def generate_iv() -> bytes:
    """
    AES-CBC cần IV 16 byte.
    """

    return get_random_bytes(IV_SIZE)


# =========================
# AES CBC
# =========================

def encrypt_aes_cbc(
    plaintext: bytes,
    key: bytes,
    iv: bytes
) -> bytes:
    """
    Mã hóa AES-CBC.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("Key size không hợp lệ.")

    if len(iv) != IV_SIZE:
        raise ValueError("IV phải dài 16 byte.")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded = pad(plaintext)

    return cipher.encrypt(padded)


def decrypt_aes_cbc(
    ciphertext: bytes,
    key: bytes,
    iv: bytes
) -> bytes:
    """
    Giải mã AES-CBC.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("Key size không hợp lệ.")

    if len(iv) != IV_SIZE:
        raise ValueError("IV phải dài 16 byte.")

    if not ciphertext:
        raise ValueError("Ciphertext rỗng.")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            "Ciphertext không phải bội số của 16 byte."
        )

    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(ciphertext)

    return unpad(padded_plaintext)


# =========================
# KEY CHANNEL
# FORMAT:
# [key_length:4B][key][iv]
# =========================

def build_key_packet(
    key: bytes,
    iv: bytes
) -> bytes:
    """
    Tạo packet cho key channel.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("Key size không hợp lệ.")

    if len(iv) != IV_SIZE:
        raise ValueError("IV size không hợp lệ.")

    key_len = len(key)

    header = struct.pack("!I", key_len)

    return header + key + iv


def parse_key_packet(
    packet: bytes
) -> Tuple[bytes, bytes]:
    """
    Parse key packet:
    [key_length][key][iv]
    """

    if len(packet) < LENGTH_HEADER_SIZE:
        raise ValueError("Packet quá ngắn.")

    key_len = struct.unpack(
        "!I",
        packet[:LENGTH_HEADER_SIZE]
    )[0]

    if key_len not in VALID_KEY_SIZES:
        raise ValueError("Key length không hợp lệ.")

    expected_len = (
        LENGTH_HEADER_SIZE +
        key_len +
        IV_SIZE
    )

    if len(packet) != expected_len:
        raise ValueError("Sai kích thước key packet.")

    key = packet[
        LENGTH_HEADER_SIZE:
        LENGTH_HEADER_SIZE + key_len
    ]

    iv = packet[
        LENGTH_HEADER_SIZE + key_len:
    ]

    return key, iv


# =========================
# DATA CHANNEL
# FORMAT:
# [ciphertext_length:4B][ciphertext]
# =========================

def build_data_packet(
    ciphertext: bytes
) -> bytes:
    """
    Tạo packet cho data channel.
    """

    if not ciphertext:
        raise ValueError("Ciphertext rỗng.")

    header = struct.pack(
        "!I",
        len(ciphertext)
    )

    return header + ciphertext


def parse_data_packet(
    packet: bytes
) -> bytes:
    """
    Parse data packet.
    """

    if len(packet) < LENGTH_HEADER_SIZE:
        raise ValueError("Packet quá ngắn.")

    cipher_len = struct.unpack(
        "!I",
        packet[:LENGTH_HEADER_SIZE]
    )[0]

    ciphertext = packet[
        LENGTH_HEADER_SIZE:
    ]

    if len(ciphertext) != cipher_len:
        raise ValueError(
            "Ciphertext length mismatch."
        )

    return ciphertext


# =========================
# TCP RECEIVE EXACT
# =========================

def recv_exact(
    conn: socket.socket,
    n: int
) -> bytes:
    """
    Nhận đúng n byte từ TCP stream.
    """

    data = b""

    while len(data) < n:

        packet = conn.recv(n - len(data))

        if not packet:
            raise ConnectionError(
                "Kết nối bị đóng giữa chừng."
            )

        data += packet

    return data
