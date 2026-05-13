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
    PKCS#7 padding.
    """

    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding.
    """

    if not data:
        raise ValueError("Empty data")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-pad_len]


# =========================
# KEY + IV
# =========================

def generate_aes_key(size: int = 32) -> bytes:
    """
    Generate AES key.
    """

    if size not in VALID_KEY_SIZES:
        raise ValueError(
            "AES key must be 16 or 32 bytes"
        )

    return get_random_bytes(size)


def generate_iv() -> bytes:
    """
    Generate 16-byte IV.
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
    AES-CBC encryption.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("Invalid AES key size")

    if len(iv) != IV_SIZE:
        raise ValueError("IV must be 16 bytes")

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    padded = pad(plaintext)

    return cipher.encrypt(padded)


def decrypt_aes_cbc(
    ciphertext: bytes,
    key: bytes,
    iv: bytes
) -> bytes:
    """
    AES-CBC decryption.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("Invalid AES key size")

    if len(iv) != IV_SIZE:
        raise ValueError("IV must be 16 bytes")

    if not ciphertext:
        raise ValueError("Ciphertext empty")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            "Ciphertext must be multiple of 16 bytes"
        )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    padded_plain = cipher.decrypt(ciphertext)

    return unpad(padded_plain)


# =========================
# LENGTH HEADER
# =========================

def build_length_header(length: int) -> bytes:
    """
    Build 4-byte network-order header.
    """

    return struct.pack("!I", length)


def parse_length_header(header: bytes) -> int:
    """
    Parse 4-byte length header.
    """

    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError(
            "Length header must be 4 bytes"
        )

    return struct.unpack("!I", header)[0]


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
    Build key packet.
    """

    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(
            "Invalid AES key size"
        )

    if len(iv) != IV_SIZE:
        raise ValueError(
            "IV must be 16 bytes"
        )

    header = build_length_header(len(key))

    return header + key + iv


def parse_key_packet(
    packet: bytes
) -> Tuple[bytes, bytes]:
    """
    Parse key packet.
    """

    if len(packet) < LENGTH_HEADER_SIZE:
        raise ValueError(
            "Packet too short"
        )

    key_len = parse_length_header(
        packet[:LENGTH_HEADER_SIZE]
    )

    if key_len not in VALID_KEY_SIZES:
        raise ValueError(
            "Invalid key length"
        )

    expected_len = (
        LENGTH_HEADER_SIZE +
        key_len +
        IV_SIZE
    )

    if len(packet) != expected_len:
        raise ValueError(
            "Invalid key packet size"
        )

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
    Build data packet.
    """

    if not ciphertext:
        raise ValueError(
            "Ciphertext empty"
        )

    header = build_length_header(
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
        raise ValueError(
            "Packet too short"
        )

    cipher_len = parse_length_header(
        packet[:LENGTH_HEADER_SIZE]
    )

    ciphertext = packet[
        LENGTH_HEADER_SIZE:
    ]

    if len(ciphertext) != cipher_len:
        raise ValueError(
            "Ciphertext length mismatch"
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
    Receive exactly n bytes.
    """

    data = b""

    while len(data) < n:

        packet = conn.recv(
            n - len(data)
        )

        if not packet:
            raise ConnectionError(
                "Socket connection closed"
            )

        data += packet

    return data
