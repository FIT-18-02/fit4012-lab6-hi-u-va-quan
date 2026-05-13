#!/usr/bin/env python3
import os
import struct
from typing import Tuple
from Crypto.Cipher import AES

# ==================================================
# Cấu hình hệ thống
# ==================================================
BLOCK_SIZE = 16
LENGTH_HEADER_SIZE = 4
KEY_LENGTH_HEADER_SIZE = 4
IV_SIZE = 16
VALID_KEY_SIZES = (16, 32)

def pad(data: bytes) -> bytes:
    """Thêm padding PKCS#7 để dữ liệu khớp với kích thước block của AES."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    """Xóa và kiểm tra tính hợp lệ của padding PKCS#7."""
    if not data:
        raise ValueError("Dữ liệu rỗng, không thể bỏ padding.")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding không hợp lệ: Giá trị byte padding nằm ngoài phạm vi.")

    expected = bytes([pad_len]) * pad_len
    if data[-pad_len:] != expected:
        raise ValueError("Padding PKCS#7 không khớp hoặc bị hỏng.")

    return data[:-pad_len]

def generate_key_iv(key_size: int = 16) -> Tuple[bytes, bytes]:
    """Tạo ngẫu nhiên AES Key và IV an toàn về mặt mật mã."""
    if key_size not in VALID_KEY_SIZES:
        raise ValueError(f"AES key size không hỗ trợ: {key_size}. Chỉ dùng 16 hoặc 32 bytes.")
    return os.urandom(key_size), os.urandom(IV_SIZE)

def validate_key_iv(key: bytes, iv: bytes) -> None:
    """Kiểm tra độ dài chuẩn của Key và IV."""
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(f"AES key phải dài 16 hoặc 32 byte (đang nhận: {len(key)}).")
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV phải dài đúng 16 byte (đang nhận: {len(iv)}).")

# ==================================================
# Các hàm Mã hóa / Giải mã chính
# ==================================================

def encrypt_aes_cbc(
    plain: bytes,
    key: bytes = None,
    iv: bytes = None,
    key_size: int = 16,
) -> Tuple[bytes, bytes, bytes]:
    """Mã hóa bản tin với AES-CBC và PKCS#7 padding."""
    if key is None or iv is None:
        key, iv = generate_key_iv(key_size)

    validate_key_iv(key, iv)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plain))
    return key, iv, ciphertext

def decrypt_aes_cbc(key: bytes, iv: bytes, cipher_bytes: bytes) -> bytes:
    """Giải mã AES-CBC và gỡ bỏ padding."""
    validate_key_iv(key, iv)

    if not cipher_bytes:
        raise ValueError("Ciphertext không được rỗng.")
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Độ dài Ciphertext không phải bội số của 16 (Sai block).")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(cipher_bytes)
    return unpad(decrypted_data)

# ==================================================
# Các hàm hỗ trợ Socket (Đóng gói & Nhận tin)
# ==================================================

def build_key_packet(key: bytes, iv: bytes) -> bytes:
    """Đóng gói kênh khóa: [Độ dài Key(4B)] + [Key] + [IV(16B)]."""
    validate_key_iv(key, iv)
    # '!I': Big-endian, 4 byte unsigned int
    return struct.pack("!I", len(key)) + key + iv

def parse_key_packet(packet: bytes) -> Tuple[bytes, bytes]:
    """Phân tách gói tin từ kênh khóa."""
    if len(packet) < KEY_LENGTH_HEADER_SIZE + IV_SIZE:
        raise ValueError("Gói tin khóa quá ngắn.")

    key_len = struct.unpack("!I", packet[:KEY_LENGTH_HEADER_SIZE])[0]
    
    if key_len not in VALID_KEY_SIZES:
        raise ValueError(f"Độ dài key {key_len} không hợp lệ.")

    expected_len = KEY_LENGTH_HEADER_SIZE + key_len + IV_SIZE
    if len(packet) != expected_len:
        raise ValueError(f"Độ dài gói ({len(packet)}) không khớp với Header ({expected_len}).")

    key = packet[KEY_LENGTH_HEADER_SIZE : KEY_LENGTH_HEADER_SIZE + key_len]
    iv = packet[KEY_LENGTH_HEADER_SIZE + key_len :]
    return key, iv

def build_data_packet(cipher_bytes: bytes) -> bytes:
    """Đóng gói kênh dữ liệu: [Độ dài Ciphertext(4B)] + [Ciphertext]."""
    if not cipher_bytes:
        raise ValueError("Ciphertext gửi đi không được rỗng.")
    return struct.pack("!I", len(cipher_bytes)) + cipher_bytes

def parse_length_header(header: bytes) -> int:
    """Đọc 4 byte header để lấy độ dài phần dữ liệu phía sau."""
    if len(header) != LENGTH_HEADER_SIZE:
        raise ValueError("Header độ dài phải đủ 4 byte.")
    return struct.unpack("!I", header)[0]

def recv_exact(conn, n: int) -> bytes:
    """Đảm bảo nhận đúng và đủ n bytes từ TCP stream."""
    chunks = []
    received = 0
    while received < n:
        try:
            chunk = conn.recv(min(n - received, 4096))
            if not chunk:
                raise ConnectionError("Kết nối bị ngắt đột ngột trước khi nhận đủ dữ liệu.")
            chunks.append(chunk)
            received += len(chunk)
        except Exception as e:
            raise ConnectionError(f"Lỗi khi đang nhận dữ liệu: {e}")
    return b"".join(chunks)
