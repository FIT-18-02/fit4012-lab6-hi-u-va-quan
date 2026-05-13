import sys
import os
import pytest
import struct

# Đảm bảo import được từ thư mục gốc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes_socket_utils import (
    build_data_packet,
    build_key_packet,
    encrypt_aes_cbc,
    parse_key_packet,
    parse_length_header,
    pad,
    unpad,
)

def test_pad_unpad_roundtrip():
    """Kiểm tra logic thêm và xóa padding cho nhiều độ dài khác nhau."""
    test_cases = [
        b"hello AES socket",    # 16 bytes (vừa khít 1 block)
        b"DNU",                 # Ngắn hơn 1 block
        b"A" * 31,              # Gần 2 blocks
        b""                     # Dữ liệu rỗng
    ]
    for data in test_cases:
        assert unpad(pad(data)) == data

def test_invalid_padding_raises_error():
    """Kiểm tra xem unpad có bắt được lỗi khi padding bị hỏng không."""
    bad_data = b"Some data" + b"\x05\x05" # Sai giá trị padding
    with pytest.raises(ValueError):
        unpad(bad_data)

def test_aes_cbc_roundtrip():
    """Kiểm tra mã hóa/giải mã với key và IV cố định."""
    plain = b"FIT4012 Lab 6 AES-CBC"
    key_fixed = b"1" * 16
    iv_fixed = b"2" * 16
    key, iv, cipher_bytes = encrypt_aes_cbc(plain, key=key_fixed, iv=iv_fixed)
    
    assert key == key_fixed
    assert iv == iv_fixed
    assert len(cipher_bytes) % 16 == 0

def test_key_packet_roundtrip():
    """Kiểm tra đóng gói và phân tách gói tin chứa Key/IV."""
    key = os.urandom(16)
    iv = os.urandom(16)
    packet = build_key_packet(key, iv)
    parsed_key, parsed_iv = parse_key_packet(packet)
    
    assert parsed_key == key
    assert parsed_iv == iv

def test_data_packet_contains_correct_length():
    """Kiểm tra Header độ dài (4 bytes) trong gói tin dữ liệu."""
    _, _, cipher_bytes = encrypt_aes_cbc(b"FIT4012", key=b"k"*16, iv=b"i"*16)
    packet = build_data_packet(cipher_bytes)
    
    # Parse 4 byte đầu tiên
    length = parse_length_header(packet[:4])
    
    assert length == len(cipher_bytes)
    assert packet[4:] == cipher_bytes

def test_parse_invalid_length_header():
    """Kiểm tra xử lý lỗi khi header không đủ 4 bytes."""
    with pytest.raises(ValueError):
        parse_length_header(b"\x00\x00\x01") # Chỉ có 3 bytes
        #qh
