import sys
import os
import pytest

# Đảm bảo import được aes_socket_utils từ thư mục gốc
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes_socket_utils import build_key_packet, parse_key_packet, VALID_KEY_SIZES

def test_key_channel_contract_128bit():
    """Kiểm tra cấu trúc gói tin khóa 128-bit (16 bytes)."""
    key = b"k" * 16
    iv = b"i" * 16
    packet = build_key_packet(key, iv)
#quanhieu
    # Kiểm tra header độ dài key (4 bytes đầu tiên)
    # 16 bytes = \x00\x00\x00\x10 trong Big-endian
    assert packet[:4] == (16).to_bytes(4, "big")
    
    # Kiểm tra phân tách gói tin
    parsed_key, parsed_iv = parse_key_packet(packet)
    assert parsed_key == key
    assert parsed_iv == iv
    assert len(parsed_iv) == 16

def test_key_channel_contract_256bit():
    """Kiểm tra cấu trúc gói tin khóa 256-bit (32 bytes)."""
    key = b"k" * 32
    iv = b"i" * 16
    packet = build_key_packet(key, iv)

    assert packet[:4] == (32).to_bytes(4, "big")
    parsed_key, parsed_iv = parse_key_packet(packet)
    assert len(parsed_key) == 32
    assert parsed_key == key

def test_invalid_key_size_should_fail():
    """Hệ thống phải từ chối các kích thước khóa không tiêu chuẩn."""
    invalid_key = b"bad_key" # Không phải 16 hay 32 bytes
    iv = b"i" * 16
    with pytest.raises(ValueError):
        build_key_packet(invalid_key, iv)

def test_corrupted_key_packet_should_fail():
    """Kiểm tra việc phát hiện gói tin khóa bị thiếu dữ liệu."""
    key = b"k" * 16
    iv = b"i" * 16
    packet = build_key_packet(key, iv)
    
    # Cắt bớt gói tin để làm hỏng cấu trúc
    corrupted_packet = packet[:-5] 
    with pytest.raises(ValueError):
        parse_key_packet(corrupted_packet)
