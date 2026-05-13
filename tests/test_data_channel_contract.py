import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from aes_socket_utils import build_data_packet, parse_length_header


def test_data_channel_contract():
    ciphertext = b"x" * 32
    packet = build_data_packet(ciphertext)
#quanhieu
    assert packet[:4] == (32).to_bytes(4, "big")
    assert parse_length_header(packet[:4]) == 32
    assert packet[4:] == ciphertext


def test_empty_ciphertext_should_fail():
    with pytest.raises(ValueError):
        build_data_packet(b"")


def test_bad_length_header_should_fail():
    with pytest.raises(ValueError):
        parse_length_header(b"\x00\x01")
