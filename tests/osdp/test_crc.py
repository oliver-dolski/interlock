"""The OSDP CRC must be CRC-16/AUG-CCITT, proven by its canonical check value.

Docker-free host test (no ``lab`` marker). If this value is wrong the trailer will
never match the lab's frames and byte-identity (OSDP-01) fails, so this is the
cheapest guard that the CRC port is the right algorithm.
"""

from __future__ import annotations

from interlock.osdp.codec import checksum, crc16, crc16_le


def test_crc_aug_ccitt_check_value() -> None:
    """crc16(b"123456789") is 0xE5CC, the CRC-16/AUG-CCITT check value."""
    assert crc16(b"123456789") == 0xE5CC


def test_crc16_le_is_lsb_first() -> None:
    """crc16_le appends the CRC LSB first, matching LibOSDP's trailer order."""
    value = crc16(b"123456789")
    assert crc16_le(b"123456789") == bytes([value & 0xFF, (value >> 8) & 0xFF])
    assert crc16_le(b"123456789") == b"\xcc\xe5"


def test_checksum_is_twos_complement_byte() -> None:
    """The fallback checksum is the one-byte two's complement of the byte sum."""
    assert checksum(b"\x53\x65\x01") == bytes([(-(0x53 + 0x65 + 0x01)) & 0xFF])
