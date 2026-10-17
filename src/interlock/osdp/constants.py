"""Verified OSDP wire constants, ported byte-for-byte from LibOSDP v3.0.8.

Every value here is lifted from the LibOSDP source that the Phase 2 lab runs, so
a codec built against these constants round-trips the lab's real frames exactly.
Each constant carries a provenance comment naming the source file at v3.0.8. The
SCBK_D value is the OSDP specification default Secure Channel Base Key (an
artifact of the spec), not a vendor production key (SAFE-03).
"""

from __future__ import annotations

# Framing markers. VERIFIED: src/osdp_phy.c @ v3.0.8 (OSDP_PKT_MARK, OSDP_PKT_SOM).
SOM = 0x53
MARK = 0xFF

# Control byte bit masks. VERIFIED: src/osdp_phy.c @ v3.0.8.
PKT_CONTROL_SQN = 0x03  # bits 0-1: sequence number (wraps 1->2->3->1, skips 0)
PKT_CONTROL_CRC = 0x04  # bit 2: 1 = CRC-16 trailer, 0 = one-byte checksum
PKT_CONTROL_SCB = 0x08  # bit 3: a Secure Control Block is present in data[0..]

# Address direction flag. VERIFIED: src/osdp_phy.c @ v3.0.8 (bit 0x80 of pd_address
# marks a reply, PD->CP). It lives on the address byte, never on control.
ADDR_REPLY_FLAG = 0x80

# Command codes (CP->PD). VERIFIED: src/osdp_common.h @ v3.0.8.
CMD_POLL = 0x60
CMD_ID = 0x61
CMD_CAP = 0x62
CMD_LSTAT = 0x64
CMD_ISTAT = 0x65
CMD_OSTAT = 0x66
CMD_RSTAT = 0x67
CMD_OUT = 0x68
CMD_LED = 0x69
CMD_BUZ = 0x6A
CMD_TEXT = 0x6B
CMD_RMODE = 0x6C
CMD_TDSET = 0x6D
CMD_COMSET = 0x6E
CMD_BIOREAD = 0x73
CMD_BIOMATCH = 0x74
CMD_KEYSET = 0x75
CMD_CHLNG = 0x76
CMD_SCRYPT = 0x77
CMD_ACURXSIZE = 0x7B
CMD_FILETRANSFER = 0x7C
CMD_MFG = 0x80
CMD_XWR = 0xA1
CMD_ABORT = 0xA2
CMD_PIVDATA = 0xA3
CMD_GENAUTH = 0xA4
CMD_CRAUTH = 0xA5
CMD_KEEPACTIVE = 0xA7

# Reply codes (PD->CP). VERIFIED: src/osdp_common.h @ v3.0.8. Note CMD_CHLNG and
# REPLY_CCRYPT share byte 0x76; only the address direction bit tells them apart.
REPLY_ACK = 0x40
REPLY_NAK = 0x41
REPLY_PDID = 0x45
REPLY_PDCAP = 0x46
REPLY_LSTATR = 0x48
REPLY_ISTATR = 0x49
REPLY_OSTATR = 0x4A
REPLY_RSTATR = 0x4B
REPLY_RAW = 0x50
REPLY_FMT = 0x51
REPLY_KEYPAD = 0x53
REPLY_COM = 0x54
REPLY_BIOREADR = 0x57
REPLY_BIOMATCHR = 0x58
REPLY_CCRYPT = 0x76
REPLY_RMAC_I = 0x78
REPLY_BUSY = 0x79
REPLY_FTSTAT = 0x7A
REPLY_PIVDATAR = 0x80
REPLY_GENAUTHR = 0x81
REPLY_CRAUTHR = 0x82
REPLY_MFGSTATR = 0x83
REPLY_MFGERRR = 0x84
REPLY_MFGREP = 0x90
REPLY_XRD = 0xB1

# Name tables for readable decoding; the raw byte stays authoritative on the frame.
# VERIFIED: src/osdp_common.h @ v3.0.8.
COMMAND_CODES: dict[int, str] = {
    CMD_POLL: "CMD_POLL",
    CMD_ID: "CMD_ID",
    CMD_CAP: "CMD_CAP",
    CMD_LSTAT: "CMD_LSTAT",
    CMD_ISTAT: "CMD_ISTAT",
    CMD_OSTAT: "CMD_OSTAT",
    CMD_RSTAT: "CMD_RSTAT",
    CMD_OUT: "CMD_OUT",
    CMD_LED: "CMD_LED",
    CMD_BUZ: "CMD_BUZ",
    CMD_TEXT: "CMD_TEXT",
    CMD_RMODE: "CMD_RMODE",
    CMD_TDSET: "CMD_TDSET",
    CMD_COMSET: "CMD_COMSET",
    CMD_BIOREAD: "CMD_BIOREAD",
    CMD_BIOMATCH: "CMD_BIOMATCH",
    CMD_KEYSET: "CMD_KEYSET",
    CMD_CHLNG: "CMD_CHLNG",
    CMD_SCRYPT: "CMD_SCRYPT",
    CMD_ACURXSIZE: "CMD_ACURXSIZE",
    CMD_FILETRANSFER: "CMD_FILETRANSFER",
    CMD_MFG: "CMD_MFG",
    CMD_XWR: "CMD_XWR",
    CMD_ABORT: "CMD_ABORT",
    CMD_PIVDATA: "CMD_PIVDATA",
    CMD_GENAUTH: "CMD_GENAUTH",
    CMD_CRAUTH: "CMD_CRAUTH",
    CMD_KEEPACTIVE: "CMD_KEEPACTIVE",
}

REPLY_CODES: dict[int, str] = {
    REPLY_ACK: "REPLY_ACK",
    REPLY_NAK: "REPLY_NAK",
    REPLY_PDID: "REPLY_PDID",
    REPLY_PDCAP: "REPLY_PDCAP",
    REPLY_LSTATR: "REPLY_LSTATR",
    REPLY_ISTATR: "REPLY_ISTATR",
    REPLY_OSTATR: "REPLY_OSTATR",
    REPLY_RSTATR: "REPLY_RSTATR",
    REPLY_RAW: "REPLY_RAW",
    REPLY_FMT: "REPLY_FMT",
    REPLY_KEYPAD: "REPLY_KEYPAD",
    REPLY_COM: "REPLY_COM",
    REPLY_BIOREADR: "REPLY_BIOREADR",
    REPLY_BIOMATCHR: "REPLY_BIOMATCHR",
    REPLY_CCRYPT: "REPLY_CCRYPT",
    REPLY_RMAC_I: "REPLY_RMAC_I",
    REPLY_BUSY: "REPLY_BUSY",
    REPLY_FTSTAT: "REPLY_FTSTAT",
    REPLY_PIVDATAR: "REPLY_PIVDATAR",
    REPLY_GENAUTHR: "REPLY_GENAUTHR",
    REPLY_CRAUTHR: "REPLY_CRAUTHR",
    REPLY_MFGSTATR: "REPLY_MFGSTATR",
    REPLY_MFGERRR: "REPLY_MFGERRR",
    REPLY_MFGREP: "REPLY_MFGREP",
    REPLY_XRD: "REPLY_XRD",
}

# Secure Channel Status codes carried in SCB data[1]. VERIFIED: src/osdp_phy.c @ v3.0.8.
# Present here for the Secure Channel detector in a later Phase 3 plan (OSDP-03).
SCS_11 = 0x11  # CP->PD CMD_CHLNG
SCS_12 = 0x12  # PD->CP REPLY_CCRYPT
SCS_13 = 0x13  # CP->PD CMD_SCRYPT
SCS_14 = 0x14  # PD->CP REPLY_RMAC_I
SCS_15 = 0x15  # CP->PD MAC, no encryption
SCS_16 = 0x16  # PD->CP MAC, no encryption
SCS_17 = 0x17  # CP->PD MAC and encryption
SCS_18 = 0x18  # PD->CP MAC and encryption

# OSDP specification default Secure Channel Base Key (SCBK-D), bytes 0x30..0x3F. This is the
# spec default documented in LibOSDP's source (src/osdp_sc.c), not a vendor production key
# (SAFE-03). Copied verbatim from lab/osdp/scenarios.py so the codec and the future attack
# module agree on the exact bytes.
SCBK_D = bytes(range(0x30, 0x40))
