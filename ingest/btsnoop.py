"""
Standalone .btsnoop file parser.

Decodes the raw HCI packet stream out of a btsnoop capture file, supporting
both the Linux "Monitor" datalink (2001, produced by btmon -w) and the
standard HCI UART/H4 datalink (1002, produced by tshark/Wireshark on
macOS/Windows). This is intentionally independent of the bluescope repo's
decoder -- BlueScope-RCA only needs enough structure to find HCI events,
commands and ACL signaling payloads for failure analysis, not full OTA
classification.
"""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BTSNOOP_MAGIC = b"btsnoop\x00"
FILE_HDR_SIZE = 16
REC_HDR_SIZE = 24

PKT_TYPES = {0x01: "CMD", 0x02: "ACL", 0x03: "SCO", 0x04: "EVT", 0x05: "ISO"}

# Linux Monitor (datalink 2001) opcode -> (hci_indicator_byte, direction)
_MONITOR_OPCODE_MAP = {
    2: (0x01, "host_to_controller"),   # HCI Command
    3: (0x04, "controller_to_host"),   # HCI Event
    4: (0x02, "host_to_controller"),   # ACL TX
    5: (0x02, "controller_to_host"),   # ACL RX
    6: (0x03, "host_to_controller"),   # SCO TX
    7: (0x03, "controller_to_host"),   # SCO RX
    18: (0x05, "host_to_controller"),  # ISO TX
    19: (0x05, "controller_to_host"),  # ISO RX
}


@dataclass
class RawPacket:
    seq: int
    ts_us: int          # microseconds relative to first packet
    direction: str       # "host_to_controller" | "controller_to_host"
    type: str            # CMD / EVT / ACL / SCO / ISO
    payload: bytes        # raw HCI body, WITHOUT the H4 type indicator byte


def parse_btsnoop(path: str) -> list[RawPacket]:
    data = Path(path).read_bytes()
    if len(data) < FILE_HDR_SIZE or data[:8] != BTSNOOP_MAGIC:
        raise ValueError(f"{path}: not a valid btsnoop file (bad magic)")

    datalink = struct.unpack_from(">I", data, 12)[0]
    is_monitor = datalink == 2001

    packets: list[RawPacket] = []
    offset = FILE_HDR_SIZE
    seq = 0
    t0_us: Optional[int] = None

    while offset + REC_HDR_SIZE <= len(data):
        incl_len = struct.unpack_from(">I", data, offset + 4)[0]
        flags = struct.unpack_from(">I", data, offset + 8)[0]
        ts_us = struct.unpack_from(">q", data, offset + 16)[0]
        offset += REC_HDR_SIZE

        raw = data[offset:offset + incl_len]
        offset += incl_len
        if len(raw) < incl_len:
            break  # truncated trailing record

        if is_monitor:
            opcode = flags & 0xFFFF
            mapping = _MONITOR_OPCODE_MAP.get(opcode)
            if mapping is None:
                continue  # INFO/MGMT record, not an HCI packet
            indicator, direction = mapping
            payload = raw
        else:
            if not raw:
                continue
            indicator = raw[0]
            direction = "host_to_controller" if (flags & 1) == 0 else "controller_to_host"
            payload = raw[1:]

        typ = PKT_TYPES.get(indicator)
        if typ is None:
            continue

        seq += 1
        if t0_us is None:
            t0_us = ts_us
        packets.append(RawPacket(
            seq=seq,
            ts_us=ts_us - t0_us,
            direction=direction,
            type=typ,
            payload=payload,
        ))

    return packets
