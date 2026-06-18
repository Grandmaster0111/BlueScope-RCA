"""
Reusable low-level builder for synthetic .btsnoop captures (standard H4
datalink). Shared by the demo capture generator and the benchmark dataset
so both construct HCI/L2CAP/SMP packets the same way.
"""

import struct

BTSNOOP_MAGIC = b"btsnoop\x00"


class BtsnoopBuilder:
    def __init__(self, datalink: int = 1002):
        self._records = [BTSNOOP_MAGIC + struct.pack(">II", 1, datalink)]
        self._t = 0

    def _record(self, pkt_type: int, body: bytes, host_to_controller: bool) -> None:
        self._t += 2000
        raw = bytes([pkt_type]) + body
        flags = 0 if host_to_controller else 1
        hdr = struct.pack(">IIIIq", len(raw), len(raw), flags, 0, self._t)
        self._records.append(hdr + raw)

    def cmd(self, opcode: int, params: bytes = b"") -> None:
        self._record(0x01, struct.pack("<HB", opcode, len(params)) + params, True)

    def evt(self, code: int, params: bytes = b"") -> None:
        self._record(0x04, struct.pack("<BB", code, len(params)) + params, False)

    def acl(self, handle: int, l2cap_payload: bytes, host_to_controller: bool, pb: int = 0b00) -> None:
        flags_word = (handle & 0x0FFF) | (pb << 12)
        body = struct.pack("<HH", flags_word, len(l2cap_payload)) + l2cap_payload
        self._record(0x02, body, host_to_controller)

    @staticmethod
    def l2cap_sig(cid: int, sig_code: int, ident: int, payload: bytes) -> bytes:
        sig = bytes([sig_code, ident]) + struct.pack("<H", len(payload)) + payload
        return struct.pack("<HH", len(sig), cid) + sig

    def to_bytes(self) -> bytes:
        return b"".join(self._records)
