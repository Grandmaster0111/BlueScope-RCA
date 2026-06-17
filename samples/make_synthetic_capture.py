"""
Generates a synthetic .btsnoop file (standard H4 datalink) containing a
handful of deliberate failure scenarios, used to validate the rule engine
and the end-to-end RCA pipeline without needing real hardware.
"""

import struct
import sys
from pathlib import Path

BTSNOOP_MAGIC = b"btsnoop\x00"


def _file_header(datalink: int = 1002) -> bytes:
    return BTSNOOP_MAGIC + struct.pack(">II", 1, datalink)


def _record(pkt_type: int, body: bytes, host_to_controller: bool, ts_us: int) -> bytes:
    raw = bytes([pkt_type]) + body
    flags = 0 if host_to_controller else 1
    hdr = struct.pack(">IIIIq", len(raw), len(raw), flags, 0, ts_us)
    return hdr + raw


def build() -> bytes:
    out = [_file_header()]
    t = 0

    def cmd(opcode, params=b""):
        nonlocal t
        t += 2000
        return _record(0x01, struct.pack("<HB", opcode, len(params)) + params, True, t)

    def evt(code, params=b""):
        nonlocal t
        t += 2000
        return _record(0x04, struct.pack("<BB", code, len(params)) + params, False, t)

    def acl(handle, l2cap_payload, host_to_controller, pb=0b00):
        nonlocal t
        t += 2000
        flags_word = (handle & 0x0FFF) | (pb << 12)
        body = struct.pack("<HH", flags_word, len(l2cap_payload)) + l2cap_payload
        return _record(0x02, body, host_to_controller, t)

    def l2cap_sig(cid, sig_code, ident, payload):
        sig = bytes([sig_code, ident]) + struct.pack("<H", len(payload)) + payload
        return struct.pack("<HH", len(sig), cid) + sig

    # --- Scenario 1: BR/EDR Page Timeout -----------------------------
    addr = bytes.fromhex("c250e8bbc150")  # reversed BD_ADDR bytes
    out.append(cmd(0x0405, addr + b"\x18\x00\x01\x00"))            # Create Connection
    out.append(evt(0x0f, bytes([0x00, 0x01]) + struct.pack("<H", 0x0405)))  # Command Status: pending
    out.append(evt(0x03, bytes([0x04]) + struct.pack("<H", 0x0000) + addr + b"\x01\x00\x01"))  # Connection Complete: status=0x04 Page Timeout

    # --- Scenario 2: successful LE connection, then Connection Timeout disconnect
    le_addr = bytes.fromhex("33221100bead")
    out.append(cmd(0x200d, b"\x00" * 25))                            # LE Create Connection
    out.append(evt(0x3e, bytes([0x01, 0x00]) + struct.pack("<H", 0x0042) + b"\x00" + le_addr + b"\x28\x00\x00\x00\xd0\x07\x00"))
    out.append(evt(0x05, bytes([0x00]) + struct.pack("<H", 0x0042) + bytes([0x08])))  # Disconnection: status=0, reason=0x08 Connection Timeout

    # --- Scenario 3: L2CAP channel rejected (PSM not supported, A2DP) ---
    handle3 = 0x0043
    out.append(acl(handle3, l2cap_sig(0x0001, 0x02, 1, struct.pack("<HH", 0x0019, 0x0040)), True))   # Connect Req PSM=A2DP
    out.append(acl(handle3, l2cap_sig(0x0001, 0x03, 1, struct.pack("<HHHH", 0x0000, 0x0040, 0x0002, 0x0000)), False))  # Connect Rsp result=0x0002

    # --- Scenario 4: SMP pairing failed (Authentication Requirements) ---
    handle4 = 0x0044
    out.append(acl(handle4, struct.pack("<HH", 2, 0x0006) + bytes([0x05, 0x03]), False))  # SMP Pairing Failed reason=0x03

    return b"".join(out)


if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "synthetic_failures.btsnoop"
    dest.write_bytes(build())
    print(f"wrote {dest} ({dest.stat().st_size} bytes)")
