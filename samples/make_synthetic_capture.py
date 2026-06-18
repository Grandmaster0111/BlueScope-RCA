"""
Generates a synthetic .btsnoop file containing a handful of deliberate
failure scenarios, used to validate the rule engine and the end-to-end
RCA pipeline without needing real hardware.
"""

import sys
from pathlib import Path

from samples.btsnoop_builder import BtsnoopBuilder


def build() -> bytes:
    b = BtsnoopBuilder()

    # --- Scenario 1: BR/EDR Page Timeout -----------------------------
    addr = bytes.fromhex("c250e8bbc150")  # reversed BD_ADDR bytes
    b.cmd(0x0405, addr + b"\x18\x00\x01\x00")                              # Create Connection
    b.evt(0x0f, bytes([0x00, 0x01]) + (0x0405).to_bytes(2, "little"))      # Command Status: pending
    b.evt(0x03, bytes([0x04]) + (0x0000).to_bytes(2, "little") + addr + b"\x01\x00\x01")  # Connection Complete: status=0x04 Page Timeout

    # --- Scenario 2: successful LE connection, then Connection Timeout disconnect
    le_addr = bytes.fromhex("33221100bead")
    b.cmd(0x200d, b"\x00" * 25)                                             # LE Create Connection
    b.evt(0x3e, bytes([0x01, 0x00]) + (0x0042).to_bytes(2, "little") + b"\x00" + le_addr + b"\x28\x00\x00\x00\xd0\x07\x00")
    b.evt(0x05, bytes([0x00]) + (0x0042).to_bytes(2, "little") + bytes([0x08]))  # Disconnection: status=0, reason=0x08 Connection Timeout

    # --- Scenario 3: L2CAP channel rejected (PSM not supported, A2DP) ---
    handle3 = 0x0043
    b.acl(handle3, b.l2cap_sig(0x0001, 0x02, 1, (0x0019).to_bytes(2, "little") + (0x0040).to_bytes(2, "little")), True)   # Connect Req PSM=A2DP
    b.acl(handle3, b.l2cap_sig(0x0001, 0x03, 1, (0x0000).to_bytes(2, "little") + (0x0040).to_bytes(2, "little") + (0x0002).to_bytes(2, "little") + (0x0000).to_bytes(2, "little")), False)  # Connect Rsp result=0x0002

    # --- Scenario 4: SMP pairing failed (Authentication Requirements) ---
    handle4 = 0x0044
    b.acl(handle4, (2).to_bytes(2, "little") + (0x0006).to_bytes(2, "little") + bytes([0x05, 0x03]), False)  # SMP Pairing Failed reason=0x03

    return b.to_bytes()


if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "synthetic_failures.btsnoop"
    dest.write_bytes(build())
    print(f"wrote {dest} ({dest.stat().st_size} bytes)")
