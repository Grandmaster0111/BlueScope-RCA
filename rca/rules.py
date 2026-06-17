"""
Rule-based failure detection over a decoded HCI packet stream.

Scans for known failure signatures across three layers:
  - HCI:    non-zero status in Connection Complete, Disconnection Complete,
            Command Complete/Status, Encryption Change, and LE Meta sub-events.
  - L2CAP:  non-zero result in Connection Response / Configuration Response,
            Connection Parameter Update rejections, and Command Reject.
  - SMP:    Pairing Failed PDUs.

Each hit becomes a FailureEvent carrying enough structured context (layer,
code, handle, opcode/PSM names where known) to drive both RAG retrieval and
the LLM explanation prompt.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from ingest.btsnoop import RawPacket

# A few opcode names worth surfacing in Command Complete/Status failures.
# Not exhaustive -- unknown opcodes fall back to their hex value.
_HCI_OPCODES = {
    0x0405: "Create Connection", 0x0406: "Disconnect",
    0x0409: "Accept Connection Request", 0x0419: "Remote Name Request",
    0x041b: "Read Remote Supported Features", 0x041d: "Read Remote Extended Features",
    0x041f: "Read Remote Version Information",
    0x0413: "Set Connection Encryption", 0x0411: "Authentication Requested",
    0x200d: "LE Create Connection", 0x2013: "LE Connection Update",
    0x2016: "LE Read Remote Features", 0x201a: "LE Start Encryption",
    0x2043: "LE Extended Create Connection",
}

_PSM_NAMES = {
    0x0001: "SDP", 0x0003: "RFCOMM", 0x000F: "BNEP",
    0x0011: "HID (Control)", 0x0013: "HID (Interrupt)",
    0x0017: "AVCTP/AVRCP", 0x0019: "AVDTP/A2DP", 0x001B: "AVCTP Browsing",
    0x001D: "UDI",
}

# Disconnection reasons that represent a normal, intentional teardown --
# not worth surfacing as a "failure" to root-cause.
_BENIGN_DISCONNECT_REASONS = {0x13, 0x15, 0x16}


@dataclass
class FailureEvent:
    seq: int
    ts_us: int
    layer: str          # "HCI" | "L2CAP" | "SMP"
    kind: str            # short label, e.g. "Disconnection", "Connect Rejected"
    code_hex: str         # e.g. "0x08"
    handle: Optional[int] = None
    context: dict = field(default_factory=dict)

    @property
    def summary(self) -> str:
        ctx = ""
        if self.context:
            ctx = " (" + ", ".join(f"{k}={v}" for k, v in self.context.items()) + ")"
        handle_str = f" handle={self.handle}" if self.handle is not None else ""
        return f"[{self.layer}] {self.kind} {self.code_hex}{handle_str}{ctx} @ t={self.ts_us / 1e6:.3f}s (pkt #{self.seq})"


def find_failures(packets: list[RawPacket]) -> list[FailureEvent]:
    failures: list[FailureEvent] = []
    l2cap_pending: dict[tuple, int] = {}   # (handle, scid) -> psm

    for p in packets:
        if p.type == "EVT":
            failures.extend(_check_event(p))
        elif p.type == "ACL":
            failures.extend(_check_acl(p, l2cap_pending))

    return failures


def _check_event(p: RawPacket) -> list[FailureEvent]:
    body = p.payload
    if len(body) < 2:
        return []
    code, plen = body[0], body[1]
    params = body[2:2 + plen]
    out: list[FailureEvent] = []

    if code == 0x05 and len(params) >= 4:          # Disconnection Complete
        status = params[0]
        handle = struct.unpack_from("<H", params, 1)[0]
        reason = params[3]
        if status != 0:
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", "Disconnection Complete Failed",
                                     f"0x{status:02X}", handle))
        elif reason not in _BENIGN_DISCONNECT_REASONS:
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", "Disconnection",
                                     f"0x{reason:02X}", handle))

    elif code == 0x03 and len(params) >= 9:        # Connection Complete (BR/EDR)
        status = params[0]
        if status != 0:
            handle = struct.unpack_from("<H", params, 1)[0]
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", "Connection Complete Failed",
                                     f"0x{status:02X}", handle))

    elif code == 0x0e and len(params) >= 4:        # Command Complete
        opcode = struct.unpack_from("<H", params, 1)[0]
        status = params[3]
        if status != 0:
            name = _HCI_OPCODES.get(opcode, f"opcode 0x{opcode:04X}")
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", f"Command Complete Failed [{name}]",
                                     f"0x{status:02X}", None))

    elif code == 0x0f and len(params) >= 4:        # Command Status
        status = params[0]
        opcode = struct.unpack_from("<H", params, 2)[0]
        if status != 0:
            name = _HCI_OPCODES.get(opcode, f"opcode 0x{opcode:04X}")
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", f"Command Status Failed [{name}]",
                                     f"0x{status:02X}", None))

    elif code == 0x08 and len(params) >= 3:        # Encryption Change
        status = params[0]
        if status != 0:
            handle = struct.unpack_from("<H", params, 1)[0]
            out.append(FailureEvent(p.seq, p.ts_us, "HCI", "Encryption Change Failed",
                                     f"0x{status:02X}", handle))

    elif code == 0x3e and params:                  # LE Meta
        sub = params[0]
        sparams = params[1:]
        if sub == 0x01 and len(sparams) >= 4:      # LE Connection Complete
            status = sparams[0]
            if status != 0:
                handle = struct.unpack_from("<H", sparams, 1)[0]
                out.append(FailureEvent(p.seq, p.ts_us, "HCI", "LE Connection Complete Failed",
                                         f"0x{status:02X}", handle))
        elif sub == 0x0a and len(sparams) >= 4:    # LE Enhanced Connection Complete
            status = sparams[0]
            if status != 0:
                handle = struct.unpack_from("<H", sparams, 1)[0]
                out.append(FailureEvent(p.seq, p.ts_us, "HCI", "LE Enhanced Connection Complete Failed",
                                         f"0x{status:02X}", handle))

    return out


def _check_acl(p: RawPacket, pending: dict) -> list[FailureEvent]:
    body = p.payload
    if len(body) < 4:
        return []
    word = struct.unpack_from("<H", body, 0)[0]
    handle = word & 0x0FFF
    pb = (word >> 12) & 0x3
    if pb == 0b01:
        return []  # continuation fragment, no L2CAP header present

    dlen = struct.unpack_from("<H", body, 2)[0]
    l2 = body[4:4 + dlen]
    if len(l2) < 4:
        return []
    l2len = struct.unpack_from("<H", l2, 0)[0]
    cid = struct.unpack_from("<H", l2, 2)[0]
    sig = l2[4:4 + l2len]

    if cid in (0x0001, 0x0005):
        return _parse_l2cap_sig(p, handle, sig, pending)
    if cid in (0x0006, 0x0007):
        return _parse_smp(p, handle, sig)
    return []


def _parse_l2cap_sig(p: RawPacket, handle: int, data: bytes, pending: dict) -> list[FailureEvent]:
    out: list[FailureEvent] = []
    offset = 0
    while offset + 4 <= len(data):
        code = data[offset]
        sig_len = struct.unpack_from("<H", data, offset + 2)[0]
        pl = data[offset + 4: offset + 4 + sig_len]
        offset += 4 + sig_len

        if code == 0x01 and len(pl) >= 2:          # Command Reject
            reason = struct.unpack_from("<H", pl, 0)[0]
            out.append(FailureEvent(p.seq, p.ts_us, "L2CAP", "Command Reject",
                                     f"0x{reason:04X}", handle))

        elif code == 0x02 and len(pl) >= 4:         # Connection Request
            psm = struct.unpack_from("<H", pl, 0)[0]
            scid = struct.unpack_from("<H", pl, 2)[0]
            pending[(handle, scid)] = psm

        elif code == 0x03 and len(pl) >= 8:         # Connection Response
            scid = struct.unpack_from("<H", pl, 2)[0]
            result = struct.unpack_from("<H", pl, 4)[0]
            psm = pending.pop((handle, scid), None)
            if result != 0:
                ctx = {"psm": _PSM_NAMES.get(psm, f"0x{psm:04X}")} if psm is not None else {}
                out.append(FailureEvent(p.seq, p.ts_us, "L2CAP", "Connect Rejected",
                                         f"0x{result:04X}", handle, ctx))

        elif code == 0x05 and len(pl) >= 6:         # Configuration Response
            result = struct.unpack_from("<H", pl, 4)[0]
            if result != 0:
                out.append(FailureEvent(p.seq, p.ts_us, "L2CAP", "Configure Rejected",
                                         f"0x{result:04X}", handle))

        elif code == 0x13 and len(pl) >= 2:         # Connection Parameter Update Response
            result = struct.unpack_from("<H", pl, 0)[0]
            if result != 0:
                out.append(FailureEvent(p.seq, p.ts_us, "L2CAP", "Connection Parameter Update Rejected",
                                         f"0x{result:04X}", handle))

    return out


def _parse_smp(p: RawPacket, handle: int, data: bytes) -> list[FailureEvent]:
    if len(data) >= 2 and data[0] == 0x05:          # Pairing Failed
        reason = data[1]
        return [FailureEvent(p.seq, p.ts_us, "SMP", "Pairing Failed", f"0x{reason:02X}", handle)]
    return []
