"""
Labeled benchmark dataset: synthetic failure traces with known ground truth.

Each BenchmarkCase describes one deliberately-injected failure: the exact
packet(s) that produce it, what the rule engine should detect (layer, kind,
code, handle), and a set of root-cause keywords -- drawn from the
hand-written rag/corpus entries -- that a correct plain-English explanation
should mention at least one of. This lets the benchmark score both stages
of the pipeline independently: did the rule engine find the right failure,
and did the LLM explanation land on the right root cause for it.

Cases are intentionally minimal (one triggering packet/exchange each, no
realistic surrounding session) since rca/rules.py is stateless across cases
except for the per-handle L2CAP pending-request map -- each case uses a
unique connection handle so cases never interfere with each other even when
concatenated into a single capture.
"""

from dataclasses import dataclass, field

from samples.btsnoop_builder import BtsnoopBuilder


@dataclass
class BenchmarkCase:
    name: str
    build: callable          # (BtsnoopBuilder, handle: int) -> None
    layer: str
    kind: str
    code_hex: str
    keywords: list[str] = field(default_factory=list)


def _le16(v: int) -> bytes:
    return v.to_bytes(2, "little")


# ── HCI: Connection Complete Failed (BR/EDR) ──────────────────────────

def _conn_complete(status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        addr = bytes.fromhex("c250e8bbc150")
        b.evt(0x03, bytes([status]) + _le16(handle) + addr + b"\x01\x00\x01")
    return fn


# ── HCI: Disconnection (status=0, reason=code) ────────────────────────

def _disconnect(reason: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.evt(0x05, bytes([0x00]) + _le16(handle) + bytes([reason]))
    return fn


# ── HCI: Command Complete Failed ───────────────────────────────────────

def _cmd_complete(opcode: int, status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.evt(0x0e, bytes([0x01]) + _le16(opcode) + bytes([status]))
    return fn


def _cmd_status(opcode: int, status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.evt(0x0f, bytes([status, 0x01]) + _le16(opcode))
    return fn


# ── HCI: Encryption Change Failed ──────────────────────────────────────

def _encryption_change(status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.evt(0x08, bytes([status]) + _le16(handle) + bytes([0x00]))
    return fn


# ── HCI: LE Connection Complete / Enhanced Connection Complete Failed ──

def _le_conn_complete(status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        le_addr = bytes.fromhex("33221100bead")
        b.evt(0x3e, bytes([0x01, status]) + _le16(handle) + b"\x00" + le_addr + b"\x28\x00\x00\x00\xd0\x07\x00")
    return fn


def _le_enhanced_conn_complete(status: int):
    def fn(b: BtsnoopBuilder, handle: int):
        le_addr = bytes.fromhex("33221100bead")
        rand_addr = bytes.fromhex("000000000000")
        b.evt(0x3e, bytes([0x0a, status]) + _le16(handle) + b"\x00" + le_addr + rand_addr +
              b"\x28\x00\x00\x00\xd0\x07\x00\x00")
    return fn


# ── L2CAP: Connect Rejected (with Connect Req carrying the PSM) ───────

def _l2cap_connect_rejected(psm: int, result: int):
    def fn(b: BtsnoopBuilder, handle: int):
        scid = 0x0040
        b.acl(handle, b.l2cap_sig(0x0001, 0x02, 1, _le16(psm) + _le16(scid)), True)
        b.acl(handle, b.l2cap_sig(0x0001, 0x03, 1, _le16(0x0000) + _le16(scid) + _le16(result) + _le16(0x0000)), False)
    return fn


# ── L2CAP: Configuration Response Rejected ─────────────────────────────

def _l2cap_configure_rejected(result: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.acl(handle, b.l2cap_sig(0x0001, 0x05, 1, _le16(0x0040) + _le16(0x0000) + _le16(result)), False)
    return fn


# ── L2CAP: Connection Parameter Update Rejected ────────────────────────

def _l2cap_conn_param_update_rejected(result: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.acl(handle, b.l2cap_sig(0x0005, 0x13, 1, _le16(result)), False)
    return fn


# ── L2CAP: Command Reject ──────────────────────────────────────────────

def _l2cap_command_reject(reason: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.acl(handle, b.l2cap_sig(0x0001, 0x01, 1, _le16(reason) + b"\x00\x00"), False)
    return fn


# ── SMP: Pairing Failed ─────────────────────────────────────────────────

def _smp_pairing_failed(reason: int):
    def fn(b: BtsnoopBuilder, handle: int):
        b.acl(handle, _le16(2) + _le16(0x0006) + bytes([0x05, reason]), False)
    return fn


CASES: list[BenchmarkCase] = [
    # --- HCI Connection Complete Failed ---
    BenchmarkCase("hci_conn_page_timeout", _conn_complete(0x04), "HCI", "Connection Complete Failed", "0x04",
                  ["out of range", "page", "not respond", "powered off"]),
    BenchmarkCase("hci_conn_limited_resources", _conn_complete(0x0D), "HCI", "Connection Complete Failed", "0x0D",
                  ["resource", "memory", "full"]),
    BenchmarkCase("hci_conn_security_block", _conn_complete(0x0E), "HCI", "Connection Complete Failed", "0x0E",
                  ["security", "encrypt", "authent", "bond"]),
    BenchmarkCase("hci_conn_unacceptable_bdaddr", _conn_complete(0x0F), "HCI", "Connection Complete Failed", "0x0F",
                  ["address", "allow list", "filter", "bd_addr"]),
    BenchmarkCase("hci_conn_accept_timeout", _conn_complete(0x10), "HCI", "Connection Complete Failed", "0x10",
                  ["timeout", "accept", "stopped responding"]),

    # --- HCI Disconnection (reason codes) ---
    BenchmarkCase("hci_disc_connection_timeout", _disconnect(0x08), "HCI", "Disconnection", "0x08",
                  ["range", "interference", "crash", "supervision", "lost power"]),
    BenchmarkCase("hci_disc_low_resources", _disconnect(0x14), "HCI", "Disconnection", "0x14",
                  ["resource", "memory", "low"]),
    BenchmarkCase("hci_disc_unspecified", _disconnect(0x1F), "HCI", "Disconnection", "0x1F",
                  ["unspecified", "internal", "not otherwise classified", "catch-all"]),
    BenchmarkCase("hci_disc_mic_failure", _disconnect(0x3D), "HCI", "Disconnection", "0x3D",
                  ["mic", "integrity", "tamper", "corrupt"]),
    BenchmarkCase("hci_disc_lmp_response_timeout", _disconnect(0x22), "HCI", "Disconnection", "0x22",
                  ["response timeout", "rf", "hung", "poor"]),

    # --- HCI Command Complete / Status Failed ---
    BenchmarkCase("hci_cmdcomplete_disallowed", _cmd_complete(0x0406, 0x0C), "HCI",
                  "Command Complete Failed [Disconnect]", "0x0C",
                  ["disallow", "state", "sequence", "out of sequence"]),
    BenchmarkCase("hci_cmdstatus_unknown_conn_id", _cmd_status(0x0406, 0x02), "HCI",
                  "Command Status Failed [Disconnect]", "0x02",
                  ["stale", "handle", "unknown connection", "no record"]),

    # --- HCI Encryption Change Failed ---
    BenchmarkCase("hci_enc_key_missing", _encryption_change(0x06), "HCI", "Encryption Change Failed", "0x06",
                  ["key", "pin", "missing", "stale", "cleared"]),
    BenchmarkCase("hci_enc_mode_not_acceptable", _encryption_change(0x25), "HCI", "Encryption Change Failed", "0x25",
                  ["encryption mode", "policy", "weak", "strength"]),

    # --- HCI LE Connection Complete Failed ---
    BenchmarkCase("le_conn_failed_to_establish", _le_conn_complete(0x3E), "HCI", "LE Connection Complete Failed", "0x3E",
                  ["establish", "handshake", "range", "interference"]),
    BenchmarkCase("le_conn_unacceptable_params", _le_conn_complete(0x3B), "HCI", "LE Connection Complete Failed", "0x3B",
                  ["parameter", "interval", "reject", "latency"]),
    BenchmarkCase("le_enhanced_conn_controller_busy", _le_enhanced_conn_complete(0x3A), "HCI",
                  "LE Enhanced Connection Complete Failed", "0x3A",
                  ["busy", "resource", "too busy"]),

    # --- L2CAP Connect Rejected ---
    BenchmarkCase("l2cap_psm_not_supported", _l2cap_connect_rejected(0x0019, 0x0002), "L2CAP", "Connect Rejected", "0x0002",
                  ["psm", "not support", "profile", "doesn't implement"]),
    BenchmarkCase("l2cap_security_block", _l2cap_connect_rejected(0x0001, 0x0003), "L2CAP", "Connect Rejected", "0x0003",
                  ["security", "encrypt", "authent", "pairing"]),
    BenchmarkCase("l2cap_no_resources", _l2cap_connect_rejected(0x0011, 0x0004), "L2CAP", "Connect Rejected", "0x0004",
                  ["resource", "memory", "channel table"]),

    # --- L2CAP Configuration Response Rejected ---
    BenchmarkCase("l2cap_configure_unacceptable_params", _l2cap_configure_rejected(0x0001), "L2CAP",
                  "Configure Rejected", "0x0001",
                  ["parameter", "mtu", "unacceptable", "flow"]),

    # --- L2CAP Connection Parameter Update Rejected (no exact corpus entry -- tests semantic-only fallback) ---
    BenchmarkCase("l2cap_connparam_update_rejected", _l2cap_conn_param_update_rejected(0x0001), "L2CAP",
                  "Connection Parameter Update Rejected", "0x0001",
                  ["parameter", "interval", "reject", "latency"]),

    # --- L2CAP Command Reject ---
    BenchmarkCase("l2cap_invalid_cid", _l2cap_command_reject(0x0002), "L2CAP", "Command Reject", "0x0002",
                  ["cid", "channel", "stale", "doesn't exist"]),

    # --- SMP Pairing Failed ---
    BenchmarkCase("smp_passkey_entry_failed", _smp_pairing_failed(0x01), "SMP", "Pairing Failed", "0x01",
                  ["passkey", "entry", "user", "mistyped"]),
    BenchmarkCase("smp_authentication_requirements", _smp_pairing_failed(0x03), "SMP", "Pairing Failed", "0x03",
                  ["authentication", "mitm", "io capab", "just works"]),
    BenchmarkCase("smp_encryption_key_size", _smp_pairing_failed(0x06), "SMP", "Pairing Failed", "0x06",
                  ["key size", "weak", "minimum", "downgrade"]),
    BenchmarkCase("smp_dhkey_check_failed", _smp_pairing_failed(0x0B), "SMP", "Pairing Failed", "0x0B",
                  ["dhkey", "public key", "tamper", "corrupt"]),
    BenchmarkCase("smp_numeric_comparison_failed", _smp_pairing_failed(0x0C), "SMP", "Pairing Failed", "0x0C",
                  ["numeric comparison", "user", "reject", "mismatch"]),
]


def build_capture() -> bytes:
    """Builds one combined capture with all cases, each on a unique handle."""
    b = BtsnoopBuilder()
    for i, case in enumerate(CASES):
        handle = 0x0010 + i
        case.build(b, handle)
    return b.to_bytes()
