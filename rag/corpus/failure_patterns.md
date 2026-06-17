# Common Bluetooth Failure Patterns

## Connection parameter negotiation failures

LE connection parameter negotiation happens via `LE Connection Update`
(HCI) / `LL_CONNECTION_UPDATE_IND` (link layer), or via the L2CAP
Connection Parameter Update signaling channel (CID 0x0005) for
peripheral-initiated requests. A negotiation "fails" in one of two
observable ways:

1. The central rejects the request outright -- HCI status `0x3B
   Unacceptable Connection Parameters` is returned in the relevant
   Command Complete/Status event.
2. The request is accepted but the new parameters never take effect
   before the link's supervision timeout expires, surfacing later as a
   `0x08 Connection Timeout` disconnection.

Symptoms in a packet trace: an `LE Connection Update` command or
`L2CAP Connection Parameter Update Request`, followed either by a
non-zero status in the corresponding completion event, or by a
disconnection event within a few connection intervals afterward. The
most common real-world cause is a peripheral requesting an interval
the central's power/latency policy won't allow (e.g. a fitness band
asking for a faster interval than a phone's BLE stack permits while
backgrounded).

## L2CAP channel rejections

When an L2CAP `Connection Response` carries a non-zero result code on
the signaling channel (fixed CID 0x0001 for BR/EDR, 0x0005 for LE),
the requested profile channel never opens, and everything built on top
of it (RFCOMM, AVDTP/A2DP, ATT over an LE COC, etc.) fails silently
from the application's point of view -- often surfacing only as "device
connected but no audio" or "service not found." The two most frequent
causes seen in the field are `0x0002 PSM not supported` (peer doesn't
implement that profile) and `0x0003 security block` (peer requires
encryption/authentication that hasn't completed yet -- usually because
the L2CAP channel was opened before pairing finished).

## Pairing / bonding failures (SMP)

SMP pairing failures (opcode 0x05 on fixed CID 0x0006 for LE, 0x0007
for BR/EDR Secure Connections over LE transport) almost always trace
back to one of: a user-facing rejection (Numeric Comparison Failed,
Passkey Entry Failed), an IO-capability mismatch that can't satisfy
one side's MITM requirement (Authentication Requirements), or stale
keys on a reconnect (which usually shows up one layer up, as HCI
`0x06 PIN or Key Missing` on the Encryption Change / Connection
Complete event rather than as an SMP Pairing Failed PDU). When you see
repeated pairing attempts in quick succession, check for `0x09
Repeated Attempts` -- the controller is throttling to prevent
brute-force passkey guessing, and the real root cause is whatever
caused the *first* failure, not the throttling itself.

## Page timeout vs. connection timeout

These are easy to confuse but happen at different points in the link
lifecycle:

- **Page Timeout (HCI `0x04`)** happens during BR/EDR connection
  *establishment* -- the initiator paged but the remote never
  responded. The link never existed. Root cause is almost always: peer
  out of range, peer not in page-scan mode, or wrong BD_ADDR.
- **Connection Timeout (HCI `0x08`)** happens to an *already
  established* link -- it disconnects because no valid packets were
  received within the supervision timeout. Root cause is usually: peer
  moved out of range mid-session, peer crashed/lost power, or
  interference.

If a trace shows a successful Connection Complete followed shortly
after by a Disconnection Complete with reason `0x08`, focus the
explanation on link stability (RF environment, peer power state)
rather than on the initial connection setup.

## Encryption / MIC failures

A `0x3D Connection Terminated due to MIC Failure` disconnect means an
already-encrypted link received a packet that failed integrity
verification. This is a security-relevant event: legitimate causes
include severe RF corruption flipping bits in an encrypted PDU, but it
is also the textbook signature of a downgrade or replay attack attempt
against the encrypted session. It should be flagged distinctly from
ordinary link-quality disconnects (`0x08`) in any RCA summary.

## LE connection establishment failures

`0x3E Connection Failed to be Established` differs from both page
timeout and connection timeout: it means the LE link-layer connection
procedure *started* (the controller sent/received `CONNECT_IND`) but
never completed the handshake. This typically means the peer moved out
of range or lost power in the brief window between the connection
request and the first anchor point, or there was severe interference
specifically during that establishment window.
