# BlueScope-RCA Benchmark Report

Run at: 2026-06-18T15:03:33.919432+00:00
LLM model: `llama3.2:latest`  |  Embedding model: `nomic-embed-text`
Elapsed: 105.6s for 28 cases

**Detection accuracy: 100.0%** (28/28)
**Explanation accuracy: 100.0%** (28/28)

Detection accuracy = the rule engine identified the correct layer/kind/code for the injected failure. Explanation accuracy = the LLM's explanation, for correctly-detected failures, mentioned at least one expected root-cause keyword.

## Per-case results

| Case | Layer | Code | Detected | Explained | Matched keyword |
|---|---|---|---|---|---|
| hci_conn_page_timeout | HCI | 0x04 | ✅ | ✅ | out of range |
| hci_conn_limited_resources | HCI | 0x0D | ✅ | ✅ | resource |
| hci_conn_security_block | HCI | 0x0E | ✅ | ✅ | security |
| hci_conn_unacceptable_bdaddr | HCI | 0x0F | ✅ | ✅ | address |
| hci_conn_accept_timeout | HCI | 0x10 | ✅ | ✅ | timeout |
| hci_disc_connection_timeout | HCI | 0x08 | ✅ | ✅ | range |
| hci_disc_low_resources | HCI | 0x14 | ✅ | ✅ | resource |
| hci_disc_unspecified | HCI | 0x1F | ✅ | ✅ | unspecified |
| hci_disc_mic_failure | HCI | 0x3D | ✅ | ✅ | mic |
| hci_disc_lmp_response_timeout | HCI | 0x22 | ✅ | ✅ | response timeout |
| hci_cmdcomplete_disallowed | HCI | 0x0C | ✅ | ✅ | disallow |
| hci_cmdstatus_unknown_conn_id | HCI | 0x02 | ✅ | ✅ | stale |
| hci_enc_key_missing | HCI | 0x06 | ✅ | ✅ | key |
| hci_enc_mode_not_acceptable | HCI | 0x25 | ✅ | ✅ | encryption mode |
| le_conn_failed_to_establish | HCI | 0x3E | ✅ | ✅ | range |
| le_conn_unacceptable_params | HCI | 0x3B | ✅ | ✅ | parameter |
| le_enhanced_conn_controller_busy | HCI | 0x3A | ✅ | ✅ | busy |
| l2cap_psm_not_supported | L2CAP | 0x0002 | ✅ | ✅ | psm |
| l2cap_security_block | L2CAP | 0x0003 | ✅ | ✅ | security |
| l2cap_no_resources | L2CAP | 0x0004 | ✅ | ✅ | resource |
| l2cap_configure_unacceptable_params | L2CAP | 0x0001 | ✅ | ✅ | parameter |
| l2cap_connparam_update_rejected | L2CAP | 0x0001 | ✅ | ✅ | parameter |
| l2cap_invalid_cid | L2CAP | 0x0002 | ✅ | ✅ | cid |
| smp_passkey_entry_failed | SMP | 0x01 | ✅ | ✅ | passkey |
| smp_authentication_requirements | SMP | 0x03 | ✅ | ✅ | authentication |
| smp_encryption_key_size | SMP | 0x06 | ✅ | ✅ | key size |
| smp_dhkey_check_failed | SMP | 0x0B | ✅ | ✅ | dhkey |
| smp_numeric_comparison_failed | SMP | 0x0C | ✅ | ✅ | numeric comparison |

## Explanations

### hci_conn_page_timeout (HCI 0x04)

The likely root cause for Code 0x04 (Page Timeout) is that the remote device is out of range or powered off, preventing it from responding to paging within the specified timeout window.

Next debugging step: Verify the remote device's power state and RF signal strength by checking the device's proximity to the Bluetooth module and ensuring it is turned on. Use a multimeter to measure the received signal strength indicator (RSSI) values for the remote device, which can help determine if the device is within range and transmitting correctly.

*Citations: hci_error_codes:codes:0x04, hci_error_codes:codes:0x0D, hci_error_codes:codes:0x00, hci_error_codes:codes:0x03, hci_error_codes:codes:0x3E*

### hci_conn_limited_resources (HCI 0x0D)

The likely root cause for Code name 'Connection Rejected due to Limited Resources' is that the remote device's connection table is full or it is low on memory/power.

Next debugging step: Inspect the packet capture to verify if there are multiple connections established simultaneously with the same device, which could indicate a full connection table.

*Citations: hci_error_codes:codes:0x0D, hci_error_codes:codes:0x00, hci_error_codes:codes:0x03, hci_error_codes:codes:0x05, hci_error_codes:codes:0x13*

### hci_conn_security_block (HCI 0x0E)

The likely root cause for Code name 'Connection Rejected Due To Security Reasons' is that the remote device requires bonding/encryption before allowing the connection, but the local device's security mode/IO capability is insufficient to meet the peer's requirements.

Next debugging step: Inspect the HCI packet #3 at t=0.004s in the capture to verify if the 'Security Requested' bit (bit 5 of the LMP command) was set in the LMP Command Channel message, which would indicate that the remote device is requesting security features such as encryption or authentication.

*Citations: hci_error_codes:codes:0x0E, hci_error_codes:codes:0x3E, hci_error_codes:codes:0x00, hci_error_codes:codes:0x0D, hci_error_codes:codes:0x05*

### hci_conn_unacceptable_bdaddr (HCI 0x0F)

The likely root cause of this failure is that the remote device's accept/allow list excludes the initiator's Bluetooth address, or there is an address type mismatch between public and random addresses.

Next debugging step: Verify that the initiator's Bluetooth address (BD_ADDR) matches the expected format and is correctly configured in the allow list of the remote device.

*Citations: hci_error_codes:codes:0x0F, hci_error_codes:codes:0x0D, hci_error_codes:codes:0x00, hci_error_codes:codes:0x05, hci_error_codes:codes:0x1F*

### hci_conn_accept_timeout (HCI 0x10)

The likely root cause for Code 0x10 (Connection Accept Timeout Exceeded) is that the remote device stopped responding mid-handshake, causing the local controller's connection accept timeout to expire before a successful handshake could complete.

Next debugging step: Inspect the packet capture for any indication of a remote device disconnecting or stopping its response during the handshake process. Specifically, look for packets with the L2CAP Connection Handle (CH) set to 20 and check if there are any subsequent packets from the remote device that indicate it has stopped responding or disconnected.

*Citations: hci_error_codes:codes:0x10, hci_error_codes:codes:0x03, hci_error_codes:codes:0x13, hci_error_codes:codes:0x05, hci_error_codes:codes:0x0D*

### hci_disc_connection_timeout (HCI 0x08)

The likely root cause for Code name 'Connection Timeout' (0x08) is that the peer device's supervision timeout window was set too aggressively for the link's connection interval, causing the local host to disconnect the connection prematurely.

Next debugging step: Verify the connection interval and supervision timeout values used by both devices in the pair. Check if these values are within the recommended ranges specified in the Bluetooth specification (e.g., 1-10 ms for connection intervals and 2-5 seconds for supervision timeouts).

*Citations: hci_error_codes:codes:0x08, hci_error_codes:codes:0x13, hci_error_codes:codes:0x16, hci_error_codes:codes:0x15, hci_error_codes:codes:0x03*

### hci_disc_low_resources (HCI 0x14)

The likely root cause for Code name 'Remote Device Terminated Connection due to Low Resources' is that the remote device's connection or memory limits reached a critical threshold, causing it to shed connections.

Next debugging step: Inspect the packet capture for any indication of the peer device entering a low-power state or shedding connections. Specifically, look for packets with L2CAP or SMP commands related to power management or connection limit changes (e.g., L2CAP Set Connection Limit).

*Citations: hci_error_codes:codes:0x14, hci_error_codes:codes:0x13, hci_error_codes:codes:0x15, hci_error_codes:codes:0x16, hci_error_codes:codes:0x44*

### hci_disc_unspecified (HCI 0x1F)

The likely root cause for HCI error code 0x1F (Unspecified Error) is a controller-internal failure that doesn't have a more specific error code. This could be due to an unexpected condition or an internal system failure.

Next debugging step: Inspect the vendor-specific debug logs for the real cause of the failure, as this code often indicates a non-classified issue within the controller. Reviewing these logs may provide additional information about what led up to the unspecified error and help identify potential root causes.

*Citations: hci_error_codes:codes:0x1F, hci_error_codes:codes:0x13, hci_error_codes:codes:0x16, hci_error_codes:codes:0x15, hci_error_codes:codes:0x02*

### hci_disc_mic_failure (HCI 0x3D)

The likely root cause for Code 0x3D (Connection Terminated due to MIC Failure) is RF corruption flipping bits in an encrypted PDU. This could be caused by a weak or poor-quality radio link, which may introduce errors during transmission.

Next debugging step: Analyze the packet capture to identify any packets that were transmitted with encryption and verify their integrity using the received MIC (Message Integrity Check). Specifically, examine Packet #9 at t=0.016s in the capture to check if it contains an encrypted PDU and if its MIC is valid or corrupted.

*Citations: hci_error_codes:codes:0x3D, hci_error_codes:codes:0x03, hci_error_codes:codes:0x13, hci_error_codes:codes:0x16, hci_error_codes:codes:0x15*

### hci_disc_lmp_response_timeout (HCI 0x22)

The likely root cause for Code 0x22 (LMP Response Timeout / LL Response Timeout) is that the peer device's firmware is hung mid-procedure or has a poor RF link that prevents timely LL/LMP responses.

Next debugging step: Inspect the packet capture to verify if there are any other packets with connection handles related to handle 25 before packet #10, and check for any indication of a pending LMP response or LL command in those packets.

*Citations: hci_error_codes:codes:0x22, hci_error_codes:codes:0x13, hci_error_codes:codes:0x16, hci_error_codes:codes:0x15, hci_error_codes:codes:0x02*

### hci_cmdcomplete_disallowed (HCI 0x0C)

The likely root cause for Code name 'Command Disallowed' is that there was an attempt to execute a command out of sequence relative to the controller's state machine or overlapping commands of the same type were issued back-to-back.

Next debugging step: Inspect the HCI packet sequence leading up to Packet #11 at t=0.020s to verify if any commands were issued in an incorrect order or if there are overlapping commands of the same type that could have triggered this error.

*Citations: hci_error_codes:codes:0x0C, hci_error_codes:codes:0x00, hci_error_codes:codes:0x16, hci_error_codes:codes:0x13, hci_error_codes:codes:0x02*

### hci_cmdstatus_unknown_conn_id (HCI 0x02)

The likely root cause for Code 0x02 (Unknown Connection Identifier) is that a stale connection handle was used after disconnecting. This could be due to a race between the disconnect operation and another command targeting the old handle.

Next debugging step: Inspect the HCI packet sequence leading up to Packet #12 at t=0.022s to verify if there were any commands sent with the same connection handle before or after the disconnect event, which would indicate that the handle was not properly cleared.

*Citations: hci_error_codes:codes:0x02, hci_error_codes:codes:0x13, hci_error_codes:codes:0x16, hci_error_codes:codes:0x15, hci_error_codes:codes:0x12*

### hci_enc_key_missing (HCI 0x06)

The likely root cause for Code 0x06 (PIN or Key Missing) is that the remote device's bonded keys were cleared/factory reset, causing it to no longer have a stored link key or PIN for this peer.

Next debugging step: Verify that the remote device was not factory reset recently by checking its stored link keys and/or verifying that the device's pairing settings are correct. This can be done by examining the HCI packet capture for any other error codes related to authentication or pairing, which may indicate a recent pairing attempt with an incorrect PIN/passkey.

*Citations: hci_error_codes:codes:0x06, hci_error_codes:codes:0x05, hci_error_codes:codes:0x26, hci_error_codes:codes:0x25, hci_error_codes:codes:0x03*

### hci_enc_mode_not_acceptable (HCI 0x25)

The likely root cause for 'Code name: Encryption Mode Not Acceptable' is that the proposed encryption mode/strength offered by one side of the connection is not acceptable to the other side due to security policy requirements or compatibility issues.

Next debugging step: Inspect the packet capture to verify if there are any mismatched or stale link keys on either side, as this could be a contributing factor to the Encryption Mode Not Acceptable error.

*Citations: hci_error_codes:codes:0x25, hci_error_codes:codes:0x05, hci_error_codes:codes:0x26, hci_error_codes:codes:0x29, hci_error_codes:codes:0x3D*

### le_conn_failed_to_establish (HCI 0x3E)

The likely root cause of this failure is that the peer device moved out of range during the connection setup window or lost power in that brief window, causing a synchronization timeout.

Next debugging step: Inspect the packet capture for the `CONNECT_IND` packet sent by the controller to initiate the connection procedure. Verify that the packet was received successfully and that it was not corrupted or truncated.

*Citations: hci_error_codes:codes:0x3E, hci_error_codes:codes:0x03, failure_patterns:6:LE connection establishment failures, hci_error_codes:codes:0x3B, hci_error_codes:codes:0x13*

### le_conn_unacceptable_params (HCI 0x3B)

The likely root cause for Code 0x3B (Unacceptable Connection Parameters) is that the proposed connection parameters (interval, latency, timeout) requested by the application were rejected as unacceptable by the peer device.

Next debugging step: Inspect the packet capture to verify if the application's requested connection parameters are indeed valid and reasonable. Check if the interval and latency values requested by the application fall within the typical range for Bluetooth connections (e.g., 1-10 ms for latency, 2-1000 ms for interval).

*Citations: hci_error_codes:codes:0x3B, hci_error_codes:codes:0x3E, hci_error_codes:codes:0x03, hci_error_codes:codes:0x0D, hci_error_codes:codes:0x13*

### le_enhanced_conn_controller_busy (HCI 0x3A)

The likely root cause of this failure is that the controller is too busy processing concurrent operations, leading to resource exhaustion.

Next debugging step: Inspect the system's current task list or operation queue to determine if there are multiple connections or operations running concurrently, and verify if all necessary resources (e.g., radio bandwidth) are being allocated correctly.

*Citations: hci_error_codes:codes:0x3A, hci_error_codes:codes:0x3E, hci_error_codes:codes:0x03, hci_error_codes:codes:0x3B, hci_error_codes:codes:0x3D*

### l2cap_psm_not_supported (L2CAP 0x0002)

The likely root cause for Code name 'Connection refused - PSM not supported' is that the client stack used an invalid or unsupported Protocol/Service Multiplexer (PSM). This could be due to a wrong PSM value used by the client stack.

Next debugging step: Verify the PSM values used in the L2CAP connection request and ensure they match the ones registered by the remote device. Check the 'psm' field in the packet capture for any inconsistencies or unexpected values, and review the Bluetooth protocol implementation to confirm that the correct PSM is being used.

*Citations: l2cap_result_codes:connect_result_codes:0x0002, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:connect_result_codes:0x0005, l2cap_result_codes:connect_result_codes:0x0004, l2cap_result_codes:command_reject_reason_codes:0x0000*

### l2cap_security_block (L2CAP 0x0003)

The likely root cause for this failure is that the pairing process hasn't completed yet, or bonding was lost/stale on one side, which means the link's current security level doesn't meet the service's requirements.

Next debugging step: Verify the pairing status and bonding state of both devices by checking the SDP (Service Discovery Protocol) data in the packet capture. Specifically, examine the 'psm' value (which is 'SDP' here) to ensure that it matches the expected pairing status and that bonding has not been lost or keys are stale on one side.

*Citations: l2cap_result_codes:connect_result_codes:0x0003, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:connect_result_codes:0x0007, l2cap_result_codes:connect_result_codes:0x0004, l2cap_result_codes:connect_result_codes:0x0005*

### l2cap_no_resources (L2CAP 0x0004)

The likely root cause for Code 0x0004 (Connection refused - no resources available) is that the peer device lacks sufficient memory or channel table slots to accept a new L2CAP channel.

Next debugging step: Inspect the peer's current open channels and connections to determine if it has exceeded its allowed limit, which could be causing the resource shortage.

*Citations: l2cap_result_codes:connect_result_codes:0x0004, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:connect_result_codes:0x0005, l2cap_result_codes:connect_result_codes:0x0007, l2cap_result_codes:connect_result_codes:0x0006*

### l2cap_configure_unacceptable_params (L2CAP 0x0001)

The likely root cause for 'Code name' Failure - unacceptable parameters is that the requested MTU or flow-control parameters are outside what the peer supports.

Next debugging step: Inspect the packet capture to verify the exact values of the proposed configuration parameters (e.g. MTU, flush timeout) and compare them with the peer's supported values as documented in the L2CAP specification or peer's documentation.

*Citations: l2cap_result_codes:configure_result_codes:0x0001, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:configure_result_codes:0x0005, l2cap_result_codes:command_reject_reason_codes:0x0000, l2cap_result_codes:configure_result_codes:0x0003*

### l2cap_connparam_update_rejected (L2CAP 0x0001)

The likely root cause for Code 0x0001 is that the proposed LE L2CAP COC (Connection-Oriented Control) parameters, specifically the Maximum Transmission Unit (MTU), are not acceptable to the peer device.

Next debugging step: Inspect the packet capture for the exact values of MTU and other COC parameters being requested in the connection parameter update. Verify that these values match the supported range defined by the Bluetooth specification for the specific device and firmware version being used.

*Citations: l2cap_result_codes:connect_result_codes:0x0007, l2cap_result_codes:connect_result_codes:0x0004, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:configure_result_codes:0x0001*

### l2cap_invalid_cid (L2CAP 0x0002)

The likely root cause for 'Code name: Invalid CID in request' is that a stale Channel Identifier (CID) was used after the channel was already disconnected. This could be due to incorrect handling of L2CAP connection state changes or failure to properly clean up resources when a connection is terminated.

Next debugging step: Inspect the packet capture for any evidence of a previously established connection being reused without proper re-establishment, such as a stale CID being used in subsequent packets.

*Citations: l2cap_result_codes:command_reject_reason_codes:0x0002, l2cap_result_codes:command_reject_reason_codes:0x0000, l2cap_result_codes:configure_result_codes:0x0002, l2cap_result_codes:command_reject_reason_codes:0x0001, l2cap_result_codes:configure_result_codes:0x0005*

### smp_passkey_entry_failed (SMP 0x01)

The likely root cause for 'Code name: Passkey Entry Failed' is that the user either mistyped the requested passkey or cancelled the passkey entry dialog during pairing.

Next debugging step: Inspect the passkey request and response packets to verify that they were transmitted correctly, including checking for any typos in the passkey values.

*Citations: smp_reason_codes:pairing_failed_reason_codes:0x01, smp_reason_codes:pairing_failed_reason_codes:0x05, smp_reason_codes:pairing_failed_reason_codes:0x0A, smp_reason_codes:pairing_failed_reason_codes:0x08, smp_reason_codes:pairing_failed_reason_codes:0x07*

### smp_authentication_requirements (SMP 0x03)

The likely root cause for Code 0x03 (Authentication Requirements) is that one device requires MITM protection (authenticated pairing), but the IO capabilities of the pair only support Just Works, or there's a mismatch between the Bonding flags set by the initiator and responder.

Next debugging step: Inspect the Bonding flags set during pairing for both devices to ensure they match. Verify that the bonding flags are correctly set according to the device's requirements and the expected behavior for the chosen pairing mode (e.g., Just Works).

*Citations: smp_reason_codes:pairing_failed_reason_codes:0x03, smp_reason_codes:pairing_failed_reason_codes:0x05, smp_reason_codes:pairing_failed_reason_codes:0x08, smp_reason_codes:pairing_failed_reason_codes:0x0A, smp_reason_codes:pairing_failed_reason_codes:0x07*

### smp_encryption_key_size (SMP 0x06)

The likely root cause for Code 0x06 (Encryption Key Size) is that a peer device requested an encryption key size below the local minimum security policy of one of the devices involved in the pairing process.

Next debugging step: Inspect the Pairing Request/Response PDU exchanged between the two devices to verify if the requested key size was indeed within the allowed range. Specifically, check the 'Encryption Key Size' field in the Pairing Request or Response PDU to confirm it matches the local minimum security policy of one of the devices.

*Citations: smp_reason_codes:pairing_failed_reason_codes:0x06, smp_reason_codes:pairing_failed_reason_codes:0x05, smp_reason_codes:pairing_failed_reason_codes:0x07, smp_reason_codes:pairing_failed_reason_codes:0x0A, smp_reason_codes:pairing_failed_reason_codes:0x08*

### smp_dhkey_check_failed (SMP 0x0B)

The likely root cause for Code 0x0B (DHKey Check Failed) is that the public key exchange during Secure Connections pairing was corrupted or tampered with, possibly due to a Man-in-the-Middle (MITM) attack.

Next debugging step: Inspect the Pairing Request/Response PDU exchanged between the devices to verify its integrity and authenticity. Specifically, check for any signs of tampering or corruption in the public key exchange data, such as invalid or mismatched values, truncated or padded data, or unexpected padding schemes.

*Citations: smp_reason_codes:pairing_failed_reason_codes:0x0B, smp_reason_codes:pairing_failed_reason_codes:0x05, smp_reason_codes:pairing_failed_reason_codes:0x0A, smp_reason_codes:pairing_failed_reason_codes:0x07, smp_reason_codes:pairing_failed_reason_codes:0x08*

### smp_numeric_comparison_failed (SMP 0x0C)

The likely root cause for Code name 'Numeric Comparison Failed' (Code 0x0C) is that the display values on both devices do not match or there's a UI bug causing incorrect pairing information to be displayed.

Next debugging step: Inspect the pairing request/response PDUs transmitted between the two devices. Specifically, verify that the numeric comparison parameters are correctly formatted and sent by both devices.

*Citations: smp_reason_codes:pairing_failed_reason_codes:0x0C, smp_reason_codes:pairing_failed_reason_codes:0x05, smp_reason_codes:pairing_failed_reason_codes:0x07, smp_reason_codes:pairing_failed_reason_codes:0x0A, smp_reason_codes:pairing_failed_reason_codes:0x08*