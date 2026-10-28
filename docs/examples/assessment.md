# interlock OSDP assessment

Authorized use only. interlock runs against its bundled, network-isolated lab by default. Use it on real equipment only with the owner's written authorization; physical mode is gated by --physical, a disclaimer and a typed scope confirmation. This tool ships no vendor default production keys; the only built-in key is the public OSDP specification default SCBK-D.

## Scope

- **Target:** the bundled lab, compose project interlock-assess.
- **Containment:** checked before the run with docker compose config over docker-compose.yml plus each of 6 overrides: every network internal, no published ports, no exposed ports, no devices, not privileged, no network_mode, no added capabilities, no host pid or ipc namespace, every service on labnet only, every bind mount read-only, cp upstream pinned to the attacker, only allow-listed top-level sections and service keys, every network a plain compose-created bridge, every bind mount from inside the lab dir, every mount a bind or plain named volume or tmpfs, every build a plain build from the lab dir; so no lab container gets a host device, host privileges or namespaces, a host path outside the lab dir or any network but the internal labnet (not covered: the image build steps and the Docker daemon's own configuration).
- **Profiles run:** cleartext, sc-scbkd, downgrade
- **Core under test:** LibOSDP 3.0.8 (fixed); the pinned-vulnerable CVE-2024-52288 core is not part of the default run.
- **Framework:** MITRE ATT&CK v20.0: Enterprise primary, ICS secondary where a technique fits.
- **Access vector:** T1200 (Hardware Additions), engagement-level: every bus attack presumes a device inserted on the RS-485 segment; no ICS technique fits better.
- **Generated at:** 2026-10-28T09:16:12+00:00

## Summary

| Severity | Findings |
|---|---|
| critical | 1 |
| high | 4 |
| medium | 1 |
| low | 1 |
| info | 0 |

### Steps

| Step | Profile | Status | Findings | Duration (s) |
|---|---|---|---|---|
| sniff-enumerate | cleartext | vulnerable | 2 | 34.1 |
| fuzz | cleartext | not_vulnerable | 0 | 36.0 |
| weak-key-keyset | sc-scbkd | vulnerable | 2 | 34.2 |
| downgrade | downgrade | vulnerable | 1 | 68.3 |
| spoof | cleartext | vulnerable | 1 | 34.3 |
| replay | cleartext | vulnerable | 1 | 35.7 |
| cve-2024-52288-fixed | sc-scbkd | not_vulnerable | 0 | 36.7 |

## Coverage

| Attack | Step | Result | Enterprise | ICS |
|---|---|---|---|---|
| sniff | sniff-enumerate | ATK-01-sniff-pd-101 | T1040 (Network Sniffing) | T0842 (Network Sniffing) |
| enumerate | sniff-enumerate | ATK-02-enumerate-pd-101 | T1018 (Remote System Discovery) | T0888 (Remote System Information Discovery) |
| fuzz | fuzz | no finding | T1499.004 (Endpoint Denial of Service: Application or System Exploitation) | T0814 (Denial of Service) |
| weak-key | weak-key-keyset | ATK-06-weak-key | T1110.002 (Brute Force: Password Cracking) | T1694.001 (Insecure Credentials: Default Credentials) |
| keyset | weak-key-keyset | ATK-04-keyset | T1040 (Network Sniffing) | T0842 (Network Sniffing) |
| downgrade | downgrade | ATK-03-downgrade | T1689 (Downgrade Attack) | T0830 (Adversary-in-the-Middle) |
| spoof | spoof | ATK-08-spoof-unlock | T1565.002 (Data Manipulation: Transmitted Data Manipulation) | T1692.001 (Unauthorized Message: Command Message) |
| replay | replay | ATK-05a-replay-card-exchange | T1557 (Adversary-in-the-Middle) | T1692.002 (Unauthorized Message: Reporting Message) |
| cve-2024-52288 | cve-2024-52288-fixed | no finding | T1557 (Adversary-in-the-Middle) | T0830 (Adversary-in-the-Middle) |

## Findings

## ATK-01-sniff-pd-101: OSDP PD 101 observed on the bus

- **Severity:** medium
- **ATT&CK technique:** T1040 (Network Sniffing)
- **ATT&CK for ICS:** T0842 (Network Sniffing)
- **Evidence:** PD address 101; codes seen: CMD_CAP, CMD_ID, CMD_POLL, REPLY_ACK, REPLY_PDCAP, REPLY_PDID, REPLY_RAW; Secure Channel posture: clear-text.
- **Remediation:** Enable OSDP Secure Channel (SCBK) so bus traffic is authenticated and encrypted; do not operate readers in clear-text.

## ATK-02-enumerate-pd-101: OSDP PD 101 enumerated

- **Severity:** low
- **ATT&CK technique:** T1018 (Remote System Discovery)
- **ATT&CK for ICS:** T0888 (Remote System Information Discovery)
- **Evidence:** PD address 101; identity: vendor=0xbebafe model=1 version=1 serial=0xafbeadde firmware=173.222.173; advertised capabilities: OutputControl(compliance=1,count=1), LEDControl(compliance=2,count=1), AudibleControl(compliance=1,count=1), TextOutput(compliance=1,count=1), CheckCharacterSupport(compliance=1,count=0), CommunicationSecurity(compliance=1,count=0), ReceiveBufferSize(compliance=0,count=1).
- **Remediation:** Enable OSDP Secure Channel so identity (REPLY_PDID) and capability (REPLY_PDCAP) replies are authenticated and encrypted; unauthenticated clear-text enumeration lets any bus listener map readers before attacking.

## ATK-06-weak-key: OSDP Secure Channel uses the known weak key SCBK-D

- **Severity:** high
- **ATT&CK technique:** T1110.002 (Brute Force: Password Cracking)
- **ATT&CK for ICS:** T1694.001 (Insecure Credentials: Default Credentials)
- **Evidence:** The captured CHLNG/CCRYPT handshake recomputes the PD cryptogram under SCBK-D (303132333435363738393a3b3c3d3e3f), so the Secure Channel Base Key in use is the public spec default. Confirmed by recomputing the PD cryptogram via AES-128-ECB (PyCA), not a heuristic.
- **Remediation:** Replace the default Secure Channel Base Key (SCBK-D) with a unique per-site key; the spec default provides no confidentiality or authentication.

## ATK-04-keyset: OSDP install-mode KEYSET enrolment exposes the Secure Channel Base Key

- **Severity:** high
- **ATT&CK technique:** T1040 (Network Sniffing)
- **ATT&CK for ICS:** T0842 (Network Sniffing)
- **Evidence:** The install-mode Secure Channel is protected by the known spec default SCBK-D (confirmed by recomputing the CHLNG/CCRYPT handshake via AES-128-ECB, not a heuristic), so the key enrolled over CMD_KEYSET (0x75) is readable by any bus observer: the recovered SCBK is the public OSDP spec default SCBK-D (303132333435363738393a3b3c3d3e3f). The payload was decrypted with the session key derived from SCBK-D and the R-MAC read from REPLY_RMAC_I.
- **Remediation:** Do not leave readers in install mode on the production bus; after enrolment, provision a unique per-site SCBK and disable install mode so the default SCBK-D no longer protects (and exposes) the key-set exchange.

## ATK-03-downgrade: OSDP Secure Channel downgraded to clear-text by in-path capability rewrite

- **Severity:** high
- **ATT&CK technique:** T1689 (Downgrade Attack)
- **ATT&CK for ICS:** T0830 (Adversary-in-the-Middle)
- **Evidence:** An in-path MITM stripped the CommunicationSecurity capability (function 0x09) from the PD's REPLY_PDCAP. Baseline session was Secure Channel (SCB seen=True, SCS codes=['0x11', '0x12', '0x13', '0x14', '0x15', '0x16', '0x18']); after the rewrite the CP never started the handshake and the attacked session is clear-text (no SCB, no SCS). The before/after pair proves the downgrade.
- **Remediation:** Enable and ENFORCE OSDP Secure Channel on the CP (EnforceSecure): a CP that refuses a clear-text fallback cannot be downgraded by rewriting the PD's advertised capabilities. Do not rely on the PD advertising CommunicationSecurity.

## ATK-08-spoof-unlock: OSDP PD unlocked by a forged CMD_OUT injected onto the bus

- **Severity:** critical
- **ATT&CK technique:** T1565.002 (Data Manipulation: Transmitted Data Manipulation)
- **ATT&CK for ICS:** T1692.001 (Unauthorized Message: Command Message)
- **Evidence:** The PD's lock-state signal was LOCKED before the injection and flipped to UNLOCKED immediately after a forged CMD_OUT (output permanently ON) was injected cp->pd through the in-path MITM seam, carrying the live session's own sequence number so it was accepted as a legitimate command.
- **Remediation:** Enable OSDP Secure Channel with MAC+encryption (SCS_17/18) so an in-path attacker cannot forge or inject accepted commands; without channel integrity, any party on the bus can command the PD's outputs directly.

## ATK-05a-replay-card-exchange: Clear-text card read is reusable and the bus accepts an in-path unlock (replay precondition met)

- **Severity:** high
- **ATT&CK technique:** T1557 (Adversary-in-the-Middle)
- **ATT&CK for ICS:** T1692.002 (Unauthorized Message: Reporting Message)
- **Evidence:** 1 clear-text REPLY_RAW card read(s) were captured live from the bus with no MAC and no freshness, so the exact bytes can be presented again. On the live bus the PD's lock-state signal went LOCKED -> UNLOCKED after the in-path relay's POLL-to-CMD_OUT rewrite (the ATK-08 mechanism). The byte-exact re-injection of the captured REPLY_RAW is proven by host unit tests in tests/osdp/test_attacks_replay.py, not on the live bus.
- **Remediation:** Enable OSDP Secure Channel with MAC+encryption (SCS_17/18) and reject replayed sequence numbers; a clear-text bus with no freshness guarantee lets any captured card-presentation exchange be reused verbatim.

## Checks without a finding

- fuzz (not_vulnerable): baseline poll answered; all nine corruptions handled; the PD answered every follow-up poll
- cve-2024-52288-fixed (not_vulnerable): fixed LibOSDP 3.0.8 rejected the replayed REPLY_RMAC_I: "cp-1  | OSDP: CP: PD-101: 2026-10-28T09:15:40Z   osdp_cp.c:658  [EMERG] Out of order REPLY_RMAC_I; has PD gone rogue?"

## Method notes

- sniff-enumerate: The read-only TCP tap in the attacker position records both directions of one cleartext CP-PD session; the captures are decoded with the interlock OSDP codec and folded into the PD topology (sniff) and the PD identity and capabilities (enumerate).
- fuzz: active: the nine deterministic corruptions sent from the idle attacker over one persistent connection to the PD (cp idle, docker-compose.fuzz.yml); liveness proven by a follow-up valid poll after each
- weak-key-keyset: passive: read-only TCP tap on the install-mode Secure Channel bus; AES-verified SCBK-D check and KEYSET payload decryption on the host; each direction is decoded up to the 20000-frame ceiling and a clean result from a direction that reaches it is inconclusive
- downgrade: before/after pair: untouched session via the tap, then the inline relay stripping CommunicationSecurity from REPLY_PDCAP; a CP that refuses the stripped PD (its own ENFORCE_SECURE line plus a relayed REPLY_PDCAP without CommunicationSecurity) is not_vulnerable
- spoof: active: inline rewrite relay turns an in-flight CMD_POLL into a forged CMD_OUT on a trigger file; oracle is the PD's own lock-state log line; a clean result needs the relay's own injection line in the attacker log
- replay: active: the card read comes from the sniff-enumerate step's live capture; live proof via the in-path relay, which serves the same POLL-to-CMD_OUT rewrite as spoof on the replay trigger; the byte-exact re-injection of the captured REPLY_RAW is proven by host unit tests (tests/osdp/test_attacks_replay.py), not on the live bus; a clean result needs the relay's own injection line in the attacker log
- cve-2024-52288-fixed: active: inline relay replays the live-captured REPLY_RMAC_I-first secure blob aligned to the CP's 2-bit sequence; oracle is the controller's re-authorisation count and its rejection line; the pinned-vulnerable core is not part of the default run (D-03)
