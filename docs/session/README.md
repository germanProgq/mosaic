# Session protocol

The session protocol runs after verified QUIC TLS with ALPN `mosaic-poc/2`. TLS resumption and 0-RTT are disabled. The client opens bidirectional stream zero for control. Each control message is a u32 big-endian byte length followed by exactly that many bytes of typed JSON. Empty messages, lengths above the configured cap or 4096 bytes, duplicate or unknown fields, invalid JSON and truncated input fail the session. Lengths are checked before payload allocation. Control exchange has a five-second deadline.

The client sends `SessionInit` with `type`, `version` (2), `mode` (`diagnostic`, `tunnel` or `fetch`), `token` (64 hexadecimal characters encoding exactly 32 bytes), `mtu` (1100) and `send_limit` (its current Quinn maximum datagram size). The relay compares decoded tokens with the established constant-time routine from `subtle`. Tunnel mode requires the Linux relay’s `--tunnel` service and an available single-owner lease. Diagnostic-only service still rejects it. The lease is acquired during authorization and released on rejection, connection termination or service shutdown.

The relay sends `SessionReady` with `type`, `version`, `mode`, `mtu`, `send_limit` and `session_id`. The agreed limit is the minimum of both reported send limits; each must fit 1100 payload bytes plus the 12-byte packet header. Unsupported or insufficient datagram capacity closes the session with application code 2 and a fixed size error. Other authorization failures use code 1 and a fixed redacted reason.

The session identifier is 32 bytes of TLS exporter output encoded as lowercase hex, using label `mosaic session identifier` and context `2`. Each peer independently derives the identifier from its established connection. It changes on a fresh connection and is never a substitute for the token. The client validates the identifier, version, requested mode, MTU and agreed limit.

The client sends `ClientReady` repeating all agreed values, then finishes its control direction. The relay verifies every value and the FIN, then finishes its response direction. The client waits for that FIN before returning Ready. Extra control bytes, an additional stream or datagrams observed before Ready reject the connection. No tunnel setup or IP packet injection exists in diagnostic mode.

In diagnostic sessions, subsequent bidirectional streams carry one reliable echo payload, bounded to 65536 bytes and terminated by FIN. The control size cap does not apply to these streams. The relay can process three simultaneously.

Diagnostic datagrams use this big-endian layout:

| Field | Bytes | Value |
| --- | --- | --- |
| Version | 1 | 2 |
| Kind | 1 | 1 for diagnostic echo |
| Payload length | 2 | 1 through 1100 |
| Sequence | 8 | Unsigned diagnostic sequence |
| Payload | Declared length | Exact diagnostic bytes |

The receiver checks the whole size, version, diagnostic kind and declared length before echoing. Kind 2 carries IPv4 in tunnel sessions and is rejected by diagnostic sessions. Kind 0 remains reserved. Sequences count unique replies and measure loss; they provide no replay protection or custom cryptography. QUIC datagrams can be lost, duplicated or reordered. Every response is checked against its sequence-specific expected payload; duplicate responses cannot satisfy the unique-reply threshold.

The relay loads credentials at startup. Changing its token requires restarting that exact relay process. A valid session remains usable for its bounded workload; no reconnect or credential rotation protocol is implemented.

Tunnel datagrams have the same header with kind 2 and one complete IPv4 packet. Both directions validate size, version, IHL, total length, header checksum and fragmentation fields. Valid fragments and IPv4 options are preserved. The relay validates the configured client source before injection, and the client validates its destination before injection. Outbound packets also receive the corresponding address check. Invalid packets are counted and discarded. New reliable streams are rejected in tunnel mode.

Each direction has a bounded queue of at most 256 packets. Separate read and write futures allow bidirectional traffic even when the opposite direction is waiting. A shared schedule within each pump limits aggregate packet work with transport-overhead headroom; Quinn datagram buffers remain 256 KiB. Sender capacity is rechecked before every send and oversize errors stop the pump. Dropping the pump cancels all four futures and discards their queues. No packet state survives a connection failure.

Fetch mode requires the relay’s explicit `--fetch` option and uses the same authorization and readiness exchange. On a new bidirectional stream the client sends a bounded control message `{"type":"OpenTcp","host":"example.com","port":443}`. The relay validates the configured allowlist and resolved IPv4 addresses, connects to a checked address, then responds with `{"type":"TcpReady","max_bytes":33554432,"timeout_s":300}` using its remaining byte budget and configured session deadline. The client starts destination TLS only after this response. A denied or unavailable destination receives `{"type":"TcpRejected"}` and a finished response; rejected requests count against the request limit.

After TcpReady, stream bytes are opaque TCP payload and FIN half-closes the corresponding TCP direction. Both directions share the connection byte budget, including TLS/HTTP overhead, and the relay serves one stream at a time. Malformed headers, transfer errors, exhausted request/byte budgets or the session deadline close the fetch connection. Fetch sessions reject datagrams. Diagnostic wire bytes and tunnel datagram framing are unchanged; older relays reject the new fetch session mode. See [the fetch and forwarding guide](../egress/README.md).
