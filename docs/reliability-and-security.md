# Reliability and security additions

This fork extends the native Go core. Existing encrypted Session configurations
remain compatible when forward secrecy is disabled. No scripts are required.

## Diagnose a connection

```sh
openflux doctor --config client.conf
openflux doctor --config client.conf --json --timeout 120s
openflux doctor --config client.conf --probe-url https://example.com/
```

Doctor starts an isolated client and checks configuration/key access, local
listener availability, carrier admission, authenticated peer negotiation and
HTTPS through HTTP CONNECT. Mail.ru has separate document, WebSocket and editor
authentication stages. Other carriers report connection and peer stages.
The HTTPS probe verifies certificates and reads the response (up to 1 MiB).
Any HTTP status proves endpoint reachability; HTTP 401 is not application login.
`--probe-ca-file root.pem` adds a trusted CA for a private HTTPS probe.

Text/JSON reports contain fixed error codes and counters. They exclude proxy
credentials, document links, tokens, cookies, shared secrets and payloads. A
private `--status-file PATH` provides snapshots during ordinary core startup.
It must not be shared between processes. Diagnostics distinguish connection
to a carrier from successful authentication of the remote OpenFlux peer.

Doctor temporarily occupies the configured SOCKS port. Stop an existing client
first or select an unused `--socks5 127.0.0.1:0`. The default HTTP port is selected
automatically. Both managed listeners are restricted to loopback.

## Run an application with a private proxy

```sh
openflux run --config client.conf -- curl https://example.com/
```

Run waits for peer authentication and proxy readiness before starting the
application. Its exit status is preserved. Application exit, termination signals
and core failure trigger cleanup of owned processes. Unix process groups and
Windows jobs isolate cleanup from unrelated processes; Windows children are
assigned to a kill-on-close job before execution begins. Unix terminal ownership
is transferred for interactive applications and restored afterwards.

The child receives HTTP_PROXY, HTTPS_PROXY, ALL_PROXY (also lowercase), PI_PROXY,
PI_PROXY_OPENAI and PI_PROXY_OPENAI_CODEX pointing to the private HTTP proxy.
The core keeps its original environment so it can reach carriers through an
existing upstream proxy. The parent shell environment is unchanged. Existing
NO_PROXY exclusions are retained. Applications must support the relevant proxy
variables; this command does not intercept arbitrary networking or enforce a
system firewall. Application-specific proxy settings can override environment.

A configuration lock prevents simultaneous managed sessions using the same
configuration file. Relative key/cookie paths are resolved by running the core
in the configuration directory. The application stays in the invoking directory.
`--timeout` controls startup only, not the application's maximum lifetime.

## Carrier limits and recovery

Native carriers can implement `LimitedCarrier` to declare binary payload size,
maximum packets per batch and messages per second. Limits apply after encryption
and before carrier encoding. Mail.ru uses a conservative 1450-byte binary limit
and one IP packet per batch, keeping its JSON/Base64 cursor envelope below a
2048-byte wire budget. Its bootstrap carrier advertises a 1280-byte IPv4 packet
cap so routine encrypted TCP packets fit without fragmentation. Manager and
PortDemux preserve this negotiated size for application stacks. Queued cursors
wait for editor authentication after a reconnect. Direct TCP
uses its configured record limit. Unspecified limits keep existing behavior.

Oversized encrypted messages are fragmented into bounded `OFF` v1 records and
reassembled before cryptographic authentication. Reassembly reserves at most
1 MiB across 16 incomplete messages, with 128 fragments and 128 KiB per message;
assemblies expire after 15 seconds. Duplicates and malformed fragments do not
grow the allocation budget. Both peers must use this extension for fragmented
messages; small unfragmented legacy encrypted messages remain compatible.

The recovery layer buffers FIFO data during short carrier outages. Defaults:

```ini
[Interface]
RecoveryQueueBytes = 4194304
RecoveryTTL = 30s
```

Each recovery queue accepts at most 256 frames and the configured byte budget.
`--recovery-queue-bytes` and `--recovery-ttl` override configuration. Full queues
return an error; expired frames increment diagnostic counters and emit an
operational notice. Batch send failures have a separate diagnostic counter.
Accepted means queued, not remotely acknowledged. TCP remains responsible for
retransmission; UDP can lose datagrams. Brief carrier reconnects can preserve
an established Session, but an expired application connection or restarted exit
may still require retrying a request. No promise of resuming interrupted HTTP
responses is made.

## Opt-in forward secrecy

Enable on both peers:

```ini
[Interface]
EncryptionKeyFile = secret.txt
ForwardSecrecy = true
```

Or add `--forward-secrecy` to both commands. It implies strict `--negotiate`;
classic/plaintext fallback and stream mode are unavailable. Both peers must
use the same shared secret and matching key binding (normally the document URL).
Mixed secure/legacy peers fail authentication instead of silently downgrading.

The outer cryptographic layer uses `github.com/flynn/noise` v1.1.0 and
`Noise_NNpsk0_25519_AESGCM_SHA256`: ephemeral X25519, PSK authentication, AES-GCM
and SHA-256. The PSK is domain-separated and derived with scrypt. The handshake
identifier is bound into the Noise prologue. The existing encrypted Session
protocol runs inside Noise, preserving capability negotiation and replay checks.

An encrypted confirmation proves possession of the fresh DH keys before a
responder replaces an active epoch. Recorded initial/confirmation messages
cannot displace that epoch. Retries reuse complete ciphertext bytes. Data has
authenticated explicit directional nonce counters and a 4096-record replay
window, permitting bounded reordering. Nonces are never reused for encryption
within an epoch. There is no zero-RTT application data.

Fresh DH handshakes rotate traffic keys after 30 minutes and reconnect after
45 seconds without authenticated peer traffic. Candidate handshakes expire
after 10 seconds. A pending handshake does not discard an active epoch.
Completed/abandoned ephemeral private-key slices are cleared on a best-effort
basis; Go and the Noise library do not provide guaranteed heap zeroization.
Retired traffic-key objects are no longer retained by the transport.

Later disclosure of the shared secret alone does not expose previously captured
Noise application traffic, assuming ephemeral/traffic keys were not captured.
Live endpoint compromise is outside that guarantee. This protocol composition
has regression/integration tests, not an independent security audit.
Specification: https://noiseprotocol.org/noise.html

## Validation and release artifacts

Tests cover editor admission, cursor lengths and keepalives, proxy CONNECT,
fragmentation/reordering/duplicates, queue bounds/expiry, wrong PSKs, secure
duplex traffic, replay rejection, key rotation and replayed handshakes. A real
local direct carrier test verifies a large TLS response through Doctor and
managed application exit/lock reuse. Windows jobs are tested natively.

The CLI release includes Windows and Linux amd64 binaries, portable archives,
build metadata and SHA256SUMS.txt. It contains no configuration, credentials,
shared keys, cookies or document links. Forward secrecy stays opt-in: update
both endpoints before enabling it. See `scripts/release-fork.sh` for reproducible
build and packaging commands.
