# ownvpn

A minimal, **post-quantum VPN library** written from scratch in Go. Peers talk over UDP
through a central hub server; all traffic is authenticated and encrypted with keys
derived from an ML-KEM-768 (FIPS 203) handshake. There is no classical key-exchange
fallback — the whole construction is post-quantum.

ownvpn started life as a single client/server binary. It is now a **library**: the tunnel
data-plane, the hub server, the crypto, the wire codec and the TUN plumbing are all
exposed as importable Go packages, so you can embed an encrypted overlay network directly
into your own application (a CLI, a daemon, a management server, a mobile control plane,
etc.). The former standalone binary now lives under [`examples/sample_client`](examples/sample_client)
as a reference implementation you can copy from.

This README documents two things:

1. **How to use ownvpn as a library** — the public API of each package (the new focus).
2. **How the protocol works** — the wire format and handshake, precise enough to
   re-implement a client from scratch in any other language or platform.

---

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start (as a library)](#quick-start-as-a-library)
- [API reference](#api-reference)
  - [`crypto` — key generation & derivation](#crypto--key-generation--derivation)
  - [`config` — configuration structs](#config--configuration-structs)
  - [`server` — the hub](#server--the-hub)
  - [`client` — the peer](#client--the-peer)
  - [`tunif` — TUN device & routing](#tunif--tun-device--routing)
  - [`proto` — wire codec](#proto--wire-codec)
- [The `version` context value (required)](#the-version-context-value-required)
- [Reference CLI (`examples/sample_client`)](#reference-cli-examplessample_client)
- [Repository layout](#repository-layout)
- [Wire protocol](#wire-protocol)
- [Handshake](#handshake)
- [Data path](#data-path)
- [Full tunnel](#full-tunnel)
- [Requirements & build](#requirements--build)
- [Security notes & limitations](#security-notes--limitations)
- [License](#license)

---

## Features

- **Post-quantum key exchange.** Two-message ML-KEM-768 handshake. Each side encapsulates
  to the other's static public key, so both ciphertexts contribute entropy to the final
  session secret. There is no Diffie–Hellman, no RSA, no X25519.
- **Mutual authentication.** The server only accepts peers whose `name` is registered and
  whose static ML-KEM-768 public key matches. Decapsulation only succeeds for the holder
  of the matching private key, so the handshake authenticates both sides.
- **Authenticated encryption for data.** ChaCha20-Poly1305 AEAD on every data packet with
  a per-packet random 12-byte nonce (16-byte Poly1305 tag).
- **HKDF key derivation.** Session key derived with HKDF-SHA256 from the concatenation of
  both shared secrets, using a caller-supplied version string as the `info` parameter.
- **Hub topology with IP-based routing.** The server inspects the destination IPv4 address
  of each decrypted inner packet and either delivers it locally or re-encrypts and
  forwards it to the matching peer.
- **Runtime peer management.** Add, remove, enable and disable peers on a running server
  and export the current peer set back to JSON — no restart required.
- **Optional full tunnel.** A client whose config sets `"fulltunnel": true` routes the
  machine's *entire* traffic through the tunnel and restores the routing table on exit.
- **Automatic re-handshake.** The client renegotiates the session key every 5 minutes, and
  immediately whenever encryption or decryption fails.
- **Keep-alive with SYN/ACK.** The client sends a 5-byte keepalive every 25 seconds to
  hold NAT mappings open; the server responds with an ACK variant.
- **Context-driven lifecycle.** Both `client.Run` and `server.Run` block until the
  `context.Context` you pass them is cancelled, then tear down cleanly.
- **No PKI.** No certificate authority, no TLS, no external services — just base64 keys in
  a struct you populate however you like.

---

## Installation

```sh
go get github.com/lbodlev888/ownvpn@latest
```

Then import the packages you need:

```go
import (
    "github.com/lbodlev888/ownvpn/client"
    "github.com/lbodlev888/ownvpn/config"
    "github.com/lbodlev888/ownvpn/crypto"
    "github.com/lbodlev888/ownvpn/server"
)
```

Requires **Go 1.26+** (uses the standard-library `crypto/mlkem` and `crypto/hkdf`
packages) and **Linux** with root / `CAP_NET_ADMIN` at runtime (to create the TUN device
and run `ip`).

---

## Quick start (as a library)

### 1. Generate keys

Every peer and the server needs its own ML-KEM-768 keypair.

```go
priv, _ := crypto.GeneratePrivate()      // base64 private (decapsulation) key
pub, _  := crypto.GetPublicKey(priv)     // base64 public (encapsulation) key
```

### 2. Run a hub server

```go
package main

import (
    "context"
    "os"
    "os/signal"

    "github.com/lbodlev888/ownvpn/config"
    "github.com/lbodlev888/ownvpn/server"
)

func main() {
    // The "version" value is REQUIRED — see the dedicated section below.
    ctx, stop := signal.NotifyContext(
        context.WithValue(context.Background(), "version", "myapp-v1"),
        os.Interrupt,
    )
    defer stop()

    cfg := config.ServerConfig{
        DecapsKey:   "<server private key>",
        BindAddress: "0.0.0.0:62789",
        VirtualIP:   "10.20.0.1",
        Subnet:      24,
        Peers: []config.PeerConfig{
            {
                Name:      "laptop",
                EncapsKey: "<laptop public key>",
                VirtualIP: "10.20.0.3",
            },
        },
    }

    if err := server.Init(cfg); err != nil {   // creates TUN, binds UDP, imports keys
        panic(err)
    }
    server.Run(ctx)                             // blocks until ctx is cancelled
}
```

### 3. Run a client (peer)

```go
package main

import (
    "context"
    "os"
    "os/signal"

    "github.com/lbodlev888/ownvpn/client"
    "github.com/lbodlev888/ownvpn/config"
)

func main() {
    ctx, stop := signal.NotifyContext(
        context.WithValue(context.Background(), "version", "myapp-v1"),
        os.Interrupt,
    )
    defer stop()

    cfg := config.PeerConfig{
        Name:       "laptop",
        DecapsKey:  "<laptop private key>",
        EncapsKey:  "<server public key>",
        VirtualIP:  "10.20.0.3",
        Subnet:     24,
        Endpoint:   "203.0.113.10:62789",
        FullTunnel: false,
    }

    client.Run(ctx, cfg)                        // blocks until ctx is cancelled
}
```

> **Note:** the `version` string must be **identical** on the client and the server — it
> is fed into HKDF as the `info` parameter, so a mismatch produces different session keys
> and every packet fails to decrypt. See [The `version` context value](#the-version-context-value-required).

---

## API reference

### `crypto` — key generation & derivation

```go
func GeneratePrivate() (string, error)
```
Generates a fresh ML-KEM-768 decapsulation (private) key and returns it base64-encoded.

```go
func GetPublicKey(privKey string) (string, error)
```
Derives the encapsulation (public) key from a base64 private key and returns it base64-encoded.

```go
func ParseDecapsKey(s string) (*mlkem.DecapsulationKey768, error)
func ParseEncapsKey(s string) (*mlkem.EncapsulationKey768, error)
```
Decode a base64 key string into the corresponding `crypto/mlkem` key type. Used internally
by `server`/`client`; exposed for callers that want to validate keys ahead of time.

```go
func DeriveEncryptionKey(material, salt []byte, infoString string, length int) ([]byte, error)
```
Thin wrapper over `hkdf.Key(sha256.New, ...)`. ownvpn calls it as
`DeriveEncryptionKey(ss1||ss2, nil, version, 32)` to derive the 32-byte ChaCha20-Poly1305
session key. Exposed so a re-implementation can reproduce the exact derivation.

### `config` — configuration structs

These are plain structs with JSON tags; construct them in code or unmarshal them from a
file — ownvpn does no file I/O itself.

```go
type PeerConfig struct {
    Name       string `json:"name"`
    DecapsKey  string `json:"privkey,omitempty"`   // this peer's private key (client side)
    EncapsKey  string `json:"pubkey"`              // client: server's pubkey; server: peer's pubkey
    VirtualIP  string `json:"virtual_ip"`
    Subnet     int    `json:"subnet,omitempty"`
    Endpoint   string `json:"endpoint,omitempty"`  // "host:port" of the server (client only)
    FullTunnel bool   `json:"fulltunnel,omitempty"`// route all traffic through the tunnel
    Disabled   bool   `json:"disabled,omitempty"`  // server-side: reject this peer's handshakes
}

type ServerConfig struct {
    DecapsKey   string       `json:"privkey"`
    BindAddress string       `json:"bind_address"` // "host:port" to listen on (UDP)
    VirtualIP   string       `json:"virtual_ip"`
    Subnet      int          `json:"subnet"`
    Peers       []PeerConfig `json:"peers"`
}
```

Note the dual meaning of `EncapsKey`/`pubkey`: on a **client** config it holds the
**server's** public key; inside a server's `Peers` list it holds **that peer's** public key.

### `server` — the hub

The server is a **package-level singleton**: it keeps its keys, TUN interface, UDP socket
and peer tables in package globals, so you run **one server per process**. All functions
below operate on that single instance and are safe for concurrent use (guarded by internal
mutexes).

```go
func Init(cfg config.ServerConfig) error
```
Imports the server private key, loads the allowed peers from `cfg.Peers`, creates the TUN
interface (`cfg.VirtualIP/cfg.Subnet`) and binds the UDP socket (`cfg.BindAddress`). Call
once before `Run`.

```go
func Run(ctx context.Context)
```
Starts the read loops (UDP ⇄ TUN) and **blocks** until `ctx` is cancelled, at which point
it closes the interface and socket and returns. `ctx` **must** carry the `version` value
(see below).

```go
func NewPeer(peer config.PeerConfig) error
```
Registers a peer on the running server. Validates the peer's `EncapsKey`; returns an error
if the key is not a valid ML-KEM-768 public key. Idempotent by `Name` (re-registering a
name overwrites it).

```go
func RemovePeer(name string)
```
Removes a peer by name and evicts any live session it holds (both the virtual-IP and
source-address routing entries).

```go
func EnablePeer(name string)
func DisablePeer(name string)
```
Toggle a peer's `Disabled` state. A disabled peer's handshakes are rejected and its live
session (if any) stops forwarding immediately. Enabling reverses both.

```go
func GetAllPeers() []config.PeerConfig
```
Returns a snapshot of every registered peer (for building a management/status API).

```go
func MarshalPeerSettings() ([]byte, error)
```
Serializes the current server config **including the live peer set** back to JSON — use it
to persist runtime peer changes (adds/removes/enable/disable) so they survive a restart.

**Typical management flow:**

```go
server.Init(cfg)
go server.Run(ctx)

// later, in response to your admin API:
server.NewPeer(config.PeerConfig{Name: "phone", EncapsKey: pub, VirtualIP: "10.20.0.4"})
server.DisablePeer("laptop")
peers := server.GetAllPeers()

// persist the new state:
data, _ := server.MarshalPeerSettings()
os.WriteFile("/etc/ownvpn/server.json", data, 0600)
```

### `client` — the peer

```go
func Run(ctx context.Context, cfg config.PeerConfig)
```
The entire client data-plane in one blocking call. It creates the TUN device, optionally
sets up the full tunnel, performs the handshake, and runs four goroutines (handshake loop,
keepalive, network→TUN reader, TUN→network writer). It returns when `ctx` is cancelled and
cleans up its interface/socket (and full-tunnel routes) on the way out. `ctx` **must**
carry the `version` value.

Unlike the server, the client is **not** a singleton — you can run multiple `client.Run`
calls concurrently (each gets its own TUN device, auto-named `bvpn%d`), though each still
needs `CAP_NET_ADMIN`.

### `tunif` — TUN device & routing

Low-level helpers, normally called for you by `server`/`client`. Exposed if you build a
custom data-plane.

```go
func SetupInterface(localAddr string) (*water.Interface, error) // create+configure a TUN ("cidr" e.g. "10.20.0.3/24")
func SetupFullTunnel(endpoint string) error                     // add default routes via the TUN, pin endpoint via real gw
func ClearFullTunnel(endpoint string) error                     // remove the pinned endpoint host route
```
The TUN device is named `bvpn%d` (first is `bvpn0`) and set to MTU 1420. Routing is
performed by shelling out to the `ip` command (Linux).

### `proto` — wire codec

Message-type constants and encode/decode functions for every packet on the wire. You only
need this package if you are re-implementing an endpoint or debugging the protocol; the
full format is documented in [Wire protocol](#wire-protocol).

```go
const (
    MsgClientHello  byte = 0x01
    MsgServerHello  byte = 0x02
    MsgData         byte = 0x03
    MsgKeepAlive    byte = 0x04
    MsgKeepAliveSYN byte = 0x05
    MsgKeepAliveACK byte = 0x06

    MLKEM768CiphertextLen = 1088
    MaxNameLen            = 255
)

type ClientHello struct { Name string; PublicData []byte }
type ServerHello struct { PublicData []byte }

func EncodeClientHello(ClientHello) ([]byte, error)
func DecodeClientHello([]byte) (ClientHello, error)
func EncodeServerHello(ServerHello) ([]byte, error)
func DecodeServerHello([]byte) (ServerHello, error)
func EncodeKeepAlive(flag byte) []byte
func DecodeKeepAlive(buf []byte, expectedFlag byte) bool
```

---

## The `version` context value (required)

Both `server.Run`/its handshake handler and `client.Run` read a string from the context:

```go
ctx := context.WithValue(context.Background(), "version", "myapp-v1")
```

This string is passed to HKDF as the **`info`** parameter when deriving the session key. It
acts as a domain-separation / protocol-version tag, and it **must match on both ends** —
if the client and server disagree, they derive different keys and no packet ever decrypts.

Consequences of omitting it:

- **Server:** the handshake handler logs `Missing ownvpn version key in context` and drops
  the handshake — no peer can ever connect.
- **Client:** `client.Run` calls `log.Fatalln`, terminating the process.

Pick a stable string for your application and bump it deliberately when you want to force
incompatibility between versions. The reference CLI uses the constant `"ownvpn0.0.4"`.

---

## Reference CLI (`examples/sample_client`)

The original standalone binary is preserved as a worked example that wires the library
packages together: it parses flags, reads a JSON config, sets the `version` context value,
and dispatches to `server.Run` or `client.Run`. Read it as the canonical "how do I glue
these packages together" reference — see [`examples/sample_client/main.go`](examples/sample_client/main.go).

Build and use it directly:

```sh
go build -o ownvpn ./examples/sample_client

# key management
./ownvpn -genkey                 # print a new private key
./ownvpn -pubkey <private-key>   # print the matching public key

# run
sudo ./ownvpn -server -config server.json
sudo ./ownvpn        -config peer.json
```

| Flag           | Applies to | Description                                                  |
|----------------|------------|--------------------------------------------------------------|
| `-server`      | both       | Run in server (hub) mode instead of client mode.             |
| `-config FILE` | both       | Path to the JSON config (default `/etc/ownvpn/config.json`). |
| `-genkey`      | —          | Generate and print a new ML-KEM-768 private key, then exit.  |
| `-pubkey KEY`  | —          | Print the public key for the given private key, then exit.   |

**Example peer config** (`peer.json`):

```json
{
  "name": "laptop",
  "privkey": "<this peer's private key>",
  "pubkey":  "<server's public key>",
  "virtual_ip": "10.20.0.3",
  "subnet": 24,
  "endpoint": "203.0.113.10:62789",
  "fulltunnel": false
}
```

**Example server config** (`server.json`):

```json
{
  "privkey": "<server's private key>",
  "bind_address": "0.0.0.0:62789",
  "virtual_ip": "10.20.0.1",
  "subnet": 24,
  "peers": [
    { "name": "laptop", "pubkey": "<peer's public key>", "virtual_ip": "10.20.0.3", "subnet": 24 }
  ]
}
```

---

## Repository layout

```
client/                # peer-side data-plane: handshake, encrypt, decrypt, keepalive
server/                # hub: accepts handshakes, decrypts, routes by inner dst IP, peer mgmt
  server.go            #   Init/Run + exported peer-management API
  network.go           #   UDP/TUN read loops, handshake handler, forwarding
  models.go            #   internal peer struct for the routing table
  utils.go             #   allowed-peer loading, key validation
crypto/                # ML-KEM-768 key import/export + HKDF-SHA256 derivation
proto/                 # wire-format encoders/decoders + message-type constants
tunif/                 # TUN device creation and `ip` route configuration
config/                # JSON config structs (PeerConfig, ServerConfig)
examples/sample_client # reference CLI that wires the packages together
```

---

## Wire protocol

All messages are sent as UDP datagrams. The first byte is always the **message type**.

| Code | Name            | Direction       | Length               |
|------|-----------------|-----------------|----------------------|
| 0x01 | `ClientHello`   | client → server | `2 + nameLen + 1088` |
| 0x02 | `ServerHello`   | server → client | `1 + 1088`           |
| 0x03 | `Data`          | both            | `1 + 12 + ct`        |
| 0x04 | `KeepAlive`     | both            | `5`                  |
| 0x05 | `KeepAliveSYN`  | (flag byte)     | n/a                  |
| 0x06 | `KeepAliveACK`  | (flag byte)     | n/a                  |

Constants:

- ML-KEM-768 ciphertext is fixed at **1088 bytes**; shared secret is **32 bytes**.
- ChaCha20-Poly1305: **32-byte key**, **12-byte nonce**, **16-byte tag**.
- HKDF salt: empty (nil). HKDF info string: the caller's version string (the reference CLI
  uses `"ownvpn0.0.4"`, literal ASCII, no trailing newline). Output length: 32 bytes.

### ClientHello (0x01)

```
+------+----------+-------------------+--------------------------------+
| 0x01 | nameLen  | name (nameLen B)  | mlkem768 ciphertext (1088 B)   |
+------+----------+-------------------+--------------------------------+
   1B       1B        1..255 B                    1088 B
```

`nameLen` is a single unsigned byte (1..255). `name` is raw ASCII/UTF-8 bytes.

### ServerHello (0x02)

```
+------+--------------------------------+
| 0x02 | mlkem768 ciphertext (1088 B)   |
+------+--------------------------------+
   1B               1088 B
```

### Data (0x03)

```
+------+----------------+-----------------------------------+
| 0x03 | nonce (12 B)   | chacha20poly1305 ciphertext+tag   |
+------+----------------+-----------------------------------+
   1B        12 B                 inner_len + 16 B
```

The plaintext is a **raw IPv4 packet** as read from the TUN device. The AEAD is called with
`additionalData = nil`.

### KeepAlive (0x04)

```
+------+-------+-----------------+
| 0x04 | flag  | random 3 bytes  |
+------+-------+-----------------+
   1B    1B          3 B
```

`flag` is `0x05` (SYN) when sent by the client and `0x06` (ACK) when sent back by the
server. The 3 random bytes are padding; they are not validated.

---

## Handshake

Each side owns a static ML-KEM-768 keypair. The handshake is **two messages** and derives a
fresh 32-byte ChaCha20-Poly1305 key every time.

Notation: `EK_x` = encapsulation (public) key of `x`, `DK_x` = decapsulation (private) key
of `x`. `Encaps(EK) -> (ss, ct)` returns a 32-byte shared secret and a 1088-byte
ciphertext. `Decaps(DK, ct) -> ss` recovers the same 32-byte shared secret.

### Step 1 — client builds and sends `ClientHello`

1. The client calls `Encaps(EK_server)` and gets `(ss1, ct1)`.
2. It builds `ClientHello { name, publicData = ct1 }` (`1 + 1 + nameLen + 1088` bytes).
3. It sends the datagram to the server's UDP endpoint.

### Step 2 — server processes `ClientHello`

1. Decodes the message; rejects if `name` is not registered, or if that peer is `Disabled`.
2. Looks up that peer's static public key `EK_client`.
3. Computes `ss1 = Decaps(DK_server, ct1)`. Failure means the client used the wrong server
   public key.
4. Computes `Encaps(EK_client) -> (ss2, ct2)`.
5. Derives `K = HKDF-SHA256(ikm = ss1 || ss2, salt = nil, info = version, L = 32)`.
6. Stores the peer keyed by both its UDP source address (data path) and its virtual IP
   (routing table). Any previous session for the same virtual IP is evicted.
7. Sends `ServerHello { publicData = ct2 }`.

### Step 3 — client processes `ServerHello`

1. Reads the response with a 2-second read deadline (a lost packet retries the whole
   handshake). The deadline is cleared after a successful read.
2. Verifies the source address matches the expected server endpoint.
3. Decodes `ServerHello`, computes `ss2 = Decaps(DK_client, ct2)`. Failure means the server
   used the wrong client public key.
4. Derives the **same** `K = HKDF-SHA256(ss1 || ss2, nil, version, 32)`.
5. Initializes ChaCha20-Poly1305 with `K`. Tunnel is now ready.

### Authentication property

Because `ss1` can only be recovered with `DK_server` and `ss2` only with `DK_client`, only
the legitimate holders of both private keys can derive `K`. An attacker holding *one* of
the two keys still cannot. There are no signatures and no certificates — authentication is
a side-effect of mutual key encapsulation.

### Re-handshake

The client re-runs the handshake when **any** of these happen:

- The 5-minute `HANDSHAKE_TIMEOUT` ticker fires.
- AEAD `Open` (decrypt) returns an error on a received data packet.
- `WriteTo` fails when sending an encrypted data packet.
- A keepalive ACK reports the session is no longer valid.

On a re-handshake the client clears its cipher (the reader/writer goroutines pause until
the new key is installed) and sends a fresh `ClientHello`. The server treats a new
`ClientHello` as authoritative: if the same virtual IP was mapped to a different UDP
address, the old mapping is dropped.

### Porting a client to another language

```text
// one-time
DK_client  = load_private_key(peer.privkey)
EK_server  = load_public_key(peer.pubkey)
serverAddr = resolve(peer.endpoint)
socket     = DatagramSocket()                            // ephemeral local port

// handshake loop (once at startup, then every 300 s and on any cipher failure)
loop {
    (ss1, ct1) = MLKEM768.encaps(EK_server)
    send(socket, serverAddr, [0x01] || [len(name)] || name_bytes || ct1)   // 2+N+1088 B

    socket.setSoTimeout(2000)                            // 2 s
    (resp, src) = recv(socket, 2048)
    if src != serverAddr || resp[0] != 0x02 || resp.length != 1 + 1088 { retry }

    ct2 = resp[1..1089]
    ss2 = MLKEM768.decaps(DK_client, ct2)
    ikm = ss1 || ss2                                     // 64 B
    K   = HKDF_SHA256(ikm, salt=null, info=VERSION, 32)  // 32 B — VERSION must match server
    aead = ChaCha20Poly1305(K)
    wait(min(300 s, until cipher_failure))
}

// data: TUN -> network
on_tun_packet(p):
    nonce = secure_random(12)
    ct    = aead.seal(nonce, plaintext=p, aad=null)      // tag appended
    send(socket, serverAddr, [0x03] || nonce || ct)

// data: network -> TUN
on_udp_packet(buf, src):
    if src != serverAddr: drop
    if buf[0] == 0x04: handle_keepalive(buf); return
    if buf[0] != 0x03 || buf.length < 1+12+16: drop
    pt = aead.open(buf[1..13], buf[13..], aad=null)      // on failure -> rehandshake
    tun.write(pt)

// keepalive (every 25 s while a session exists)
send(socket, serverAddr, [0x04, 0x05, rnd, rnd, rnd])    // SYN, expect [0x04,0x06,...] ACK
```

Platform notes (e.g. Android):

- `VERSION` (the HKDF `info`) must match the server's `version` context value exactly.
- Use a cryptographically secure RNG for the 12-byte per-packet nonce — never a counter.
- ML-KEM-768 is in `java.security.KeyPairGenerator` as of JDK 24 (`"ML-KEM"`); on Android
  use BouncyCastle (`bcprov` ≥ 1.78 exposes `MLKEM`).
- On Android the TUN device comes from `VpnService`; its `ParcelFileDescriptor` plays the
  role of the `iface` in this codebase.

---

## Data path

```
                ┌────────────────┐                ┌────────────────┐
   bvpn0  ─→──┤  client (peer) │──UDP, AEAD──→──┤  server (hub)  │──→── bvpn0
                │  ChaCha20-Poly │                │  ChaCha20-Poly │
   bvpn0  ←──┤   per session   │←─UDP, AEAD──←──┤   per session  │←── bvpn0
                └────────────────┘                └────────────────┘
                                                          │
                                                          └─── re-encrypt + forward
                                                               to another peer
```

The server looks at bytes 16..19 of every decrypted inner packet (the IPv4 destination). If
it equals the server's own virtual IP the packet is written to the local TUN; if it matches
a known peer's virtual IP it is re-sealed under that peer's session key and sent to that
peer. If it matches **neither**, the packet is written to the server's TUN device (see
[Full tunnel](#full-tunnel)) rather than dropped. Non-IPv4 packets (`version != 4`) are
dropped.

---

## Full tunnel

By default ownvpn is a hub overlay: only traffic addressed to a `virtual_ip` on the tunnel
subnet crosses the tunnel; everything else uses the host's normal routes. **Full tunnel**
mode turns the server into a default gateway so that *all* of a client's traffic is
encrypted and egresses through the server.

Enable it by setting `FullTunnel: true` on the client's `PeerConfig` (or `"fulltunnel":
true` in JSON). There is no separate flag or API call — the client acts on the config field
when `client.Run` starts.

### How the client side works

When `FullTunnel` is true, right after the TUN device is created the client reprograms the
host routing table (via the `ip` command in `tunif`):

1. **Capture all traffic.** It adds `0.0.0.0/1` and `128.0.0.0/1` pointing at `bvpn0`.
   Together these two `/1` routes cover the whole IPv4 space and, being more specific than
   the existing `0.0.0.0/0` default, win for every destination — without deleting the
   original default route, so it restores cleanly.
2. **Keep the tunnel reachable.** To stop the encrypted UDP packets to the server from
   being routed back into the tunnel (a loop), the client discovers the physical default
   gateway (via `jackpal/gateway`) and pins a host route to the **server's endpoint IP**
   through that real gateway.
3. **Clean up on exit.** On cancellation the client's `defer` calls `ClearFullTunnel`,
   deleting the pinned host route. The two `/1` routes are bound to `bvpn0` and vanish when
   the TUN closes. If the process is killed hard, the endpoint host route may linger and can
   be removed with `ip route del <endpoint-ip> via <gateway-ip>`.

The endpoint IP is taken from `Endpoint` with the `:port` stripped — this assumes a literal
IPv4 endpoint; a DNS hostname is not resolved here.

### How the server side works

Nothing needs enabling in ownvpn itself: when the server decrypts a packet whose
destination is neither its own virtual IP nor a known peer, it writes it to its TUN device
and lets the host kernel route it. For that to reach the internet, the **server's host**
must be configured as a router:

```sh
# 1. Allow the kernel to forward packets between interfaces
sudo sysctl -w net.ipv4.ip_forward=1

# 2. NAT/masquerade tunnel traffic out of the physical interface
#    (replace 10.20.0.0/24 with your tunnel subnet and eth0 with the WAN NIC)
sudo iptables -t nat -A POSTROUTING -s 10.20.0.0/24 -o eth0 -j MASQUERADE
```

### Notes and limitations

- Only **IPv4** is tunnelled; working host IPv6 can leak outside the tunnel.
- DNS is not modified — set a resolver separately if you want to avoid your ISP's.
- Full tunnel is a **client-only** setting; a server serves normal and full-tunnel peers
  simultaneously with no extra config beyond the host NAT above.

---

## Requirements & build

- **Go 1.26+** (stdlib `crypto/mlkem`, `crypto/hkdf`).
- **Linux.** `tunif` shells out to `ip` to configure the TUN device.
- **Root** (or `CAP_NET_ADMIN`) — to create the TUN device and run `ip link`.

Build the reference CLI:

```sh
go build -o ownvpn ./examples/sample_client
```

Cross-compile for ARMv7 (e.g. a router):

```sh
GOOS=linux GOARCH=arm GOARM=7 go build -o ownvpn_armv7 ./examples/sample_client
```

---

## Security notes & limitations

- **Post-quantum only, no hybrid.** Authentication and confidentiality rest entirely on
  ML-KEM-768. There is no classical (X25519/RSA) layer, so there is no fallback if a flaw
  is found in ML-KEM. This is a deliberate design choice, not an oversight.
- **No replay protection.** Data packets carry a random nonce but no sequence number or
  replay window; a captured ciphertext can be re-injected until the session key rotates.
- **No per-packet authentication of source beyond the session key.** Once a peer's UDP
  source address is bound during the handshake, data packets are trusted by address + AEAD.
- **Metadata.** Packet sizes and timing are not padded (beyond the 3 keepalive bytes);
  traffic analysis is possible.
- **Keys are plaintext** in the config structs/JSON — protect them at rest (file perms,
  secrets manager) yourself; ownvpn does not encrypt them.
- **Single server instance per process** (package-level state) — run multiple hubs in
  separate processes.

Treat ownvpn as a compact, auditable, from-scratch VPN for experimentation, self-hosting,
and post-quantum research — not (yet) as a hardened replacement for WireGuard in a
high-assurance production deployment.

---

## License

MIT — see [LICENSE](LICENSE).
