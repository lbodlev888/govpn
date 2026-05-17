# ownvpn

A minimal, post-quantum VPN written from scratch in Go. Peers talk over UDP through a
central hub server; all traffic is authenticated and encrypted with keys derived from a
ML-KEM-768 (FIPS 203) handshake. There is no classical key-exchange fallback — the
whole construction is post-quantum.

The codebase is intentionally small (one file per package) so it can be ported to other
platforms. This README documents the wire protocol and handshake precisely enough that
a client can be re-implemented from scratch in any other language for any other platform.

---

## Features

- **Post-quantum key exchange.** Two-message ML-KEM-768 handshake. Each side encapsulates
  to the other's static public key, so both ciphertexts contribute entropy to the final
  session secret. There is no Diffie–Hellman, no RSA, no X25519.
- **Mutual authentication.** The server only accepts peers whose `name` is listed in its
  config and whose static ML-KEM-768 public key matches. Decapsulation only succeeds for
  the holder of the matching private key, so the handshake authenticates both sides.
- **Authenticated encryption for data.** ChaCha20-Poly1305 AEAD on every data packet
  with a per-packet random 12-byte nonce. Tag length is 16 bytes (Poly1305 default).
- **HKDF key derivation.** Session key derived with HKDF-SHA256 from the concatenation
  of both shared secrets, salted with `nil` and using the protocol version string
  (e.g. `ownvpn0.0.3`) as the `info` parameter.
- **Hub topology with IP-based routing.** The server inspects the destination IPv4
  address of the decrypted inner packet and either delivers it to its own TUN interface
  or re-encrypts and forwards it to the matching peer.
- **Automatic re-handshake.** The client renegotiates the session key every 3 minutes,
  and immediately whenever encryption or decryption fails (so a corrupted/replayed
  packet does not poison the cipher state).
- **Keep-alive with SYN/ACK.** The client sends a 5-byte keepalive every 25 seconds to
  hold the NAT mapping open; the server responds with an ACK variant.
- **TUN interface.** Uses the `songgao/water` library to allocate a TUN device named
  `bvpn0`; the IP, subnet and MTU (1420) are configured with the `ip` command.
- **Stateless server reads.** UDP packets are dispatched by their first byte (message
  type) and the source address is used as the peer identity once the handshake is done.
- **Single static binary.** No external services, no certificate authority, no PKI;
  keys are 32-line base64 strings stored in a JSON config.
- **Cross-compilable.** A prebuilt `ownvpn_armv7` is checked in alongside the `ownvpn`
  Linux/amd64 binary.

---

## Repository layout

```
main.go        # CLI entrypoint, flags, config loading
client/        # peer-side loop: handshake, encrypt, decrypt, keepalive
server/        # hub: accepts handshakes, decrypts, routes by inner dst IP
crypto/        # ML-KEM-768 key import/export + HKDF-SHA256 derivation
proto/         # wire-format encoders/decoders + message-type constants
tunif/         # TUN device creation and `ip` configuration
config/        # JSON config structs for peer and server
models/        # Peer struct used by the server's routing table
```

---

## Wire protocol

All messages are sent as UDP datagrams. The first byte is always the **message type**.

| Code | Name            | Direction       | Length         |
|------|-----------------|-----------------|----------------|
| 0x01 | `ClientHello`   | client → server | `2 + nameLen + 1088` |
| 0x02 | `ServerHello`   | server → client | `1 + 1088`     |
| 0x03 | `Data`          | both            | `1 + 12 + ct`  |
| 0x04 | `KeepAlive`     | both            | `5`            |
| 0x05 | `KeepAliveSYN`  | (flag byte)     | n/a            |
| 0x06 | `KeepAliveACK`  | (flag byte)     | n/a            |

Constants:

- ML-KEM-768 ciphertext is fixed at **1088 bytes**.
- ML-KEM-768 shared secret is **32 bytes**.
- ChaCha20-Poly1305: **32-byte key**, **12-byte nonce**, **16-byte tag**.
- HKDF salt: empty (nil). HKDF info string: the protocol version, currently
  `"ownvpn0.0.3"` (literal ASCII, no trailing newline). Output length: 32 bytes.

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

The plaintext that goes in / comes out is a **raw IPv4 packet** as read from the TUN
device. The AEAD is called with `additionalData = nil`.

### KeepAlive (0x04)

```
+------+-------+-----------------+
| 0x04 | flag  | random 3 bytes  |
+------+-------+-----------------+
   1B    1B          3 B
```

`flag` is `0x05` (SYN) when sent by the client and `0x06` (ACK) when sent back by the
server. The 3 random bytes are padding to make passive traffic-analysis a little
harder; they are not validated.

---

## Handshake (read this if you're porting the client)

Each side owns a static ML-KEM-768 keypair. The handshake is **two messages** and
derives a fresh 32-byte ChaCha20-Poly1305 key every time.

Notation: `EK_x` = encapsulation (public) key of `x`, `DK_x` = decapsulation (private)
key of `x`. `Encaps(EK) -> (ss, ct)` returns a 32-byte shared secret and a 1088-byte
ciphertext. `Decaps(DK, ct) -> ss` recovers the same 32-byte shared secret.

### Step 1 — client builds and sends `ClientHello`

1. The client calls `Encaps(EK_server)` and gets `(ss1, ct1)`.
2. It builds `ClientHello { name, publicData = ct1 }` and encodes it per the wire
   format above (1 + 1 + nameLen + 1088 bytes).
3. It sends the datagram to the server's UDP endpoint.

### Step 2 — server processes `ClientHello`

1. Decodes the message; rejects if `name` is not in its `peers` config.
2. Looks up that peer's static public key `EK_client`.
3. Computes `ss1 = Decaps(DK_server, ct1)` — this is the same 32-byte secret the client
   has. Failure here means the client used the wrong server public key.
4. Computes `Encaps(EK_client) -> (ss2, ct2)`.
5. Derives `K = HKDF-SHA256(ikm = ss1 || ss2, salt = nil, info = "ownvpn0.0.3", L = 32)`.
6. Stores the peer keyed by both its UDP source address (for the data path) and its
   configured virtual IP (for the routing table). Any previous session for the same
   virtual IP is evicted.
7. Sends `ServerHello { publicData = ct2 }`.

### Step 3 — client processes `ServerHello`

1. Reads the response with a 1-second read deadline (so a lost packet doesn't wedge the
   client; on timeout the whole handshake is retried). The deadline is cleared after a
   successful read.
2. Verifies the source address matches the expected server endpoint.
3. Decodes `ServerHello`, then computes `ss2 = Decaps(DK_client, ct2)`. Failure here
   means the server used the wrong client public key.
4. Derives the **same** `K = HKDF-SHA256(ss1 || ss2, nil, "ownvpn0.0.3", 32)`.
5. Initializes ChaCha20-Poly1305 with `K`. Tunnel is now ready.

### Authentication property

Because `ss1` can only be recovered with `DK_server`, and `ss2` can only be recovered
with `DK_client`, only the legitimate holders of both private keys can derive `K`. An
attacker who has *one* of the two keys still cannot. There are no signatures and no
certificates — authentication is a side-effect of mutual key encapsulation.

### Re-handshake

The client re-runs the handshake when **any** of these happen:

- The 3-minute `HANDSHAKE_TIMEOUT` ticker fires.
- AEAD `Open` (decrypt) returns an error on a received data packet.
- `conn.WriteTo` fails when sending an encrypted data packet.

On a re-handshake the client clears its `aead` (so the reader/writer goroutines pause
on `aead == nil` until the new key is installed) and sends a fresh `ClientHello`. The
server treats a new `ClientHello` from any source as authoritative: if the same virtual
IP was already mapped to a different UDP address, the old mapping is dropped.

### Pseudocode (target Java/Android)

```text
// one-time
DK_client = load_private_key(peer.privkey)
EK_server = load_public_key(peer.pubkey)
serverAddr = resolve(peer.endpoint)
socket = DatagramSocket()                  // ephemeral local port

// handshake loop (runs once at startup, then every 180 s
// and on any cipher failure)
loop {
    (ss1, ct1) = MLKEM768.encaps(EK_server)

    send(socket, serverAddr,
         [0x01] || [len(name)] || name_bytes || ct1)        // 2+N+1088 B

    socket.setSoTimeout(1000)                                // 1 s
    (resp, src) = recv(socket, 2048)
    if src != serverAddr || resp[0] != 0x02
       || resp.length != 1 + 1088 { retry }

    ct2 = resp[1..1089]
    ss2 = MLKEM768.decaps(DK_client, ct2)

    ikm = ss1 || ss2                                          // 64 B
    K   = HKDF_SHA256(ikm, salt=null, info="ownvpn0.0.3", 32) // 32 B
    aead = ChaCha20Poly1305(K)
    handshake_done = true
    wait(min(180 s, until cipher_failure))
}

// data: TUN -> network
on_tun_packet(p):
    if !handshake_done: drop
    nonce = secure_random(12)
    ct    = aead.seal(nonce, plaintext=p, aad=null)           // tag is appended
    send(socket, serverAddr, [0x03] || nonce || ct)

// data: network -> TUN
on_udp_packet(buf, src):
    if src != serverAddr: drop
    if buf[0] == 0x04: handle_keepalive(buf); return
    if buf[0] != 0x03 || buf.length < 1+12+16: drop
    nonce = buf[1..13]
    ct    = buf[13..]
    try:
        pt = aead.open(nonce, ct, aad=null)
    catch:
        handshake_done = false                                // trigger rehandshake
        return
    tun.write(pt)

// keepalive (every 25 s while handshake_done)
send(socket, serverAddr, [0x04, 0x05, rnd, rnd, rnd])         // SYN
// expect [0x04, 0x06, rnd, rnd, rnd] (ACK) back
```

A few platform notes for Android:

- The `info` string passed to HKDF must match exactly what the server uses — it is the
  `OWNVPN_VERSION` constant in `main.go`. Keep it in sync when the server is upgraded.
- Use `java.security.SecureRandom` for the per-packet nonce. Do **not** use a counter
  — the server expects 12 random bytes and there is no replay window.
- ML-KEM-768 is in `java.security.KeyPairGenerator` as of JDK 24 (`"ML-KEM"`); on
  Android you'll likely need BouncyCastle (`bcprov` ≥ 1.78 exposes `MLKEM`).
- The TUN device on Android is provided by `VpnService` — the `ParcelFileDescriptor`
  it returns plays the role of the `iface` file in this codebase.

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

The server looks at bytes 16..19 of every decrypted inner packet (the IPv4 destination
address). If it equals the server's own virtual IP it is written to the local TUN; if
it matches a known peer's virtual IP it is re-sealed under that peer's session key and
sent to that peer's UDP address. Non-IPv4 packets (`version != 4`) are dropped.

---

## Requirements

- Go 1.26+ (uses the stdlib `crypto/mlkem` and `crypto/hkdf` packages).
- Linux. The `tunif` package shells out to `ip` to configure the TUN device.
- Root (or `CAP_NET_ADMIN`) — needed to create the TUN device and run `ip link`.

## Build

```sh
go build -o ownvpn .
```

Cross-compile for ARMv7 (e.g. a router):

```sh
GOOS=linux GOARCH=arm GOARM=7 go build -o ownvpn_armv7 .
```

## Key generation

Generate a private key, then derive its public key:

```sh
./ownvpn -genkey
./ownvpn -pubkey <private-key>
```

Both are printed as base64. Every peer and the server need their own keypair. The
private key is the full ML-KEM-768 decapsulation key (seed-expanded form).

## Configuration

Configuration is a JSON file passed with `-config`.

**Peer (client):**

```json
{
  "name": "archlinux",
  "privkey": "<this peer's private key>",
  "pubkey":  "<server's public key>",
  "virtual_ip": "10.20.0.3",
  "subnet": 24,
  "endpoint": "203.0.113.10:62789"
}
```

**Server:**

```json
{
  "privkey": "<server's private key>",
  "bind_address": "0.0.0.0:62789",
  "virtual_ip": "10.20.0.1",
  "subnet": 24,
  "peers": [
    {
      "name": "archlinux",
      "pubkey": "<peer's public key>",
      "virtual_ip": "10.20.0.3",
      "subnet": 24
    }
  ]
}
```

The server only accepts peers listed in `peers`, matched by `name`. Keep private keys
out of version control.

## Usage

Start the server:

```sh
sudo ./ownvpn -server -config server.json
```

Start a client:

```sh
sudo ./ownvpn -config peer.json
```

Once connected, peers can reach each other over the `virtual_ip` addresses on the
configured subnet.
