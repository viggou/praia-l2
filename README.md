# l2

Layer 2 raw ethernet frame access for [Praia](https://praia.sh). Provides raw socket operations at the ethernet level using AF_PACKET on Linux and BPF on macOS, plus helpers for building and parsing ethernet/ARP frames.

Requires root or `CAP_NET_RAW`.

## Installation

```sh
sand install github.com/viggou/praia-l2
```

Installs the `arp` grain as a transitive dependency.

## Usage

```praia
use "l2"

let sock = l2.open("en0")
l2.setTimeout(sock, 2000)

// Send a gratuitous ARP
let myMac = l2.mac("en0")
let frame = l2.ethFrame("ff:ff:ff:ff:ff:ff", myMac, 0x0806,
    l2.arpPacket(2, myMac, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "10.0.0.1"))
l2.send(sock, frame)

// Sniff frames
let data = l2.recv(sock)
let parsed = l2.parseFrame(data)
if (parsed) {
    print(parsed.src, "->", parsed.dst, "type:", parsed.etherType)
}

l2.close(sock)
```

## API

### Socket operations

| Function | Description |
|----------|-------------|
| `open(iface)` | Open a raw L2 socket bound to an interface |
| `send(sock, data)` | Send a raw ethernet frame (min 14 bytes) |
| `recv(sock)` | Receive a raw ethernet frame, returns nil on timeout |
| `close(sock)` | Close the socket |
| `setTimeout(sock, ms)` | Set receive timeout in milliseconds |
| `mac(iface)` | Get the MAC address of a local interface |

### Frame building

| Function | Description |
|----------|-------------|
| `ethFrame(dst, src, etherType, payload)` | Build a raw ethernet frame |
| `arpPacket(op, senderMac, senderIp, targetMac, targetIp)` | Build a 28-byte ARP packet (op: 1=request, 2=reply) |

### Frame parsing

| Function | Description |
|----------|-------------|
| `parseFrame(data)` | Parse into `{dst, src, etherType, payload}`, nil-safe |
| `parseArp(data)` | Parse ARP payload into `{op, senderMac, senderIp, targetMac, targetIp}`, nil-safe |

### Helpers

| Function | Description |
|----------|-------------|
| `resolve(ip)` | Resolve an IP to a MAC via the arp grain (pings first) |
| `macToBytes(mac)` | Convert `"aa:bb:cc:dd:ee:ff"` to bytes |
| `ipToBytes(ip)` | Convert `"192.168.1.1"` to bytes |
| `formatMac(arr)` | Convert a 6-element byte array to a MAC string |

## Building from source

```sh
make
```

Requires Praia's development headers (`praia --include-path`).

## Platform notes

- **Linux**: Uses `AF_PACKET` with `SOCK_RAW`. Requires root or `CAP_NET_RAW`.
- **macOS**: Uses BPF (`/dev/bpfN`). Requires root. BPF reads may return multiple packets per buffer read - currently only the first packet is extracted per `recv()` call. Call `recv()` in a loop for continuous capture.
