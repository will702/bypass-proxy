# bypass-proxy

A lightweight, zero-VPS anti-censorship proxy and tunnel tool written in Go, specifically designed to bypass **DNS hijacking** and **SNI Deep Packet Inspection (DPI)** used by Indonesian ISPs (Indihome, Telkomsel, Biznet, XL, MyRepublic, FirstMedia) under the **Kominfo / TrustPositif / Internet Sehat** blocklist.

---

## 🎯 How It Works

Censorship in Indonesia works at two stages:
1. **DNS Redirection**: Plain DNS queries (port 53 UDP/TCP) are intercepted by ISP transparent DNS proxies and redirected to TrustPositif/Internet Sehat IP addresses.
2. **SNI Deep Packet Inspection (DPI)**: Even if you use encrypted DNS, when your browser starts a TLS handshake with a blocked server (e.g. `reddit.com`), the ISP's DPI hardware inspects the unencrypted `Server Name Indication` (SNI) extension in the `ClientHello` packet and injects a TCP `RST` to terminate the connection.

### The Bypass Technique
- **Encrypted DNS-over-HTTPS (DoH)**: Resolves real IP addresses directly from Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) over HTTPS, completely circumventing ISP DNS interception.
- **TLS ClientHello / SNI Fragmentation**: Splits the initial TLS `ClientHello` packet across multiple TCP segments right in the middle of the SNI domain name. Because ISP DPI middleboxes do not perform full stateful TCP stream reassembly on high-speed transit lines, they fail to detect the blocked domain name. The destination web server's TCP stack reassembles the segments normally, completing the HTTPS handshake without interference.
- **Zero Remote VPS Needed**: Runs 100% locally on your machine. You get your ISP's full connection speed with zero latency penalty and zero monthly hosting costs.

---

## 🚀 Quick Start

### 1. Build & Install Globally
```bash
# Build and install to ~/.local/bin/bypass-proxy
make install

# Or build locally in the directory:
make build
```

### 2. Run from Anywhere
Since `~/.local/bin` is in your `$PATH`, you can now run it from any directory:
```bash
bypass-proxy
```
By default:
- HTTP/HTTPS Proxy runs at `127.0.0.1:8080`
- SOCKS5 Proxy runs at `127.0.0.1:1080`
- Automatically configures macOS system proxy on start and restores it cleanly on `Ctrl+C`.

---

## ⚙️ CLI Options

| Flag | Default | Description |
|---|---|---|
| `-http-port` | `8080` | Port for the HTTP/HTTPS forward proxy |
| `-socks-port` | `1080` | Port for the SOCKS5 proxy |
| `-bind` | `127.0.0.1` | Local address to bind listeners |
| `-strategy` | `sni` | Fragmentation strategy: `sni` (split middle of hostname), `early` (split first 2 bytes), or `multi` |
| `-delay` | `5` | Micro-delay in milliseconds between fragmented TCP packets |
| `-doh` | `https://1.1.1.1/...` | Comma-separated list of DoH resolver endpoints |
| `-sysproxy` | `true` | Automatically toggle macOS system proxy (`networksetup`) |
| `-test` | `false` | Run connectivity self-test against blocked sites |

---

## 🧪 Verification & Usage Examples

### Run Self-Test
```bash
./bypass-proxy -test
```

### Test with `curl`
```bash
curl -x http://127.0.0.1:8080 -I https://www.reddit.com
```

### Use in Terminal / Shell
```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export all_proxy=socks5://127.0.0.1:1080
```

### Use with Git
```bash
git config --global http.proxy http://127.0.0.1:8080
git config --global https.proxy http://127.0.0.1:8080
```

---

## 🛑 Stopping & Restoring Settings
Press `Ctrl+C` in the terminal where `bypass-proxy` is running. The built-in signal handler will automatically disable the system proxy and restore your standard network settings.
