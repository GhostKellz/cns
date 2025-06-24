# CNS — a cryptographic QUIC Name Server

`cns` is a blazing-fast, encrypted DNS server and resolver written in Zig with full QUIC (HTTP/3) support. It is designed for modern internet use, seamlessly integrating with zero-trust architectures, self-hosted networks, and next-gen systems like GhostMesh.

---

## 🌐 Features

* 🚀 **QUIC-native** DNS server for ultra-fast encrypted queries
* 🔐 **Built-in DNS-over-QUIC (DoQ)** support
* 🔁 **Forwarding, caching, and recursive resolver modes**
* 🌍 **IPv6-first** with fallback to IPv4
* 🧱 **Zig-powered performance and memory safety**
* 🔧 Configurable zone files or dynamic upstreams
* 🛰️ Compatible with GhostMesh VPN or standalone deployment
* 📦 Minimal binary footprint, embeddable as a module

---

## 🔧 Use Cases

* Secure DNS for self-hosted infrastructures
* Resolver for Zig/Rust-powered edge devices or embedded systems
* Drop-in DNS-over-QUIC layer for VPN tunnels (e.g., GhostMesh)
* On-prem authoritative or hybrid DNS + resolver
* Modern privacy-first DNS stack replacement for Unbound, dnsmasq, etc.

---

## 📦 Architecture Overview

```
       ┌─────────────┐       ┌──────────────┐
       │   zqnsd     │<----->│  GhostMesh   │
       │ (QUIC DNS) │       │   VPN Core   │
       └─────┬───────┘       └────┬─────────┘
             │                     │
     ┌───────▼────────┐     ┌─────▼──────────┐
     │ Resolver Core  │     │  Auth Zones    │
     │ Cache & Query  │     │ .cktechx.io    │
     └────────────────┘     └────────────────┘
```

---

## 🚧 Planned Extensions

* [ ] DNSSEC signing and validation
* [ ] Web interface / metrics via QUIC or gRPC
* [ ] Built-in support for DNS-over-HTTPS fallback
* [ ] GhostChain-backed DNS integrity proof

---

## 🚀 Quickstart (Prototype)

```sh
zig build run -- -c config.zqns.toml
```

Example config:

```toml
[server]
listen = "[::]:853"
mode = "recursive" # or "forward" or "authoritative"

[quic]
enable = true
certificate = "certs/fullchain.pem"
private_key = "certs/privkey.pem"

[upstream]
servers = ["9.9.9.9", "1.1.1.1"]
```

---

## 🛠 Goals

* Be the **default resolver** for Zig-powered mesh systems
* Replace traditional DNS daemons in containerized and embedded contexts
* Enable encrypted DNS in **airgapped, private**, or **hostile environments**

---

## 📜 License

MIT — Built with love for fast, open, and private networks.

---

## 🔗 Related Projects

* [GhostMesh](https://github.com/GhostKellz/ghostmesh) — VPN infrastructure
* [zigDNS](https://github.com/GhostKellz/zigDNS) — Local resolver stub
* [zcrypto](https://github.com/GhostKellz/zcrypto) — Cryptographic backend

---

## 👻 Authored by

**GhostKellz / CK Technology LLC**

