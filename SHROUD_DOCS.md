# 🕸️ Shroud Framework Documentation

> A high-performance, zero-trust cryptographic and network framework for Ghostchain and the Web5 ecosystem.

---

## Overview

**Shroud v1.0** is a modular framework that bridges **Web2 protocols (DNS, HTTP3, QUIC)** with **Web3 primitives (DIDs, ZNS, QID, cryptographic identity)**. It provides secure, verifiable, high-speed communication over modern internet infrastructure and powers key components of the **Ghostchain** protocol stack.

## Architecture

Shroud follows a modular architecture where each module can be used independently or together as a unified framework. The framework is built in Zig and designed for high performance and security.

### Core Philosophy

- **Zero-Trust**: Every operation requires cryptographic verification
- **Modular**: Each component can be used independently
- **High-Performance**: Optimized for speed and low latency
- **Web5-Ready**: Bridges traditional and decentralized protocols
- **Post-Quantum Ready**: Built with future cryptographic standards in mind

---

## Module Architecture

Shroud consists of 8 core modules organized into three tiers:

### Foundation Tier
- **`ghostcipher`** - Cryptographic primitives and post-quantum crypto
- **`sigil`** - Identity resolution and zero-trust authentication

### Network Tier  
- **`ghostwire`** - Complete networking stack (QUIC, HTTP/1-3, WebSocket, gRPC, IPv6)
- **`zns`** - Decentralized domain name system

### Application Tier
- **`keystone`** - Transaction ledger and state management
- **`shadowcraft`** - Identity enforcement and zero-trust logic
- **`guardian`** - Multi-signature and access control
- **`covenant`** - Smart contract policy engine
- **`gwallet`** - GhostWallet: Secure programmable wallet with RealID integration

---

## Core Modules

### 🔐 GhostCipher
*Advanced cryptographic primitives*

GhostCipher provides the cryptographic foundation for Shroud, including:

- **ZCrypto**: Core cryptographic operations (AES, ChaCha20, Ed25519, secp256k1)
- **ZSig**: Digital signature framework with multiple algorithm support
- **Post-Quantum**: ML-KEM and other PQ-ready algorithms
- **Protocols**: Noise, Signal, MLS protocol implementations
- **Hardware Acceleration**: Assembly optimizations for x86_64 and AArch64

**Key Features:**
- Zero-allocation crypto operations where possible
- Constant-time implementations
- Hardware acceleration support
- Comprehensive test vectors
- FFI bindings for C interoperability

### 🆔 Sigil
*Zero-trust identity framework (formerly RealID)*

Sigil handles identity creation, resolution, and verification:

- **Identity Generation**: Deterministic keypair generation from passphrases
- **QID System**: IPv6-based identity addressing
- **Device Fingerprinting**: Hardware-based device identification
- **Digital Signatures**: Ed25519-based signing and verification
- **Legacy Compatibility**: Maintains RealID API compatibility

**Key Features:**
- Deterministic identity generation
- IPv6-native addressing (QID)
- Device-specific fingerprinting
- Cross-platform compatibility
- Zero-trust verification

### 🌐 GhostWire
*Complete networking stack*

GhostWire provides comprehensive networking capabilities:

- **QUIC/HTTP3**: Modern high-performance web protocols
- **HTTP/1.1 & HTTP/2**: Traditional web protocol support
- **WebSocket**: Real-time bidirectional communication
- **gRPC**: High-performance RPC framework
- **IPv6**: First-class IPv6 support with auto-discovery
- **Reverse Proxy**: Load balancing and traffic management

**Key Features:**
- Unified server supporting multiple protocols
- Zero-configuration IPv6 setup
- Multicast service discovery
- TLS 1.3 and post-quantum handshakes
- Built-in reverse proxy and load balancing

### 🏗️ Keystone
*Advanced ledger engine (evolved from Zledger)*

Keystone manages financial transactions and state:

- **Double-Entry Accounting**: Professional-grade ledger system
- **Crypto Integration**: Secure transaction signing and verification
- **Audit Trail**: Comprehensive transaction tracking
- **Fixed-Point Math**: Precise financial calculations
- **Wallet Integration**: HD wallet and multi-signature support

**Key Features:**
- Double-entry bookkeeping compliance
- Cryptographically signed transactions
- Real-time audit capabilities
- Integration with hardware wallets
- Multi-currency support

### 🕯️ ZNS
*Decentralized name system*

ZNS provides decentralized domain resolution:

- **Universal Resolution**: ENS, Unstoppable Domains, .ghost domains
- **Caching**: SQLite-based resolution caching
- **QUIC Integration**: High-speed resolution over QUIC
- **Ghost Domains**: Native .ghost/.bc/.gcc/.sig domain support
- **CLI Tools**: Command-line domain management

**Key Features:**
- Multi-protocol domain resolution
- Intelligent caching system
- IPv6-native resolution
- Integration with traditional DNS
- Extensible resolver architecture

### 🥷 ShadowCraft
*Identity enforcement and zero-trust logic*

ShadowCraft implements runtime identity verification:

- **AuthContext**: Request-level identity verification
- **Policy Engine**: Rule-based access control
- **Zero-Trust Enforcement**: Continuous verification
- **Session Management**: Secure session handling

### 🛡️ Guardian
*Multi-signature and access control*

Guardian provides advanced access control:

- **Multi-Signature**: M-of-N signature schemes
- **Role-Based Access**: Hierarchical permission systems
- **Watchdog Functions**: Automated security monitoring
- **Threshold Schemes**: Distributed key management

### 📜 Covenant
*Smart contract policy engine*

Covenant handles conditional validation:

- **Policy Rules**: Declarative security policies
- **Contract Validation**: Smart contract rule enforcement
- **Conditional Logic**: Complex validation scenarios
- **Integration Hooks**: Pluggable validation system

### 👻 GWallet (GhostWallet)
*Secure programmable wallet with Sigil identity integration*

GhostWallet provides comprehensive wallet functionality:

- **Identity Integration**: Built on Sigil identity framework
- **Multi-Protocol Support**: Bitcoin, Ethereum, Ghostchain, and custom chains
- **HD Wallet**: Hierarchical deterministic key management
- **Web3 Bridge**: dApp integration via HTTP/WebSocket bridge
- **Command-Line Interface**: Full-featured CLI for wallet operations
- **FFI Support**: C/Rust integration for blockchain services

**Key Features:**
- Deterministic wallet generation from passphrases
- QID-based network addressing
- Encrypted storage with Sigil signatures
- Multi-signature transaction support
- Bridge mode for dApp integration
- CLI with comprehensive wallet operations

---

## Integration Patterns

### Basic Integration
```zig
const shroud = @import("shroud");

// Use individual modules
const identity = try shroud.sigil.realid_generate_from_passphrase("secure_passphrase");
const signature = try shroud.sigil.realid_sign("data", identity.private_key);

// Networking
var server = try shroud.ghostwire.createUnifiedServer(allocator, config);
try server.start();
```

### Advanced Integration
```zig
// Multi-module integration
const crypto_config = shroud.ghostcipher.zcrypto.CryptoConfig{
    .algorithm = .chacha20_poly1305,
    .key_derivation = .argon2id,
};

const network_config = shroud.ghostwire.unified.UnifiedServerConfig{
    .http1_port = 8080,
    .http2_port = 8443,
    .quic_port = 443,
    .enable_grpc = true,
    .enable_websocket = true,
};

// Create integrated services
var unified_server = try shroud.ghostwire.createUnifiedServer(allocator, network_config);
var ledger = try shroud.keystone.Ledger.init(allocator);
var identity_resolver = try shroud.zns.resolver.UniversalResolver.init(allocator);
```

---

## Security Model

### Zero-Trust Architecture
- Every request requires cryptographic verification
- No implicit trust between components
- Continuous identity verification
- Minimal privilege principles

### Cryptographic Guarantees
- All data encrypted at rest and in transit
- Digital signatures on all transactions
- Post-quantum cryptographic readiness
- Hardware security module support

### Network Security
- TLS 1.3 with perfect forward secrecy
- QUIC transport encryption
- IPv6 security extensions
- DDoS protection mechanisms

---

## Performance Characteristics

### Benchmarks
- **QUIC Connections**: 100k+ concurrent connections
- **Cryptographic Operations**: Hardware-accelerated when available
- **Memory Usage**: Zero-allocation critical paths
- **Latency**: Sub-millisecond local operations

### Optimization Features
- Assembly-level optimizations for crypto operations
- SIMD acceleration where available
- Lock-free data structures
- Async I/O throughout

---

## Compatibility

### Language Bindings
- **Native**: Zig (primary)
- **C/C++**: Complete FFI bindings
- **Rust**: Experimental bindings (see archived/zquic/bindings/rust/)
- **Future**: Python, Go, JavaScript planned

### Platform Support
- **Linux**: Full support (x86_64, AArch64)
- **macOS**: Full support
- **Windows**: Planned
- **Embedded**: RISC-V support planned

### Protocol Compatibility
- **IPv4/IPv6**: Dual-stack support
- **HTTP**: 1.1, 2.0, 3.0 support
- **TLS**: 1.2, 1.3 support
- **QUIC**: RFC 9000 compliant
- **DNS**: Traditional and decentralized

---

## Dependencies

Shroud is designed to minimize external dependencies:

### Core Dependencies
- **Zig Standard Library**: Core functionality
- **SQLite3**: ZNS caching (optional)
- **OpenSSL/BoringSSL**: Fallback crypto (optional)

### Optional Dependencies
- **Hardware HSM**: For enhanced security
- **GPU Acceleration**: For ML-KEM operations
- **Custom Allocators**: For specialized use cases

---

## Version History

### v1.0.0 (Current)
- Complete modular architecture
- Production-ready networking stack
- Post-quantum cryptography support
- Unified API across all modules
- Comprehensive documentation

### Legacy Versions
- Individual component libraries (zcrypto, zquic, zsig, zns, etc.)
- Proof-of-concept implementations
- Research and development phases

---

## Related Projects

Shroud powers and integrates with:

- **Ghostchain**: Primary blockchain implementation
- **GhostWallet**: Secure programmable wallet (integrated as gwallet module)  
- **GhostBridge**: Cross-chain bridge protocol
- **Wraith**: Privacy-enhanced communication layer
- **ZVM**: Zero-knowledge virtual machine

---

## License

Shroud is released under multiple licenses depending on the component. See individual module LICENSE files for details.

## Support

For technical support and community:
- **Documentation**: This file and module-specific docs
- **Examples**: See `examples/` directories in each module
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions

---

*Shroud v1.0 - Building the foundation for Web5*
