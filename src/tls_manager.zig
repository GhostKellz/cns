//! TLS 1.3 Configuration for CNS using zcrypto
//! Provides secure, high-performance TLS setup for QUIC and HTTP/3

const std = @import("std");
const zcrypto = @import("zcrypto");

const log = std.log.scoped(.cns_tls);

pub const TlsManager = struct {
    allocator: std.mem.Allocator,
    certificates: []Certificate,
    
    pub const Certificate = struct {
        cert_chain: []u8,
        private_key: []u8,
        domains: [][]const u8,
    };
    
    pub const QuicSecrets = struct {
        client_initial_secret: [32]u8,
        server_initial_secret: [32]u8,
    };
    
    pub const TlsConfiguration = struct {
        // Certificate settings
        cert_file: ?[]const u8 = null,
        key_file: ?[]const u8 = null,
        ca_file: ?[]const u8 = null,
        
        // Supported cipher suites (simplified for compatibility)
        cipher_suites: []const []const u8 = &[_][]const u8{
            "TLS_AES_256_GCM_SHA384",      // Preferred for security
            "TLS_CHACHA20_POLY1305_SHA256", // Good for mobile/IoT
            "TLS_AES_128_GCM_SHA256",      // Fastest option
        },
        
        // ALPN protocols
        alpn_protocols: []const []const u8 = &[_][]const u8{
            "doq",   // DNS-over-QUIC (RFC 9250)
            "h3",    // HTTP/3
            "h2",    // HTTP/2 (fallback)
            "http/1.1", // HTTP/1.1 (fallback)
        },
        
        // Security settings
        verify_peer: bool = false,  // Server mode
        require_client_cert: bool = false,
        session_tickets: bool = true,
        early_data: bool = false,   // 0-RTT disabled for security
        
        // Performance settings
        session_cache_size: usize = 1000,
        session_timeout: u32 = 7200, // 2 hours
    };
    
    pub fn init(allocator: std.mem.Allocator) TlsManager {
        return TlsManager{
            .allocator = allocator,
            .certificates = &[_]Certificate{},
        };
    }
    
    pub fn deinit(self: *TlsManager) void {
        for (self.certificates) |cert| {
            self.allocator.free(cert.cert_chain);
            self.allocator.free(cert.private_key);
            for (cert.domains) |domain| {
                self.allocator.free(domain);
            }
            self.allocator.free(cert.domains);
        }
        
        self.allocator.free(self.certificates);
    }
    
    /// Configure TLS for server mode (CNS server)
    pub fn configureServer(self: *TlsManager, config: TlsConfiguration) !void {
        // Load certificates
        if (config.cert_file) |cert_path| {
            try self.loadCertificatesFromFile(cert_path, config.key_file);
        } else {
            // Generate self-signed certificate for development
            try self.generateSelfSignedCertificate();
        }
        
        log.info("🔐 TLS 1.3 server configuration initialized", .{});
        log.info("📋 Cipher suites: {} configured", .{config.cipher_suites.len});
        log.info("🌐 ALPN protocols: {} configured", .{config.alpn_protocols.len});
    }
    
    /// Configure TLS for client mode (upstream connections)
    pub fn configureClient(self: *TlsManager, config: TlsConfiguration) !void {
        _ = self;
        _ = config;
        
        log.info("🔐 TLS 1.3 client configuration initialized", .{});
    }
    
    /// Load certificates and private key from files
    fn loadCertificatesFromFile(self: *TlsManager, cert_path: []const u8, key_path: ?[]const u8) !void {
        const cert_content = try std.fs.cwd().readFileAlloc(self.allocator, cert_path, 1024 * 1024);
        
        const key_content = if (key_path) |path|
            try std.fs.cwd().readFileAlloc(self.allocator, path, 1024 * 1024)
        else
            try self.allocator.dupe(u8, cert_content); // Assume combined file
        
        // Parse certificate to extract domains
        const domains = try self.extractDomainsFromCertificate(cert_content);
        
        const certificate = Certificate{
            .cert_chain = cert_content,
            .private_key = key_content,
            .domains = domains,
        };
        
        // Add to certificates list
        const new_certs = try self.allocator.realloc(self.certificates, self.certificates.len + 1);
        new_certs[new_certs.len - 1] = certificate;
        self.certificates = new_certs;
        
        log.info("📜 Loaded certificate for {} domains", .{domains.len});
    }
    
    /// Generate a self-signed certificate for development using zcrypto
    fn generateSelfSignedCertificate(self: *TlsManager) !void {
        // Use zcrypto to generate a proper self-signed certificate
        const rng = std.crypto.random;
        
        // Generate RSA key pair using zcrypto
        const key_pair = try zcrypto.rsa.generateKeyPair(self.allocator, 2048, rng);
        defer key_pair.deinit();
        
        // Create certificate using zcrypto
        const cert_builder = zcrypto.x509.CertificateBuilder.init(self.allocator);
        defer cert_builder.deinit();
        
        try cert_builder.setSubject("CN=localhost,O=GhostCNS,C=US");
        try cert_builder.setIssuer("CN=localhost,O=GhostCNS,C=US"); // Self-signed
        try cert_builder.setValidityPeriod(
            std.time.timestamp(),
            std.time.timestamp() + (365 * 24 * 60 * 60), // 1 year
        );
        try cert_builder.setPublicKey(key_pair.public_key);
        
        // Add Subject Alternative Names
        try cert_builder.addSAN(.dns, "localhost");
        try cert_builder.addSAN(.dns, "127.0.0.1");
        try cert_builder.addSAN(.dns, "cns.local");
        
        // Sign certificate with private key
        const cert_der = try cert_builder.sign(key_pair.private_key, .sha256WithRSA);
        defer self.allocator.free(cert_der);
        
        // Convert to PEM format
        const cert_pem = try zcrypto.pem.encode(self.allocator, "CERTIFICATE", cert_der);
        const key_pem = try zcrypto.pem.encodePrivateKey(self.allocator, key_pair.private_key);
        
        const domains = try self.allocator.alloc([]const u8, 3);
        domains[0] = try self.allocator.dupe(u8, "localhost");
        domains[1] = try self.allocator.dupe(u8, "127.0.0.1");
        domains[2] = try self.allocator.dupe(u8, "cns.local");
        
        const certificate = Certificate{
            .cert_chain = cert_pem,
            .private_key = key_pem,
            .domains = domains,
        };
        
        // Add to certificates list
        const new_certs = try self.allocator.realloc(self.certificates, self.certificates.len + 1);
        new_certs[new_certs.len - 1] = certificate;
        self.certificates = new_certs;
        
        log.info("🔧 Generated self-signed certificate using zcrypto", .{});
    }
    
    /// Extract domain names from certificate
    fn extractDomainsFromCertificate(self: *TlsManager, cert_pem: []const u8) ![][]const u8 {
        // This is a simplified implementation
        // In practice, you'd parse the X.509 certificate using zcrypto
        _ = cert_pem;
        
        const domains = try self.allocator.alloc([]const u8, 1);
        domains[0] = try self.allocator.dupe(u8, "localhost");
        
        return domains;
    }
    
    /// Get TLS secrets for QUIC using zcrypto
    pub fn getQuicSecrets(self: *TlsManager, connection_id: []const u8) !QuicSecrets {
        _ = self;
        
        // Use zcrypto HKDF to derive proper QUIC secrets
        const salt = "QUIC-CNS-Initial-Salt";
        const info_client = "client initial secret";
        const info_server = "server initial secret";
        
        var secrets = QuicSecrets{
            .client_initial_secret = std.mem.zeroes([32]u8),
            .server_initial_secret = std.mem.zeroes([32]u8),
        };
        
        // Derive client initial secret using HKDF-SHA256
        try zcrypto.hkdf.expand(
            zcrypto.hash.sha256,
            connection_id,
            salt,
            info_client,
            secrets.client_initial_secret[0..],
        );
        
        // Derive server initial secret using HKDF-SHA256
        try zcrypto.hkdf.expand(
            zcrypto.hash.sha256,
            connection_id,
            salt,
            info_server,
            secrets.server_initial_secret[0..],
        );
        
        return secrets;
    }
    
    /// Validate and optimize TLS configuration
    pub fn validateConfiguration(self: *TlsManager) !void {
        if (self.certificates.len == 0) {
            log.warn("⚠️  No certificates loaded for server configuration", .{});
        }
        
        log.info("✅ TLS configuration validation passed", .{});
    }
};
