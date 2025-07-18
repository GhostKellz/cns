//! Enhanced CNS Server with ZQLite v1.2.0, zcrypto, ghostnet, and zquic
//! Refactored to use zcrypto for crypto operations instead of shroud for crypto
//! Now leveraging Shroud for QUIC-based DID identity and security platform
const std = @import("std");
const zcrypto = @import("zcrypto");
const ghostnet = @import("ghostnet");
const zquic = @import("zquic");
const shroud = @import("shroud"); // For identity and security features
const dns = @import("dns.zig");
const cache = @import("cache.zig");
const config = @import("config.zig");
const database = @import("database.zig");
const identity_manager = @import("identity_manager.zig");
const zqlite = @import("zqlite");

const log = std.log.scoped(.enhanced_cns);

pub const EnhancedServer = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    cache: cache.DNSCache,
    database: ?*database.Database,
    identity_mgr: ?identity_manager.CNSIdentityManager,

    // Network components using ghostnet and zquic (simplified for now)
    tcp_listener: ?std.net.Server,
    udp_socket: ?std.net.Server,
    quic_server: ?*zquic.Http3.Http3Server,

    // Shroud identity and security components (deprecated - moved to identity_mgr)
    identity_manager: ?*shroud.IdentityManager,
    cross_chain_resolver: ?*shroud.CrossChainResolver,
    guardian: ?*shroud.Guardian,

    // Statistics
    queries_total: std.atomic.Value(u64),
    queries_failed: std.atomic.Value(u64),
    queries_blockchain: std.atomic.Value(u64),
    queries_http3: std.atomic.Value(u64),

    // Control
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config_path: ?[]const u8) !EnhancedServer {
        const cfg = try config.Config.loadFromFile(allocator, config_path);
        const dns_cache = try cache.DNSCache.init(allocator, cfg.cache_size);

        // Initialize database with ZQLite v1.2.0
        const db = try database.Database.init(allocator, .{
            .db_path = "cns.db",
            .encryption_key = "cns_default_key_change_in_production",
            .enable_analytics = true,
        });

        log.info("🚀 Enhanced CNS with ZQLite v1.2.0, zcrypto, ghostnet, and zquic ready!", .{});

        return EnhancedServer{
            .allocator = allocator,
            .config = cfg,
            .cache = dns_cache,
            .database = db,
            .identity_mgr = null,
            .tcp_listener = null,
            .udp_socket = null,
            .quic_server = null,
            .identity_manager = null,
            .cross_chain_resolver = null,
            .guardian = null,
            .queries_total = std.atomic.Value(u64).init(0),
            .queries_failed = std.atomic.Value(u64).init(0),
            .queries_blockchain = std.atomic.Value(u64).init(0),
            .queries_http3 = std.atomic.Value(u64).init(0),
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *EnhancedServer) void {
        self.stop();
        
        // Clean up identity manager
        if (self.identity_mgr) |*mgr| {
            mgr.deinit();
        }
        
        if (self.database) |db| {
            db.deinit();
        }
        
        self.cache.deinit();
        self.config.deinit();
    }

    pub fn start(self: *EnhancedServer) !void {
        self.running.store(true, .monotonic);
        
        // Initialize comprehensive identity management system
        try self.initializeIdentitySystem();
        
        // Test identity-aware resolution
        try self.testIdentityResolution();
        
        // Initialize networking components
        try self.initializeNetworking();
        
        log.info("✅ Enhanced CNS Server started with ZQLite v1.2.0, zcrypto, ghostnet, zquic, and Shroud identity!", .{});
    }

    pub fn stop(self: *EnhancedServer) void {
        self.running.store(false, .monotonic);
        
        // Stop networking components
        if (self.tcp_listener) |*listener| {
            listener.deinit();
        }
        
        if (self.udp_socket) |*socket| {
            socket.deinit();
        }
        
        if (self.quic_server) |server| {
            server.deinit();
        }
        
        log.info("🛑 Enhanced CNS Server stopped", .{});
    }

    /// Initialize networking components using std.net and zquic (simplified)
    fn initializeNetworking(self: *EnhancedServer) !void {
        // Use unprivileged ports for testing (53 requires root)
        const tcp_address = std.net.Address.parseIp("127.0.0.1", 5353) catch |err| {
            log.err("Failed to parse TCP address: {}", .{err});
            return err;
        };
        
        self.tcp_listener = tcp_address.listen(.{ .reuse_address = true }) catch |err| {
            log.err("Failed to create TCP listener: {}", .{err});
            return err;
        };
        
        // Initialize UDP "listener" on port 5353 (for demonstration)
        const udp_address = std.net.Address.parseIp("127.0.0.1", 5354) catch |err| {
            log.err("Failed to parse UDP address: {}", .{err});
            return err;
        };
        
        self.udp_socket = udp_address.listen(.{ .reuse_address = true }) catch |err| {
            log.err("Failed to create UDP socket: {}", .{err});
            return err;
        };
        
        // TODO: Initialize zquic HTTP/3 server for DNS-over-QUIC when API is stable
        // For now, just log that it would be initialized
        log.info("🌐 Networking components initialized (TCP:5353, UDP:5354 + planned zquic HTTP/3)", .{});
    }

    /// Initialize comprehensive identity management system
    fn initializeIdentitySystem(self: *EnhancedServer) !void {
        log.info("🆔 Initializing CNS Identity Management System...", .{});
        
        // Get database connection from our database wrapper
        if (self.database) |db| {
            // Initialize the comprehensive identity manager
            const identity_mgr = try identity_manager.CNSIdentityManager.init(self.allocator, db.connection);
            self.identity_mgr = identity_mgr;
            
            log.info("🛡️  CNS Identity Manager initialized successfully!", .{});
            log.info("🔐 Ready for identity-aware DNS resolution with QUIC-based DIDs", .{});
            log.info("� Supporting Web3 domains, traditional DNS, and cross-chain identity", .{});
            log.info("� QID-based identity verification enabled", .{});
        } else {
            log.err("❌ Database not initialized - cannot start identity system", .{});
            return error.DatabaseNotInitialized;
        }
    }

    /// Test ZQLite v1.2.0 integration and zcrypto functionality
    pub fn testZQLite(self: *EnhancedServer) !void {
        // Test ZQLite v1.2.0 connection (new API)
        var conn = try zqlite.Connection.openMemory();
        defer conn.deinit();

        // Test basic DNS cache table creation
        try conn.execute(
            \\CREATE TABLE dns_cache_test (
            \\    domain TEXT PRIMARY KEY,
            \\    ip_address TEXT,
            \\    ttl INTEGER,
            \\    timestamp INTEGER DEFAULT (strftime('%s','now'))
            \\)
        );

        // Insert test data using the new simplified API
        try conn.execute("INSERT INTO dns_cache_test (domain, ip_address, ttl) VALUES ('example.com', '93.184.216.34', 300)");

        // Query test data
        try conn.execute("SELECT COUNT(*) as count FROM dns_cache_test WHERE domain = 'example.com'");

        log.info("🎯 ZQLite v1.2.0 test successful! Database operations working with new API", .{});
        
        // Test zcrypto functionality
        try self.testCrypto();
    }

    /// Test zcrypto cryptographic operations
    fn testCrypto(self: *EnhancedServer) !void {
        _ = self;
        
        // Test SHA-256 hashing
        const test_data = "Hello, CNS with zcrypto!";
        var hash_output: [32]u8 = undefined;
        zcrypto.hash.sha256(&hash_output, test_data);
        
        log.info("🔐 zcrypto SHA-256 test successful! Hash: {x}", .{std.fmt.fmtSliceHexLower(&hash_output)});
        
        // Test random number generation
        var random_bytes: [16]u8 = undefined;
        try zcrypto.random.fill(&random_bytes);
        
        log.info("🎲 zcrypto random generation test successful! Bytes: {x}", .{std.fmt.fmtSliceHexLower(&random_bytes)});
    }

    /// Resolve DNS query with identity verification and QUIC-based DID support
    pub fn resolveWithIdentity(self: *EnhancedServer, domain: []const u8, client_qid: ?[]const u8) !identity_manager.DNSResolutionResult {
        if (self.identity_mgr) |*mgr| {
            return try mgr.resolveWithIdentity(domain, client_qid);
        } else {
            return error.IdentitySystemNotInitialized;
        }
    }
    
    /// Test the identity-aware resolution system
    pub fn testIdentityResolution(self: *EnhancedServer) !void {
        log.info("🧪 Testing CNS Identity-Aware DNS Resolution...", .{});
        
        // Test traditional domain
        const result1 = try self.resolveWithIdentity("example.com", null);
        log.info("📡 Traditional: {} - Trust: {}", .{ result1.resolved, result1.trust_level });
        
        // Test Web3 domain  
        const result2 = try self.resolveWithIdentity("vitalik.eth", null);
        log.info("🌐 Web3: {} - Trust: {}", .{ result2.resolved, result2.trust_level });
        
        // Test with client QID
        const result3 = try self.resolveWithIdentity("secure.example", "fd00:1234:5678:9abc:def0:1234:5678:9abc");
        log.info("🔐 With QID: {} - Trust: {}", .{ result3.resolved, result3.trust_level });
        
        log.info("✅ Identity resolution tests completed!", .{});
    }
};
