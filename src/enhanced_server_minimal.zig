//! Minimal Enhanced CNS Server to test ZQLite compilation
const std = @import("std");
const dns = @import("dns.zig");
const cache = @import("cache.zig");
const config = @import("config.zig");
const zqlite = @import("zqlite");

const log = std.log.scoped(.enhanced_cns);

pub const EnhancedServer = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    cache: cache.DNSCache,

    // Statistics
    queries_total: std.atomic.Value(u64),
    queries_failed: std.atomic.Value(u64),

    // Control
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config_path: ?[]const u8) !EnhancedServer {
        const cfg = try config.Config.loadFromFile(allocator, config_path);
        const dns_cache = try cache.DNSCache.init(allocator, cfg.cache_size);

        log.info("🚀 Enhanced CNS with ZQLite v0.4.0 ready!", .{});

        return EnhancedServer{
            .allocator = allocator,
            .config = cfg,
            .cache = dns_cache,
            .queries_total = std.atomic.Value(u64).init(0),
            .queries_failed = std.atomic.Value(u64).init(0),
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *EnhancedServer) void {
        self.cache.deinit();
        self.config.deinit();
    }

    pub fn start(self: *EnhancedServer) !void {
        self.running.store(true, .monotonic);
        log.info("✅ Enhanced CNS Server started with ZQLite v0.4.0 support!", .{});
    }

    pub fn stop(self: *EnhancedServer) void {
        self.running.store(false, .monotonic);
        log.info("🛑 Enhanced CNS Server stopped", .{});
    }

    /// Test ZQLite integration
    pub fn testZQLite(self: *EnhancedServer) !void {
        _ = self;

        const allocator = std.heap.page_allocator;

        // Test ZQLite connection
        const connection = try zqlite.db.Connection.init(allocator, .{
            .path = ":memory:",
            .encryption_key = null,
        });
        defer connection.deinit();

        // Test basic DNS cache table
        try connection.execute(
            \\CREATE TABLE dns_cache_test (
            \\    domain TEXT PRIMARY KEY,
            \\    ip_address TEXT,
            \\    ttl INTEGER,
            \\    timestamp INTEGER
            \\)
        );

        try connection.executeWithParams("INSERT INTO dns_cache_test (domain, ip_address, ttl, timestamp) VALUES (?, ?, ?, ?)", .{ "example.com", "93.184.216.34", 300, std.time.timestamp() });

        const result = try connection.queryWithParams("SELECT COUNT(*) as count FROM dns_cache_test WHERE domain = ?", .{"example.com"});
        defer result.deinit();

        log.info("🎯 ZQLite test successful! Found {d} records", .{result.rows.len});
    }
};
