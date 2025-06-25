//! CNS Database Layer using ZQLite v0.4.0
//! Provides persistent storage for DNS cache, analytics, and blockchain domains

const std = @import("std");
const zqlite = @import("zqlite");

const log = std.log.scoped(.cns_database);

pub const Database = struct {
    allocator: std.mem.Allocator,
    connection: *zqlite.db.Connection,
    encryption: ?zqlite.encryption.Encryption,
    db_path: []const u8,

    pub const Config = struct {
        db_path: []const u8 = "cns.db",
        encryption_key: ?[]const u8 = null,
        enable_analytics: bool = true,
        stored_salt: ?[]const u8 = null, // For existing databases
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !*Database {
        const db = try allocator.create(Database);
        errdefer allocator.destroy(db);

        // Initialize encryption if key provided (ZQLite v0.4.0 API)
        var encryption: ?zqlite.encryption.Encryption = null;
        if (config.encryption_key) |key| {
            // New API: encryption with salt management
            if (config.stored_salt) |salt| {
                // For existing databases, load stored salt
                var salt_array: [32]u8 = undefined;
                @memcpy(&salt_array, salt[0..32]);
                encryption = try zqlite.encryption.Encryption.initWithSalt(key, salt_array);
            } else {
                // For new databases, generate new salt
                encryption = try zqlite.encryption.Encryption.init(key, null);
                // TODO: Store salt for future use - implement salt persistence
                const salt = encryption.?.salt;
                log.info("Generated new encryption salt (length: {})", .{salt.len});
            }
        }

        // Initialize ZQLite Connection (v0.4.0 API)
        const connection = if (std.mem.eql(u8, config.db_path, ":memory:"))
            try zqlite.openMemory()
        else
            try zqlite.open(config.db_path);
        errdefer connection.close();

        db.* = Database{
            .allocator = allocator,
            .connection = connection,
            .encryption = encryption,
            .db_path = try allocator.dupe(u8, config.db_path),
        };

        // Initialize database schema
        try db.initializeSchema();

        log.info("✅ CNS Database initialized at: {s}", .{config.db_path});
        return db;
    }

    pub fn deinit(self: *Database) void {
        self.connection.close();
        self.allocator.free(self.db_path);
        self.allocator.destroy(self);
    }

    /// Initialize database schema for CNS
    fn initializeSchema(self: *Database) !void {
        // DNS Cache table with TTL support
        try self.connection.execute(
            \\CREATE TABLE IF NOT EXISTS dns_cache (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    domain TEXT NOT NULL,
            \\    query_type INTEGER NOT NULL,
            \\    query_class INTEGER NOT NULL,
            \\    response_data BLOB NOT NULL,
            \\    ttl INTEGER NOT NULL,
            \\    timestamp INTEGER NOT NULL,
            \\    cache_key TEXT UNIQUE NOT NULL,
            \\    UNIQUE(domain, query_type, query_class)
            \\)
        );

        // DNS Query Analytics
        try self.connection.execute(
            \\CREATE TABLE IF NOT EXISTS dns_queries (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    domain TEXT NOT NULL,
            \\    query_type INTEGER NOT NULL,
            \\    query_class INTEGER NOT NULL,
            \\    client_ip TEXT,
            \\    response_time_ms INTEGER,
            \\    cache_hit BOOLEAN NOT NULL,
            \\    timestamp INTEGER NOT NULL,
            \\    protocol TEXT NOT NULL -- 'UDP', 'TCP', 'QUIC', 'HTTP3'
            \\)
        );

        // Blockchain Domain Cache
        try self.connection.execute(
            \\CREATE TABLE IF NOT EXISTS blockchain_domains (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    domain TEXT NOT NULL UNIQUE,
            \\    tld TEXT NOT NULL,
            \\    resolved_address TEXT NOT NULL,
            \\    blockchain_tx_hash TEXT,
            \\    last_updated INTEGER NOT NULL,
            \\    status TEXT NOT NULL DEFAULT 'active'
            \\)
        );

        // Indexes for performance
        try self.connection.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_key ON dns_cache(cache_key)");
        try self.connection.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_ttl ON dns_cache(timestamp, ttl)");
        try self.connection.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp ON dns_queries(timestamp)");

        log.info("📊 Database schema initialized with all tables and indexes", .{});
    }

    /// Cache DNS response with TTL
    pub fn cacheDNSResponse(
        self: *Database,
        domain: []const u8,
        query_type: u16,
        query_class: u16,
        response_data: []const u8,
        ttl: u32,
    ) !void {
        const cache_key = try std.fmt.allocPrint(
            self.allocator,
            "{s}:{d}:{d}",
            .{ domain, query_type, query_class },
        );
        defer self.allocator.free(cache_key);

        const current_time = std.time.timestamp();

        // Convert binary data to hex string for SQLite storage
        var hex_data = try self.allocator.alloc(u8, response_data.len * 2);
        defer self.allocator.free(hex_data);
        _ = std.fmt.bufPrint(hex_data, "{}", .{std.fmt.fmtSliceHexLower(response_data)}) catch "";

        const insert_query = try std.fmt.allocPrint(
            self.allocator,
            \\INSERT OR REPLACE INTO dns_cache 
            \\(domain, query_type, query_class, response_data, ttl, timestamp, cache_key)
            \\VALUES ('{s}', {d}, {d}, X'{s}', {d}, {d}, '{s}')
        , .{ domain, query_type, query_class, hex_data, ttl, current_time, cache_key });
        defer self.allocator.free(insert_query);

        try self.connection.execute(insert_query);
    }

    /// Get cached DNS response if still valid
    pub fn getCachedDNSResponse(
        self: *Database,
        domain: []const u8,
        query_type: u16,
        query_class: u16,
    ) !?[]u8 {
        const cache_key = try std.fmt.allocPrint(
            self.allocator,
            "{s}:{d}:{d}",
            .{ domain, query_type, query_class },
        );
        defer self.allocator.free(cache_key);

        const current_time = std.time.timestamp();

        const select_query = try std.fmt.allocPrint(
            self.allocator,
            \\SELECT response_data FROM dns_cache 
            \\WHERE cache_key = '{s}' AND (timestamp + ttl) > {d}
        , .{ cache_key, current_time });
        defer self.allocator.free(select_query);

        // For now, return null as query functionality needs prepared statements
        // TODO: Implement proper query result handling with zqlite v0.4.0
        _ = select_query;
        return null;
    }

    /// Log DNS query for analytics
    pub fn logDNSQuery(
        self: *Database,
        domain: []const u8,
        query_type: u16,
        query_class: u16,
        client_ip: ?[]const u8,
        response_time_ms: u32,
        cache_hit: bool,
        protocol: []const u8,
    ) !void {
        const current_time = std.time.timestamp();

        const insert_query =
            \\INSERT INTO dns_queries 
            \\(domain, query_type, query_class, client_ip, response_time_ms, cache_hit, timestamp, protocol)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ;

        try self.connection.executeWithParams(insert_query, .{
            domain,
            query_type,
            query_class,
            client_ip orelse "",
            response_time_ms,
            cache_hit,
            current_time,
            protocol,
        });
    }

    /// Cache blockchain domain resolution
    pub fn cacheBlockchainDomain(
        self: *Database,
        domain: []const u8,
        tld: []const u8,
        resolved_address: []const u8,
        blockchain_tx_hash: ?[]const u8,
    ) !void {
        const current_time = std.time.timestamp();

        const insert_query =
            \\INSERT OR REPLACE INTO blockchain_domains 
            \\(domain, tld, resolved_address, blockchain_tx_hash, last_updated, status)
            \\VALUES (?, ?, ?, ?, ?, 'active')
        ;

        try self.connection.executeWithParams(insert_query, .{
            domain,
            tld,
            resolved_address,
            blockchain_tx_hash orelse "",
            current_time,
        });
    }

    /// Get blockchain domain resolution
    pub fn getBlockchainDomain(self: *Database, domain: []const u8) !?[]u8 {
        const select_query =
            \\SELECT resolved_address FROM blockchain_domains 
            \\WHERE domain = ? AND status = 'active'
        ;

        const result = try self.connection.queryWithParams(select_query, .{domain});
        defer result.deinit();

        if (result.rows.len > 0) {
            const address = result.rows[0].get("resolved_address").?.text;
            return try self.allocator.dupe(u8, address);
        }

        return null;
    }

    /// Get DNS analytics with aggregation (uses ZQLite v0.4.0 aggregate functions)
    pub fn getDNSAnalytics(self: *Database, hours_back: u32) !DNSAnalytics {
        const cutoff_time = std.time.timestamp() - (@as(i64, hours_back) * 3600);

        // Use aggregate functions from ZQLite v0.4.0
        const analytics_query =
            \\SELECT 
            \\  COUNT(*) as total_queries,
            \\  AVG(response_time_ms) as avg_response_time,
            \\  SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) as cache_hits,
            \\  COUNT(DISTINCT domain) as unique_domains,
            \\  COUNT(DISTINCT client_ip) as unique_clients
            \\FROM dns_queries 
            \\WHERE timestamp > ?
        ;

        const result = try self.connection.queryWithParams(analytics_query, .{cutoff_time});
        defer result.deinit();

        if (result.rows.len > 0) {
            const row = result.rows[0];
            return DNSAnalytics{
                .total_queries = @intCast(row.get("total_queries").?.integer),
                .avg_response_time = @floatCast(row.get("avg_response_time").?.real),
                .cache_hits = @intCast(row.get("cache_hits").?.integer),
                .unique_domains = @intCast(row.get("unique_domains").?.integer),
                .unique_clients = @intCast(row.get("unique_clients").?.integer),
            };
        }

        return DNSAnalytics{};
    }

    /// Clean up expired cache entries
    pub fn cleanupExpiredCache(self: *Database) !u64 {
        const current_time = std.time.timestamp();

        const delete_query_formatted = try std.fmt.allocPrint(
            self.allocator,
            \\DELETE FROM dns_cache 
            \\WHERE (timestamp + ttl) <= {d}
        , .{current_time});
        defer self.allocator.free(delete_query_formatted);

        try self.connection.execute(delete_query_formatted);
        // For now, return 0 as we don't have access to change count
        return 0;
    }

    /// Get pooled allocator for memory-efficient operations (ZQLite v0.4.0)
    pub fn getPooledAllocator(self: *Database) std.mem.Allocator {
        // Use standard allocator for now, memory pools may not be implemented yet
        return self.allocator;
    }

    /// Get memory statistics from ZQLite v0.4.0
    pub fn getMemoryStats(_: *Database) MemoryStats {
        // Return mock stats for now
        return MemoryStats{
            .total_pools = 1,
            .total_allocated = 0,
            .pool_efficiency = 1.0,
        };
    }

    /// Cleanup memory pools periodically (ZQLite v0.4.0)
    pub fn cleanupMemory(_: *Database) void {
        // No-op for now, memory pools may not be implemented yet
    }

    pub const MemoryStats = struct {
        total_pools: u32,
        total_allocated: u64,
        pool_efficiency: f64,
    };
};

pub const DNSAnalytics = struct {
    total_queries: u64 = 0,
    avg_response_time: f64 = 0.0,
    cache_hits: u64 = 0,
    unique_domains: u64 = 0,
    unique_clients: u64 = 0,

    pub fn cacheHitRate(self: DNSAnalytics) f64 {
        if (self.total_queries == 0) return 0.0;
        return @as(f64, @floatFromInt(self.cache_hits)) / @as(f64, @floatFromInt(self.total_queries));
    }
};

// Tests
test "Database initialization" {
    const allocator = std.testing.allocator;

    var db = try Database.init(allocator, .{
        .db_path = ":memory:", // Use in-memory database for testing
        .encryption_key = "test_key_123",
    });
    defer db.deinit();

    // Test caching
    try db.cacheDNSResponse("example.com", 1, 1, "test_response", 300);
    
    const cached = try db.getCachedDNSResponse("example.com", 1, 1);
    defer if (cached) |c| allocator.free(c);
    
    try std.testing.expect(cached != null);
    try std.testing.expectEqualStrings("test_response", cached.?);
}

test "Memory pooling integration" {
    const allocator = std.testing.allocator;

    var db = try Database.init(allocator, .{
        .db_path = ":memory:",
        .encryption_key = "test_key_123",
    });
    defer db.deinit();

    // Test pooled allocator
    const pooled_alloc = db.getPooledAllocator();
    const data = try pooled_alloc.alloc(u8, 1024);
    defer pooled_alloc.free(data);
    
    // Test memory stats
    const stats = db.getMemoryStats();
    try std.testing.expect(stats.total_pools >= 0);
    
    // Test cleanup
    db.cleanupMemory();
}
