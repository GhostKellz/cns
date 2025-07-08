//! Enhanced DNS Cache using ZQLite v0.4.0 backend
//! Provides both in-memory and persistent caching with analytics

const std = @import("std");
const dns = @import("dns.zig");
const database = @import("database.zig");

const log = std.log.scoped(.enhanced_cache);

pub const EnhancedDNSCache = struct {
    allocator: std.mem.Allocator,
    database: *database.Database,

    // In-memory cache for ultra-fast lookups
    memory_cache: std.hash_map.StringHashMap(*CacheEntry),

    // LRU for memory cache management
    lru_head: ?*CacheEntry,
    lru_tail: ?*CacheEntry,
    max_memory_entries: usize,
    current_memory_entries: usize,

    // Statistics (atomic for thread safety)
    memory_hits: std.atomic.Value(u64),
    database_hits: std.atomic.Value(u64),
    misses: std.atomic.Value(u64),

    mutex: std.Thread.Mutex,

    const CacheEntry = struct {
        key: []u8,
        packet: dns.DNSPacket,
        ttl: u32,
        timestamp: i64,

        // LRU chain
        prev: ?*CacheEntry,
        next: ?*CacheEntry,

        pub fn isExpired(self: *const CacheEntry) bool {
            return (std.time.timestamp() - self.timestamp) > self.ttl;
        }
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, max_memory_entries: usize) !EnhancedDNSCache {
        return EnhancedDNSCache{
            .allocator = allocator,
            .database = db,
            .memory_cache = std.hash_map.StringHashMap(*CacheEntry).init(allocator),
            .lru_head = null,
            .lru_tail = null,
            .max_memory_entries = max_memory_entries,
            .current_memory_entries = 0,
            .memory_hits = std.atomic.Value(u64).init(0),
            .database_hits = std.atomic.Value(u64).init(0),
            .misses = std.atomic.Value(u64).init(0),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *EnhancedDNSCache) void {
        var it = self.memory_cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.packet.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.memory_cache.deinit();
    }

    /// Get cached DNS response with hybrid memory/database lookup
    pub fn get(self: *EnhancedDNSCache, cache_key: []const u8) ?dns.DNSPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        // First check memory cache
        if (self.memory_cache.get(cache_key)) |entry| {
            if (!entry.isExpired()) {
                // Move to front of LRU
                self.moveToFront(entry);
                _ = self.memory_hits.fetchAdd(1, .monotonic);

                log.debug("💾 Memory cache HIT for: {s}", .{cache_key});
                return entry.packet; // TODO: Clone packet for safety
            } else {
                // Remove expired entry
                self.removeEntry(entry);
            }
        }

        // Check database cache
        var domain_parts = std.mem.splitSequence(u8, cache_key, ":");
        const domain = domain_parts.next() orelse return null;
        const type_str = domain_parts.next() orelse return null;
        const class_str = domain_parts.next() orelse return null;

        const query_type = std.fmt.parseInt(u16, type_str, 10) catch return null;
        const query_class = std.fmt.parseInt(u16, class_str, 10) catch return null;

        // Database cache lookup - currently disabled due to API incompatibility
        // TODO: Fix once database implementation is complete
        _ = self.database.getCachedDNSResponse(domain, query_type, query_class) catch null;

        _ = self.misses.fetchAdd(1, .monotonic);
        log.debug("❌ Cache MISS for: {s}", .{cache_key});
        return null;
    }

    /// Store DNS response in both memory and database
    pub fn put(self: *EnhancedDNSCache, cache_key: []const u8, packet: dns.DNSPacket, ttl: u32) !void {
        // Store in database for persistence
        try self.putInDatabase(cache_key, packet, ttl);

        // Store in memory for fast access
        try self.putInMemoryCache(cache_key, packet, ttl);

        log.debug("💽 Cached response for: {s} (TTL: {d}s)", .{ cache_key, ttl });
    }

    /// Store in database with proper serialization
    fn putInDatabase(self: *EnhancedDNSCache, cache_key: []const u8, packet: dns.DNSPacket, ttl: u32) !void {
        // Serialize DNS packet
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try packet.serialize(buffer.writer());

        // Parse cache key
        var domain_parts = std.mem.splitSequence(u8, cache_key, ":");
        const domain = domain_parts.next() orelse return;
        const type_str = domain_parts.next() orelse return;
        const class_str = domain_parts.next() orelse return;

        const query_type = try std.fmt.parseInt(u16, type_str, 10);
        const query_class = try std.fmt.parseInt(u16, class_str, 10);

        try self.database.cacheDNSResponse(domain, query_type, query_class, buffer.items, ttl);
    }

    /// Store in memory cache with LRU management
    fn putInMemoryCache(self: *EnhancedDNSCache, cache_key: []const u8, packet: dns.DNSPacket, ttl: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if we need to evict
        if (self.current_memory_entries >= self.max_memory_entries) {
            self.evictLRU();
        }

        const entry = try self.allocator.create(CacheEntry);
        entry.* = CacheEntry{
            .key = try self.allocator.dupe(u8, cache_key),
            .packet = packet, // TODO: Clone packet for safety
            .ttl = ttl,
            .timestamp = std.time.timestamp(),
            .prev = null,
            .next = null,
        };

        try self.memory_cache.put(entry.key, entry);
        self.addToFront(entry);
        self.current_memory_entries += 1;
    }

    /// LRU Management
    fn moveToFront(self: *EnhancedDNSCache, entry: *CacheEntry) void {
        if (entry == self.lru_head) return;

        // Remove from current position
        if (entry.prev) |prev| prev.next = entry.next;
        if (entry.next) |next| next.prev = entry.prev;

        if (entry == self.lru_tail) {
            self.lru_tail = entry.prev;
        }

        // Add to front
        entry.prev = null;
        entry.next = self.lru_head;
        if (self.lru_head) |head| head.prev = entry;
        self.lru_head = entry;

        if (self.lru_tail == null) {
            self.lru_tail = entry;
        }
    }

    fn addToFront(self: *EnhancedDNSCache, entry: *CacheEntry) void {
        entry.next = self.lru_head;
        entry.prev = null;

        if (self.lru_head) |head| {
            head.prev = entry;
        }
        self.lru_head = entry;

        if (self.lru_tail == null) {
            self.lru_tail = entry;
        }
    }

    fn evictLRU(self: *EnhancedDNSCache) void {
        if (self.lru_tail) |tail| {
            self.removeEntry(tail);
        }
    }

    fn removeEntry(self: *EnhancedDNSCache, entry: *CacheEntry) void {
        _ = self.memory_cache.remove(entry.key);

        if (entry.prev) |prev| prev.next = entry.next;
        if (entry.next) |next| next.prev = entry.prev;

        if (entry == self.lru_head) self.lru_head = entry.next;
        if (entry == self.lru_tail) self.lru_tail = entry.prev;

        self.allocator.free(entry.key);
        entry.packet.deinit();
        self.allocator.destroy(entry);
        self.current_memory_entries -= 1;
    }

    /// Get comprehensive cache statistics
    pub fn getStats(self: *EnhancedDNSCache) CacheStats {
        const memory_hits = self.memory_hits.load(.monotonic);
        const database_hits = self.database_hits.load(.monotonic);
        const misses = self.misses.load(.monotonic);
        const total = memory_hits + database_hits + misses;

        return CacheStats{
            .memory_hits = memory_hits,
            .database_hits = database_hits,
            .misses = misses,
            .total_queries = total,
            .memory_entries = self.current_memory_entries,
            .memory_hit_rate = if (total > 0) @as(f64, @floatFromInt(memory_hits)) / @as(f64, @floatFromInt(total)) else 0.0,
            .overall_hit_rate = if (total > 0) @as(f64, @floatFromInt(memory_hits + database_hits)) / @as(f64, @floatFromInt(total)) else 0.0,
        };
    }

    /// Clean up expired entries from both memory and database
    pub fn cleanup(self: *EnhancedDNSCache) !u64 {
        var expired_count: u64 = 0;

        // Clean memory cache
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.memory_cache.iterator();
        var entries_to_remove = std.ArrayList(*CacheEntry).init(self.allocator);
        defer entries_to_remove.deinit();

        while (it.next()) |entry| {
            if (entry.value_ptr.*.isExpired()) {
                try entries_to_remove.append(entry.value_ptr.*);
            }
        }

        for (entries_to_remove.items) |entry| {
            self.removeEntry(entry);
            expired_count += 1;
        }

        // Clean database cache
        const db_expired = try self.database.cleanupExpiredCache();
        expired_count += db_expired;

        if (expired_count > 0) {
            log.info("🧹 Cleaned up {d} expired cache entries", .{expired_count});
        }

        return expired_count;
    }
};

pub const CacheStats = struct {
    memory_hits: u64,
    database_hits: u64,
    misses: u64,
    total_queries: u64,
    memory_entries: usize,
    memory_hit_rate: f64,
    overall_hit_rate: f64,

    pub fn format(
        self: CacheStats,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Cache Stats: Total={d}, Memory={d}, DB={d}, Misses={d}, Hit Rate={d:.1}%", .{ self.total_queries, self.memory_hits, self.database_hits, self.misses, self.overall_hit_rate * 100 });
    }
};

// Tests
test "Enhanced cache memory and database integration" {
    const allocator = std.testing.allocator;

    var db = try database.Database.init(allocator, .{
        .db_path = ":memory:",
    });
    defer db.deinit();

    var cache = try EnhancedDNSCache.init(allocator, db, 2);
    defer cache.deinit();

    // Create test packet
    var packet = dns.DNSPacket.init(allocator);
    defer packet.deinit();

    // Test put and get
    try cache.put("example.com:1:1", packet, 300);

    const retrieved = cache.get("example.com:1:1");
    try std.testing.expect(retrieved != null);

    const stats = cache.getStats();
    try std.testing.expect(stats.total_queries > 0);
}
