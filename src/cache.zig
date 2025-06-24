const std = @import("std");
const dns = @import("dns.zig");

// Cache entry structure
pub const CacheEntry = struct {
    key: []const u8,
    packet: dns.DNSPacket,
    created_at: i64,
    ttl: u32,
    hits: u64,
    
    // For LRU linked list
    prev: ?*CacheEntry = null,
    next: ?*CacheEntry = null,
    
    pub fn isExpired(self: *const CacheEntry) bool {
        const now = std.time.timestamp();
        return now > self.created_at + @as(i64, self.ttl);
    }
};

// High-performance DNS cache with LRU eviction
pub const DNSCache = struct {
    allocator: std.mem.Allocator,
    entries: std.hash_map.StringHashMap(*CacheEntry),
    lru_head: ?*CacheEntry,
    lru_tail: ?*CacheEntry,
    max_entries: usize,
    current_entries: usize,
    
    // Statistics
    hits: std.atomic.Value(u64),
    misses: std.atomic.Value(u64),
    evictions: std.atomic.Value(u64),
    
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, max_entries: usize) !DNSCache {
        return DNSCache{
            .allocator = allocator,
            .entries = std.hash_map.StringHashMap(*CacheEntry).init(allocator),
            .lru_head = null,
            .lru_tail = null,
            .max_entries = max_entries,
            .current_entries = 0,
            .hits = std.atomic.Value(u64).init(0),
            .misses = std.atomic.Value(u64).init(0),
            .evictions = std.atomic.Value(u64).init(0),
            .mutex = .{},
        };
    }
    
    pub fn deinit(self: *DNSCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.packet.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.entries.deinit();
    }
    
    pub fn get(self: *DNSCache, key: []const u8) ?dns.DNSPacket {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.entries.get(key)) |entry| {
            if (entry.isExpired()) {
                self.removeEntry(entry);
                _ = self.misses.fetchAdd(1, .monotonic);
                return null;
            }
            
            // Move to front of LRU list
            self.moveToFront(entry);
            entry.hits += 1;
            _ = self.hits.fetchAdd(1, .monotonic);
            
            // Return a copy of the packet
            return entry.packet;
        }
        
        _ = self.misses.fetchAdd(1, .monotonic);
        return null;
    }
    
    pub fn put(self: *DNSCache, key: []const u8, packet: dns.DNSPacket, ttl: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check if key already exists
        if (self.entries.get(key)) |existing| {
            existing.packet.deinit();
            existing.packet = packet;
            existing.created_at = std.time.timestamp();
            existing.ttl = ttl;
            self.moveToFront(existing);
            return;
        }
        
        // Evict if necessary
        if (self.current_entries >= self.max_entries) {
            if (self.lru_tail) |tail| {
                self.removeEntry(tail);
                _ = self.evictions.fetchAdd(1, .monotonic);
            }
        }
        
        // Create new entry
        const entry = try self.allocator.create(CacheEntry);
        const key_copy = try self.allocator.dupe(u8, key);
        
        entry.* = CacheEntry{
            .key = key_copy,
            .packet = packet,
            .created_at = std.time.timestamp(),
            .ttl = ttl,
            .hits = 0,
        };
        
        try self.entries.put(key_copy, entry);
        self.addToFront(entry);
        self.current_entries += 1;
    }
    
    pub fn remove(self: *DNSCache, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.entries.get(key)) |entry| {
            self.removeEntry(entry);
        }
    }
    
    pub fn clear(self: *DNSCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.packet.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        
        self.entries.clearAndFree();
        self.lru_head = null;
        self.lru_tail = null;
        self.current_entries = 0;
    }
    
    pub fn getStats(self: *DNSCache) CacheStats {
        return CacheStats{
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
            .evictions = self.evictions.load(.monotonic),
            .entries = self.current_entries,
            .capacity = self.max_entries,
        };
    }
    
    // LRU list management
    fn moveToFront(self: *DNSCache, entry: *CacheEntry) void {
        if (self.lru_head == entry) return;
        
        // Remove from current position
        if (entry.prev) |prev| {
            prev.next = entry.next;
        }
        if (entry.next) |next| {
            next.prev = entry.prev;
        }
        if (self.lru_tail == entry) {
            self.lru_tail = entry.prev;
        }
        
        // Add to front
        entry.prev = null;
        entry.next = self.lru_head;
        if (self.lru_head) |head| {
            head.prev = entry;
        }
        self.lru_head = entry;
        
        if (self.lru_tail == null) {
            self.lru_tail = entry;
        }
    }
    
    fn addToFront(self: *DNSCache, entry: *CacheEntry) void {
        entry.prev = null;
        entry.next = self.lru_head;
        
        if (self.lru_head) |head| {
            head.prev = entry;
        }
        self.lru_head = entry;
        
        if (self.lru_tail == null) {
            self.lru_tail = entry;
        }
    }
    
    fn removeEntry(self: *DNSCache, entry: *CacheEntry) void {
        if (entry.prev) |prev| {
            prev.next = entry.next;
        } else {
            self.lru_head = entry.next;
        }
        
        if (entry.next) |next| {
            next.prev = entry.prev;
        } else {
            self.lru_tail = entry.prev;
        }
        
        _ = self.entries.remove(entry.key);
        self.allocator.free(entry.key);
        entry.packet.deinit();
        self.allocator.destroy(entry);
        self.current_entries -= 1;
    }
};

pub const CacheStats = struct {
    hits: u64,
    misses: u64,
    evictions: u64,
    entries: usize,
    capacity: usize,
    
    pub fn hitRate(self: CacheStats) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }
};

// Tests
test "DNS cache basic operations" {
    const allocator = std.testing.allocator;
    
    var cache = try DNSCache.init(allocator, 10);
    defer cache.deinit();
    
    // Create a test packet
    var packet = dns.DNSPacket.init(allocator);
    packet.header.id = 0x1234;
    
    // Put and get
    try cache.put("example.com", packet, 300);
    
    if (cache.get("example.com")) |cached| {
        try std.testing.expectEqual(@as(u16, 0x1234), cached.header.id);
    } else {
        try std.testing.expect(false); // Should have found the entry
    }
    
    // Test miss
    try std.testing.expect(cache.get("nonexistent.com") == null);
    
    // Check stats
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.hits);
    try std.testing.expectEqual(@as(u64, 1), stats.misses);
}

test "DNS cache LRU eviction" {
    const allocator = std.testing.allocator;
    
    var cache = try DNSCache.init(allocator, 2);
    defer cache.deinit();
    
    // Fill cache
    var packet1 = dns.DNSPacket.init(allocator);
    packet1.header.id = 1;
    try cache.put("one.com", packet1, 300);
    
    var packet2 = dns.DNSPacket.init(allocator);
    packet2.header.id = 2;
    try cache.put("two.com", packet2, 300);
    
    // Access first entry to make it more recent
    _ = cache.get("one.com");
    
    // Add third entry, should evict "two.com"
    var packet3 = dns.DNSPacket.init(allocator);
    packet3.header.id = 3;
    try cache.put("three.com", packet3, 300);
    
    // Check that "two.com" was evicted
    try std.testing.expect(cache.get("two.com") == null);
    try std.testing.expect(cache.get("one.com") != null);
    try std.testing.expect(cache.get("three.com") != null);
    
    const stats = cache.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.evictions);
}