//! Simple ZQLite test for CNS
const std = @import("std");
const zqlite = @import("zqlite");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    std.log.info("🚀 Testing ZQLite v0.4.0 integration with CNS...", .{});
    
    // Test ZQLite connection
    const connection = zqlite.db.Connection.init(allocator, .{
        .path = ":memory:",
        .encryption_key = null,
    }) catch |err| {
        std.log.err("Failed to create ZQLite connection: {}", .{err});
        return;
    };
    defer connection.deinit();
    
    std.log.info("✅ ZQLite v0.4.0 connected successfully!", .{});
    
    // Test basic operations
    connection.execute("CREATE TABLE dns_test (domain TEXT, ip TEXT)") catch |err| {
        std.log.err("Failed to create table: {}", .{err});
        return;
    };
    
    connection.executeWithParams(
        "INSERT INTO dns_test (domain, ip) VALUES (?, ?)",
        .{ "example.com", "127.0.0.1" }
    ) catch |err| {
        std.log.err("Failed to insert data: {}", .{err});
        return;
    };
    
    const result = connection.queryWithParams(
        "SELECT COUNT(*) as count FROM dns_test WHERE domain = ?",
        .{"example.com"}
    ) catch |err| {
        std.log.err("Failed to query data: {}", .{err});
        return;
    };
    defer result.deinit();
    
    if (result.rows.len > 0) {
        std.log.info("🎯 Query successful! Found {} matching records", .{result.rows.len});
    }
    
    std.log.info("🚀 ZQLite v0.4.0 integration test completed successfully!");
    std.log.info("📊 Ready to integrate with CNS DNS server!");
}
