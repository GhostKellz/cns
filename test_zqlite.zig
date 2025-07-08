//! Test ZQLite integration in CNS
const std = @import("std");
const zqlite = @import("zqlite");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.log.info("🚀 Testing ZQLite v0.4.0 integration...", .{});

    // Test basic ZQLite functionality
    const db = try zqlite.Database.init(allocator, .{
        .path = ":memory:",
        .encryption_key = "test_key",
    });
    defer db.deinit();

    // Test new v0.4.0 features
    try db.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)");
    try db.execute("INSERT INTO test (name) VALUES ('CNS Test')");

    // Test aggregate functions (new in v0.4.0)
    const result = try db.query("SELECT COUNT(*) as count FROM test");
    defer result.deinit();

    if (result.rows.len > 0) {
        const count = result.rows[0].columns[0].integer;
        std.log.info("✅ ZQLite v0.4.0 working! Row count: {}", .{count});
    }

    std.log.info("🎯 ZQLite integration test completed successfully!", .{});
}
