const std = @import("std");
const cns = @import("cns");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    
    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    var config_path: ?[]const u8 = null;
    var use_enhanced: bool = true;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-c") or std.mem.eql(u8, args[i], "--config")) {
            if (i + 1 < args.len) {
                config_path = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, args[i], "--legacy")) {
            use_enhanced = false;
        } else if (std.mem.eql(u8, args[i], "--enhanced")) {
            use_enhanced = true;
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            printHelp();
            return;
        }
    }
    
    std.debug.print("🌐 CNS (Crypto Name Server) v0.2.0 - Web5.0 DNS\n", .{});
    std.debug.print("🔧 Bridging traditional DNS with blockchain naming\n", .{});
    
    if (use_enhanced) {
        std.debug.print("🚀 Using Enhanced Server with HTTP/3, QUIC, and TLS 1.3\n", .{});
        
        // Initialize the Enhanced DNS server
        var enhanced_server = try cns.EnhancedServer.init(allocator, config_path);
        defer enhanced_server.deinit();
        
        // Start the enhanced server
        try enhanced_server.start();
    } else {
        std.debug.print("📡 Using Legacy Server (UDP/TCP only)\n", .{});
        
        // Initialize the traditional DNS server
        var server = try cns.Server.init(allocator, config_path);
        defer server.deinit();
        
        // Start the server
        try server.start();
    }
}

fn printHelp() void {
    std.debug.print(
        \\CNS (Crypto Name Server) - Web5.0 DNS Bridge
        \\
        \\USAGE:
        \\    cns [OPTIONS]
        \\
        \\OPTIONS:
        \\    -c, --config <FILE>    Configuration file path
        \\    --enhanced             Use enhanced server with HTTP/3 and QUIC (default)
        \\    --legacy               Use legacy server (UDP/TCP only)
        \\    -h, --help             Show this help message
        \\
        \\FEATURES:
        \\    🔐 TLS 1.3 encryption with zcrypto
        \\    🌐 HTTP/3 and QUIC support with zquic
        \\    📡 DNS-over-QUIC (DoQ) - RFC 9250
        \\    🌍 DNS-over-HTTPS (DoH) - RFC 8484
        \\    🔗 Blockchain domain resolution (.ghost, .chain, .bc, .eth, .ens)
        \\    ⚡ High-performance caching
        \\    📊 Real-time metrics and web interface
        \\    🛡️ Advanced security and rate limiting
        \\
        \\EXAMPLES:
        \\    cns                                    # Start with default config
        \\    cns -c /etc/cns/cns.conf               # Use specific config
        \\    cns --legacy                           # Use traditional DNS only
        \\    sudo cns -c configs/cns.conf           # Run as root for port 53
        \\
        \\For more information, visit: https://github.com/ghostkellz/cns
        \\
    , .{});
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
