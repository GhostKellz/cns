const std = @import("std");
const dns = @import("dns.zig");
const server = @import("server.zig");
const enhanced_server = @import("enhanced_server.zig");
const cache = @import("cache.zig");
const enhanced_cache = @import("enhanced_cache.zig");
const config = @import("config.zig");
const tls_manager = @import("tls_manager.zig");
const database = @import("database.zig");

// Legacy DNS components
pub const Server = server.Server;
pub const DNSPacket = dns.DNSPacket;
pub const DNSHeader = dns.DNSHeader;
pub const DNSQuestion = dns.DNSQuestion;
pub const DNSRecord = dns.DNSRecord;
pub const DNSCache = cache.DNSCache;
pub const Config = config.Config;

// Enhanced components with HTTP/3, QUIC, and TLS 1.3
pub const EnhancedServer = enhanced_server.EnhancedServer;
pub const TlsManager = tls_manager.TlsManager;
pub const TlsConfiguration = tls_manager.TlsConfiguration;

// Database layer with ZQLite v0.4.0
pub const Database = database.Database;
pub const DNSAnalytics = database.DNSAnalytics;
pub const EnhancedDNSCache = enhanced_cache.EnhancedDNSCache;

test {
    std.testing.refAllDecls(@This());
}
