const std = @import("std");

// Enhanced Configuration structure for CNS with HTTP/3, QUIC, and TLS 1.3 support
pub const Config = struct {
    // Network settings
    bind_addresses: []const std.net.Address,
    upstream_resolvers: []const std.net.Address,
    
    // Traditional DNS settings
    port: u16 = 53,
    enable_tcp: bool = true,
    enable_udp: bool = true,
    
    // Modern protocol settings
    enable_quic: bool = true,
    enable_http3: bool = true,
    enable_doh: bool = true,        // DNS-over-HTTPS
    enable_doq: bool = true,        // DNS-over-QUIC
    
    // Port configuration
    quic_port: u16 = 853,           // Standard DoQ port
    http3_port: u16 = 443,          // HTTP/3 port
    doh_port: u16 = 443,            // DoH port (can be same as HTTP/3)
    
    // TLS configuration (simplified)
    tls_cert_file: ?[]const u8 = null,
    tls_key_file: ?[]const u8 = null,
    
    // Cache settings
    cache_size: usize = 10000,
    default_ttl: u32 = 300,
    min_ttl: u32 = 60,
    max_ttl: u32 = 86400,
    cache_negative_ttl: u32 = 300,  // Cache NXDOMAIN responses
    
    // Security settings
    dnssec_enabled: bool = true,
    rate_limit_per_ip: u32 = 100,
    rate_limit_window: u32 = 60, // seconds
    max_query_size: u32 = 65535,
    
    // Performance settings
    worker_threads: u32 = 0,        // 0 = auto-detect CPU count
    connection_pool_size: u32 = 100,
    upstream_timeout_ms: u32 = 5000,
    
    // Blockchain settings (for future integration)
    blockchain_enabled: bool = true,
    blockchain_rpc_url: ?[]const u8 = null,
    blockchain_chain_id: ?[]const u8 = null,
    blockchain_tlds: []const []const u8 = &[_][]const u8{
        "ghost",  // GhostChain TLD
        "chain",  // Generic blockchain TLD
        "bc",     // Root blockchain zone
        "eth",    // Ethereum domains
        "ens",    // ENS domains
    },
    
    // ENS settings
    ens_enabled: bool = true,
    ens_rpc_url: ?[]const u8 = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
    ens_cache_ttl: u32 = 3600,      // 1 hour for ENS lookups
    
    // Web interface settings
    web_interface_enabled: bool = true,
    web_interface_port: u16 = 8080,
    api_enabled: bool = true,
    metrics_enabled: bool = true,
    
    // Logging
    log_level: LogLevel = .info,
    log_queries: bool = false,
    log_responses: bool = false,
    log_file: ?[]const u8 = null,
    
    // Monitoring and health checks
    health_check_enabled: bool = true,
    health_check_interval: u32 = 30, // seconds
    prometheus_metrics: bool = false,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Config {
        return Config{
            .bind_addresses = &[_]std.net.Address{},
            .upstream_resolvers = &[_]std.net.Address{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Config) void {
        self.allocator.free(self.bind_addresses);
        self.allocator.free(self.upstream_resolvers);
        if (self.blockchain_rpc_url) |url| {
            self.allocator.free(url);
        }
        if (self.blockchain_chain_id) |id| {
            self.allocator.free(id);
        }
        if (self.ens_rpc_url) |url| {
            self.allocator.free(url);
        }
        for (self.blockchain_tlds) |tld| {
            self.allocator.free(tld);
        }
        self.allocator.free(self.blockchain_tlds);
    }
    
    pub fn loadFromFile(allocator: std.mem.Allocator, path: ?[]const u8) !Config {
        if (path) |p| {
            const file = try std.fs.cwd().openFile(p, .{});
            defer file.close();
            
            const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
            defer allocator.free(content);
            
            return try parseConfig(allocator, content);
        } else {
            // Return default config
            return try getDefaultConfig(allocator);
        }
    }
    
    pub fn getDefaultConfig(allocator: std.mem.Allocator) !Config {
        var config = Config.init(allocator);
        
        // Default bind addresses (all interfaces)
        var bind_addresses = try allocator.alloc(std.net.Address, 2);
        bind_addresses[0] = try std.net.Address.parseIp("0.0.0.0", 53);
        bind_addresses[1] = try std.net.Address.parseIp("::", 53);
        config.bind_addresses = bind_addresses;
        
        // Default upstream resolvers
        var upstreams = try allocator.alloc(std.net.Address, 4);
        upstreams[0] = try std.net.Address.parseIp("1.1.1.1", 53);
        upstreams[1] = try std.net.Address.parseIp("1.0.0.1", 53);
        upstreams[2] = try std.net.Address.parseIp("8.8.8.8", 53);
        upstreams[3] = try std.net.Address.parseIp("8.8.4.4", 53);
        config.upstream_resolvers = upstreams;
        
        // Default blockchain TLDs
        var tlds = try allocator.alloc([]const u8, 3);
        tlds[0] = try allocator.dupe(u8, "ghost");
        tlds[1] = try allocator.dupe(u8, "chain");
        tlds[2] = try allocator.dupe(u8, "bc");
        config.blockchain_tlds = tlds;
        
        return config;
    }
};

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
    
    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

// Simple config parser (TOML-like format)
fn parseConfig(allocator: std.mem.Allocator, content: []const u8) !Config {
    var config = Config.init(allocator);
    var bind_list = std.ArrayList(std.net.Address).init(allocator);
    var upstream_list = std.ArrayList(std.net.Address).init(allocator);
    var tld_list = std.ArrayList([]const u8).init(allocator);
    
    defer bind_list.deinit();
    defer upstream_list.deinit();
    defer tld_list.deinit();
    
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        
        var parts = std.mem.tokenizeScalar(u8, trimmed, '=');
        const key = std.mem.trim(u8, parts.next() orelse continue, " \t");
        const value = std.mem.trim(u8, parts.rest(), " \t\"");
        
        if (std.mem.eql(u8, key, "port")) {
            config.port = try std.fmt.parseInt(u16, value, 10);
        } else if (std.mem.eql(u8, key, "enable_tcp")) {
            config.enable_tcp = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "enable_udp")) {
            config.enable_udp = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "enable_quic")) {
            config.enable_quic = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "cache_size")) {
            config.cache_size = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, key, "default_ttl")) {
            config.default_ttl = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, key, "blockchain_enabled")) {
            config.blockchain_enabled = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "blockchain_rpc_url")) {
            config.blockchain_rpc_url = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "blockchain_tld")) {
            try tld_list.append(try allocator.dupe(u8, value));
        } else if (std.mem.eql(u8, key, "bind")) {
            const addr = try std.net.Address.parseIp(value, config.port);
            try bind_list.append(addr);
        } else if (std.mem.eql(u8, key, "upstream")) {
            const addr = try std.net.Address.parseIp(value, 53);
            try upstream_list.append(addr);
        } else if (std.mem.eql(u8, key, "log_level")) {
            if (std.mem.eql(u8, value, "debug")) {
                config.log_level = .debug;
            } else if (std.mem.eql(u8, value, "info")) {
                config.log_level = .info;
            } else if (std.mem.eql(u8, value, "warn")) {
                config.log_level = .warn;
            } else if (std.mem.eql(u8, value, "error")) {
                config.log_level = .err;
            }
        } else if (std.mem.eql(u8, key, "log_queries")) {
            config.log_queries = std.mem.eql(u8, value, "true");
        }
    }
    
    // Use parsed values or defaults
    if (bind_list.items.len > 0) {
        config.bind_addresses = try bind_list.toOwnedSlice();
    } else {
        var default_binds = try allocator.alloc(std.net.Address, 2);
        default_binds[0] = try std.net.Address.parseIp("0.0.0.0", config.port);
        default_binds[1] = try std.net.Address.parseIp("::", config.port);
        config.bind_addresses = default_binds;
    }
    
    if (upstream_list.items.len > 0) {
        config.upstream_resolvers = try upstream_list.toOwnedSlice();
    } else {
        var default_upstreams = try allocator.alloc(std.net.Address, 2);
        default_upstreams[0] = try std.net.Address.parseIp("1.1.1.1", 53);
        default_upstreams[1] = try std.net.Address.parseIp("8.8.8.8", 53);
        config.upstream_resolvers = default_upstreams;
    }
    
    if (tld_list.items.len > 0) {
        config.blockchain_tlds = try tld_list.toOwnedSlice();
    } else {
        var default_tlds = try allocator.alloc([]const u8, 3);
        default_tlds[0] = try allocator.dupe(u8, "ghost");
        default_tlds[1] = try allocator.dupe(u8, "chain");
        default_tlds[2] = try allocator.dupe(u8, "bc");
        config.blockchain_tlds = default_tlds;
    }
    
    return config;
}

// Tests
test "Config default values" {
    const allocator = std.testing.allocator;
    
    var config = try Config.getDefaultConfig(allocator);
    defer config.deinit();
    
    try std.testing.expectEqual(@as(u16, 53), config.port);
    try std.testing.expectEqual(true, config.enable_tcp);
    try std.testing.expectEqual(true, config.enable_udp);
    try std.testing.expectEqual(@as(usize, 10000), config.cache_size);
    try std.testing.expect(config.bind_addresses.len > 0);
    try std.testing.expect(config.upstream_resolvers.len > 0);
}

test "Config parsing" {
    const allocator = std.testing.allocator;
    
    const config_text =
        \\port = 5353
        \\cache_size = 5000
        \\log_level = debug
        \\blockchain_enabled = true
        \\blockchain_tld = chain
        \\blockchain_tld = gcc
        \\upstream = 9.9.9.9
    ;
    
    var config = try parseConfig(allocator, config_text);
    defer config.deinit();
    
    try std.testing.expectEqual(@as(u16, 5353), config.port);
    try std.testing.expectEqual(@as(usize, 5000), config.cache_size);
    try std.testing.expectEqual(LogLevel.debug, config.log_level);
    try std.testing.expectEqual(true, config.blockchain_enabled);
    try std.testing.expectEqual(@as(usize, 2), config.blockchain_tlds.len);
    try std.testing.expectEqualStrings("chain", config.blockchain_tlds[0]);
    try std.testing.expectEqualStrings("gcc", config.blockchain_tlds[1]);
}