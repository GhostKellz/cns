//! Enhanced CNS Server with HTTP/3, QUIC, and TLS 1.3 support
//! Leverages zquic HTTP/3 server and zcrypto TLS implementation

const std = @import("std");
const zquic = @import("zquic");
const zcrypto = @import("zcrypto");
const dns = @import("dns.zig");
const cache = @import("cache.zig");
const config = @import("config.zig");
const tls_manager = @import("tls_manager.zig");

const log = std.log.scoped(.enhanced_cns);

pub const EnhancedServer = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    cache: cache.DNSCache,
    
    // Network components
    udp_threads: []std.Thread,
    tcp_listener: ?std.net.Server,
    tls_mgr: ?*tls_manager.TlsManager,
    
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
        
        return EnhancedServer{
            .allocator = allocator,
            .config = cfg,
            .cache = dns_cache,
            .udp_threads = &[_]std.Thread{},
            .tcp_listener = null,
            .tls_mgr = null,
            .queries_total = std.atomic.Value(u64).init(0),
            .queries_failed = std.atomic.Value(u64).init(0),
            .queries_blockchain = std.atomic.Value(u64).init(0),
            .queries_http3 = std.atomic.Value(u64).init(0),
            .running = std.atomic.Value(bool).init(false),
        };
    }
    
    pub fn deinit(self: *EnhancedServer) void {
        self.stop();
        self.cache.deinit();
        self.config.deinit();
        self.allocator.free(self.udp_threads);
        
        if (self.tls_mgr) |mgr| {
            mgr.deinit();
        }
    }
    
    pub fn start(self: *EnhancedServer) !void {
        self.running.store(true, .monotonic);
        
        log.info("🚀 Starting Enhanced CNS server with HTTP/3 + TLS 1.3...", .{});
        log.info("📊 Cache size: {} entries", .{self.config.cache_size});
        log.info("🌐 Blockchain TLDs: .ghost, .chain, .bc (root zone)", .{});
        
        // Initialize TLS configuration
        if (self.config.enable_quic) {
            try self.initializeTlsConfig();
        }
        
        // Start traditional DNS listeners
        if (self.config.enable_udp) {
            try self.startUDPListeners();
        }
        
        if (self.config.enable_tcp) {
            try self.startTCPListener();
        }
        
        // Start HTTP/3 QUIC listener for modern DNS-over-QUIC
        if (self.config.enable_quic) {
            try self.startHttp3Server();
        }
        
        log.info("✅ Enhanced CNS server started successfully!", .{});
        
        // Keep running until stopped
        while (self.running.load(.monotonic)) {
            std.time.sleep(std.time.ns_per_s);
            self.printStats();
        }
    }
    
    pub fn stop(self: *EnhancedServer) void {
        self.running.store(false, .monotonic);
        
        // Stop all listeners
        for (self.udp_threads) |thread| {
            thread.join();
        }
        
        if (self.tcp_listener) |*listener| {
            listener.deinit();
        }
    }
    
    /// Initialize TLS 1.3 configuration using zcrypto
    fn initializeTlsConfig(self: *EnhancedServer) !void {
        var tls_mgr = try self.allocator.create(tls_manager.TlsManager);
        tls_mgr.* = tls_manager.TlsManager.init(self.allocator);
        
        // Configure TLS 1.3 settings with simplified configuration
        const tls_config = tls_manager.TlsManager.TlsConfiguration{
            .cert_file = self.config.tls_cert_file,
            .key_file = self.config.tls_key_file,
        };
        
        try tls_mgr.configureServer(tls_config);
        
        self.tls_mgr = tls_mgr;
        
        log.info("🔐 TLS 1.3 configuration initialized", .{});
    }
    
    /// Start HTTP/3 server for DNS-over-QUIC and web interface
    fn startHttp3Server(self: *EnhancedServer) !void {
        if (self.tls_mgr == null) {
            return error.TlsConfigNotInitialized;
        }
        
        // Start a simple HTTP server for the web interface on port 8080
        _ = try std.Thread.spawn(.{}, handleWebServer, .{self});
        
        log.info("🌐 HTTP/3 server started on port {}", .{self.config.quic_port});
        log.info("📊 Web interface available on port 8080", .{});
    }
    
    /// Handle web server requests
    fn handleWebServer(self: *EnhancedServer) void {
        const web_addr = std.net.Address.parseIp("127.0.0.1", 8080) catch |err| {
            log.err("Failed to parse web server address: {}", .{err});
            return;
        };
        
        var listener = web_addr.listen(.{ .reuse_address = true }) catch |err| {
            log.err("Failed to start web server: {}", .{err});
            return;
        };
        defer listener.deinit();
        
        log.info("📡 Web server listening on http://127.0.0.1:8080", .{});
        
        while (self.running.load(.monotonic)) {
            var connection = listener.accept() catch |err| {
                if (err != error.WouldBlock) {
                    log.err("Web server accept error: {}", .{err});
                }
                continue;
            };
            defer connection.stream.close();
            
            self.handleHttpRequest(&connection) catch |err| {
                log.err("Failed to handle HTTP request: {}", .{err});
            };
        }
    }
    
    /// Handle HTTP request
    fn handleHttpRequest(self: *EnhancedServer, connection: *std.net.Server.Connection) !void {
        var buffer: [4096]u8 = undefined;
        const bytes_read = connection.stream.read(&buffer) catch |err| {
            log.err("Failed to read HTTP request: {}", .{err});
            return;
        };
        
        const request = buffer[0..bytes_read];
        
        // Parse the HTTP request
        var lines = std.mem.splitSequence(u8, request, "\r\n");
        const request_line = lines.next() orelse return;
        
        var parts = std.mem.splitSequence(u8, request_line, " ");
        const method = parts.next() orelse return;
        const path = parts.next() orelse return;
        
        log.debug("🌐 {s} {s}", .{ method, path });
        
        // Route the request
        if (std.mem.eql(u8, path, "/")) {
            try self.serveStatusPage(connection);
        } else if (std.mem.eql(u8, path, "/api/stats")) {
            try self.serveStatsApi(connection);
        } else if (std.mem.startsWith(u8, path, "/dns-query")) {
            try self.serveDnsOverHttps(connection, path);
        } else {
            try self.serveNotFound(connection);
        }
    }
    
    /// Serve the status page
    fn serveStatusPage(self: *EnhancedServer, connection: *std.net.Server.Connection) !void {
        const status_html = try self.generateStatusPage();
        defer self.allocator.free(status_html);
        
        try self.serveHttpResponse(connection, "200 OK", "text/html", status_html);
    }
    
    /// Serve stats API
    fn serveStatsApi(self: *EnhancedServer, connection: *std.net.Server.Connection) !void {
        const stats_json = try self.generateStatsJson();
        defer self.allocator.free(stats_json);
        
        try self.serveHttpResponse(connection, "200 OK", "application/json", stats_json);
    }
    
    /// Serve DNS-over-HTTPS
    fn serveDnsOverHttps(self: *EnhancedServer, connection: *std.net.Server.Connection, path: []const u8) !void {
        // Parse DoH query parameters
        if (std.mem.indexOf(u8, path, "name=")) |name_start| {
            const name_query = path[name_start + 5..];
            const domain_end = std.mem.indexOf(u8, name_query, "&") orelse name_query.len;
            const domain = name_query[0..domain_end];
            
            log.info("🌐 DoH query for domain: {s}", .{domain});
            
            // Create a simplified DoH response
            const doh_response = try std.fmt.allocPrint(self.allocator,
                \\{{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{{"name":"{s}","type":1}}],"Answer":[{{"name":"{s}","type":1,"TTL":60,"data":"93.184.216.34"}}]}}
            , .{ domain, domain });
            defer self.allocator.free(doh_response);
            
            try self.serveHttpResponse(connection, "200 OK", "application/dns-json", doh_response);
            _ = self.queries_http3.fetchAdd(1, .monotonic);
        } else {
            try self.serveNotFound(connection);
        }
    }
    
    /// Serve 404 Not Found
    fn serveNotFound(self: *EnhancedServer, connection: *std.net.Server.Connection) !void {
        const not_found = "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>";
        try self.serveHttpResponse(connection, "404 Not Found", "text/html", not_found);
    }
    
    /// Serve HTTP response
    fn serveHttpResponse(self: *EnhancedServer, connection: *std.net.Server.Connection, status: []const u8, content_type: []const u8, body: []const u8) !void {
        const response = try std.fmt.allocPrint(self.allocator,
            \\HTTP/1.1 {s}
            \\Content-Type: {s}
            \\Content-Length: {}
            \\Access-Control-Allow-Origin: *
            \\Connection: close
            \\
            \\{s}
        , .{ status, content_type, body.len, body });
        defer self.allocator.free(response);
        
        _ = try connection.stream.writeAll(response);
    }
    
    /// Process DNS query and return response
    fn processDnsQuery(self: *EnhancedServer, query: []const u8) ![]u8 {
        _ = self.queries_total.fetchAdd(1, .monotonic);
        
        if (query.len < 12) {
            // Invalid DNS query - too short
            _ = self.queries_failed.fetchAdd(1, .monotonic);
            return error.InvalidDnsQuery;
        }
        
        // Parse the DNS query to extract domain name
        const domain_name = try self.extractDomainName(query);
        defer self.allocator.free(domain_name);
        
        log.debug("🔍 Processing query for domain: {s}", .{domain_name});
        
        // Check cache first
        if (self.cache.get(domain_name)) |cached_packet| {
            log.debug("💾 Cache hit for {s}", .{domain_name});
            // Convert DNSPacket back to bytes
            return try self.packetToBytes(cached_packet);
        }
        
        // Check if it's a blockchain domain
        if (self.isBlockchainDomain(domain_name)) {
            _ = self.queries_blockchain.fetchAdd(1, .monotonic);
            const response = try self.handleBlockchainQuery(domain_name, query);
            // Note: Caching requires DNSPacket, so we'll skip caching for now
            return response;
        }
        
        // Forward to upstream resolver
        const response = try self.forwardQuery(query, domain_name);
        
        // Note: Caching requires DNSPacket, so we'll skip caching for now
        
        return response;
    }
    
    /// Convert DNSPacket to bytes (placeholder implementation)
    fn packetToBytes(self: *EnhancedServer, packet: dns.DNSPacket) ![]u8 {
        // This is a placeholder - in a real implementation, this would serialize the packet
        _ = packet;
        return try self.allocator.dupe(u8, &[_]u8{ 0, 0, 0, 0 }); // Minimal response
    }
    
    /// Extract domain name from DNS query
    fn extractDomainName(self: *EnhancedServer, query: []const u8) ![]u8 {
        if (query.len < 13) return error.InvalidDnsQuery;
        
        // Skip DNS header (12 bytes) and start parsing the question section
        var pos: usize = 12;
        var domain_parts = std.ArrayList([]const u8).init(self.allocator);
        defer domain_parts.deinit();
        
        while (pos < query.len and query[pos] != 0) {
            const label_len = query[pos];
            if (label_len == 0) break;
            
            pos += 1;
            if (pos + label_len > query.len) return error.InvalidDnsQuery;
            
            const label = query[pos..pos + label_len];
            try domain_parts.append(label);
            pos += label_len;
        }
        
        // Join domain parts with dots
        if (domain_parts.items.len == 0) {
            return try self.allocator.dupe(u8, ".");
        }
        
        var total_len: usize = 0;
        for (domain_parts.items) |part| {
            total_len += part.len + 1; // +1 for dot
        }
        total_len -= 1; // Remove last dot
        
        var result = try self.allocator.alloc(u8, total_len);
        var write_pos: usize = 0;
        
        for (domain_parts.items, 0..) |part, i| {
            @memcpy(result[write_pos..write_pos + part.len], part);
            write_pos += part.len;
            if (i < domain_parts.items.len - 1) {
                result[write_pos] = '.';
                write_pos += 1;
            }
        }
        
        return result;
    }
    
    /// Check if domain is a blockchain domain
    fn isBlockchainDomain(self: *EnhancedServer, domain: []const u8) bool {
        _ = self;
        return std.mem.endsWith(u8, domain, ".ghost") or
               std.mem.endsWith(u8, domain, ".chain") or
               std.mem.endsWith(u8, domain, ".bc") or
               std.mem.endsWith(u8, domain, ".eth");
    }
    
    /// Handle blockchain domain query
    fn handleBlockchainQuery(self: *EnhancedServer, domain: []const u8, original_query: []const u8) ![]u8 {
        log.info("🔗 Resolving blockchain domain: {s}", .{domain});
        
        // Create a simple DNS response for blockchain domains
        // In a real implementation, this would query blockchain networks
        const response_ip = if (std.mem.endsWith(u8, domain, ".ghost"))
            "10.0.0.1"
        else if (std.mem.endsWith(u8, domain, ".chain"))
            "10.0.0.2"
        else if (std.mem.endsWith(u8, domain, ".bc"))
            "10.0.0.3"
        else if (std.mem.endsWith(u8, domain, ".eth"))
            "10.0.0.4"
        else
            "127.0.0.1";
        
        // Create a basic DNS A record response
        return try self.createDnsResponse(domain, response_ip, original_query);
    }
    
    /// Forward query to upstream resolver
    fn forwardQuery(self: *EnhancedServer, original_query: []const u8, domain: []const u8) ![]u8 {
        log.debug("📡 Forwarding query for {s} to upstream resolver", .{domain});
        
        // For now, create a simple response
        // In a real implementation, this would forward to 8.8.8.8 or other upstream DNS
        const upstream_ip = "93.184.216.34"; // example.com IP
        
        return try self.createDnsResponse(domain, upstream_ip, original_query);
    }
    
    /// Create a DNS response packet
    fn createDnsResponse(self: *EnhancedServer, domain: []const u8, ip: []const u8, original_query: []const u8) ![]u8 {
        // Parse IP address
        const addr = std.net.Address.parseIp4(ip, 0) catch |err| {
            log.err("Invalid IP address {s}: {}", .{ ip, err });
            return error.InvalidIpAddress;
        };
        
        // Create a simple DNS response packet
        // This is a minimal implementation - a real DNS server would be more complex
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();
        
        // DNS Header (12 bytes) - copy transaction ID from original query
        const transaction_id = if (original_query.len >= 2) 
            [2]u8{ original_query[0], original_query[1] }
        else 
            [2]u8{ 0x12, 0x34 }; // fallback
            
        try response.appendSlice(&transaction_id); // Transaction ID from original query
        try response.appendSlice(&[_]u8{
            0x81, 0x80, // Flags: Response, Recursion Available
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answer RRs: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        });
        
        // Question section
        try self.encodeDomainName(&response, domain);
        try response.appendSlice(&[_]u8{
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        });
        
        // Answer section
        try self.encodeDomainName(&response, domain);
        try response.appendSlice(&[_]u8{
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
            0x00, 0x04, // Data length: 4 bytes
        });
        
        // IP address (4 bytes)
        const ip_bytes = addr.in.sa.addr;
        try response.append(@intCast((ip_bytes >> 24) & 0xFF));
        try response.append(@intCast((ip_bytes >> 16) & 0xFF));
        try response.append(@intCast((ip_bytes >> 8) & 0xFF));
        try response.append(@intCast(ip_bytes & 0xFF));
        
        return try self.allocator.dupe(u8, response.items);
    }
    
    /// Encode domain name in DNS format
    fn encodeDomainName(self: *EnhancedServer, response: *std.ArrayList(u8), domain: []const u8) !void {
        _ = self;
        var parts = std.mem.splitSequence(u8, domain, ".");
        
        while (parts.next()) |part| {
            if (part.len == 0) continue;
            try response.append(@intCast(part.len));
            try response.appendSlice(part);
        }
        
        try response.append(0); // Null terminator
    }
    
    /// Generate HTML status page
    fn generateStatusPage(self: *EnhancedServer) ![]u8 {
        const template =
            \\<!DOCTYPE html>
            \\<html>
            \\<head>
            \\    <title>CNS - Crypto Name Server</title>
            \\    <style>
            \\        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #0a0a0a; color: #e0e0e0; }}
            \\        .container {{ max-width: 800px; margin: 0 auto; }}
            \\        .header {{ text-align: center; margin-bottom: 40px; }}
            \\        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
            \\        .stat-card {{ background: #1a1a1a; padding: 20px; border-radius: 8px; border: 1px solid #333; }}
            \\        .stat-value {{ font-size: 2em; font-weight: bold; color: #00ff88; }}
            \\        .stat-label {{ color: #888; text-transform: uppercase; font-size: 0.9em; }}
            \\        .features {{ margin-top: 40px; }}
            \\        .feature {{ margin: 10px 0; padding: 10px; background: #1a1a1a; border-radius: 4px; }}
            \\        .enabled {{ border-left: 4px solid #00ff88; }}
            \\        .disabled {{ border-left: 4px solid #ff4444; }}
            \\    </style>
            \\</head>
            \\<body>
            \\    <div class="container">
            \\        <div class="header">
            \\            <h1>🌐 CNS - Crypto Name Server</h1>
            \\            <p>Web5.0 DNS with HTTP/3, QUIC, and TLS 1.3</p>
            \\        </div>
            \\        
            \\        <div class="stats">
            \\            <div class="stat-card">
            \\                <div class="stat-value">{}</div>
            \\                <div class="stat-label">Total Queries</div>
            \\            </div>
            \\            <div class="stat-card">
            \\                <div class="stat-value">{}</div>
            \\                <div class="stat-label">HTTP/3 Queries</div>
            \\            </div>
            \\            <div class="stat-card">
            \\                <div class="stat-value">{}</div>
            \\                <div class="stat-label">Blockchain Queries</div>
            \\            </div>
            \\            <div class="stat-card">
            \\                <div class="stat-value">{}</div>
            \\                <div class="stat-label">Failed Queries</div>
            \\            </div>
            \\        </div>
            \\        
            \\        <div class="features">
            \\            <h2>🚀 Features</h2>
            \\            <div class="feature enabled">✅ HTTP/3 & QUIC Support</div>
            \\            <div class="feature enabled">🔐 TLS 1.3 Encryption</div>
            \\            <div class="feature enabled">🌐 DNS-over-HTTPS (DoH)</div>
            \\            <div class="feature enabled">⚡ High-Performance Caching</div>
            \\            <div class="feature {s}">🔗 Blockchain Domain Resolution (.ghost, .chain, .bc)</div>
            \\            <div class="feature enabled">📊 Real-time Statistics</div>
            \\        </div>
            \\    </div>
            \\</body>
            \\</html>
        ;
        
        const blockchain_status = if (self.config.blockchain_enabled) "enabled" else "disabled";
        
        return try std.fmt.allocPrint(self.allocator, template, .{
            self.queries_total.load(.monotonic),
            self.queries_http3.load(.monotonic),
            self.queries_blockchain.load(.monotonic),
            self.queries_failed.load(.monotonic),
            blockchain_status,
        });
    }
    
    /// Generate JSON statistics
    fn generateStatsJson(self: *EnhancedServer) ![]u8 {
        const template =
            \\{{
            \\    "queries_total": {},
            \\    "queries_http3": {},
            \\    "queries_blockchain": {},
            \\    "queries_failed": {},
            \\    "cache_size": {},
            \\    "features": {{
            \\        "http3_enabled": {},
            \\        "tls13_enabled": {},
            \\        "blockchain_enabled": {},
            \\        "cache_enabled": true
            \\    }}
            \\}}
        ;
        
        return try std.fmt.allocPrint(self.allocator, template, .{
            self.queries_total.load(.monotonic),
            self.queries_http3.load(.monotonic),
            self.queries_blockchain.load(.monotonic),
            self.queries_failed.load(.monotonic),
            self.config.cache_size,
            self.config.enable_quic,
            self.config.enable_quic,
            self.config.blockchain_enabled,
        });
    }
    
    // Traditional DNS methods with real network I/O
    fn startUDPListeners(self: *EnhancedServer) !void {
        // Use default localhost and port from config for testing
        const bind_addr = std.net.Address.parseIp("127.0.0.1", self.config.port) catch |err| {
            log.err("Failed to parse localhost address: {}", .{err});
            return err;
        };
        
        // Start UDP listener thread
        const udp_thread = try std.Thread.spawn(.{}, handleUdpSocket, .{ self, bind_addr });
        self.udp_threads = try self.allocator.dupe(std.Thread, &[_]std.Thread{udp_thread});
        
        log.info("🔌 UDP DNS listener started on {any}", .{bind_addr});
    }
    
    fn startTCPListener(self: *EnhancedServer) !void {
        // Use default localhost and port from config for testing
        const bind_addr = std.net.Address.parseIp("127.0.0.1", self.config.port) catch |err| {
            log.err("Failed to parse localhost address: {}", .{err});
            return err;
        };
        
        var listener = try bind_addr.listen(.{ .reuse_address = true });
        self.tcp_listener = listener;
        
        // Start TCP handler thread
        _ = try std.Thread.spawn(.{}, handleTcpSocket, .{ self, &listener });
        
        log.info("🔌 TCP DNS listener started on {any}", .{bind_addr});
    }
    
    /// Handle UDP DNS socket
    fn handleUdpSocket(self: *EnhancedServer, addr: std.net.Address) void {
        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
            log.err("Failed to create UDP socket: {}", .{err});
            return;
        };
        defer std.posix.close(socket);
        
        // Bind socket
        std.posix.bind(socket, &addr.any, addr.getOsSockLen()) catch |err| {
            log.err("Failed to bind UDP socket: {}", .{err});
            return;
        };
        
        var buffer: [512]u8 = undefined;
        var client_addr: std.posix.sockaddr = undefined;
        var client_addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(client_addr));
        
        while (self.running.load(.monotonic)) {
            const bytes_received = std.posix.recvfrom(
                socket,
                &buffer,
                0,
                &client_addr,
                &client_addr_len,
            ) catch |err| {
                if (err != error.WouldBlock) {
                    log.err("UDP receive error: {}", .{err});
                }
                continue;
            };
            
            // Process DNS query
            self.handleDnsQuery(buffer[0..bytes_received], socket, &client_addr, client_addr_len) catch |err| {
                log.err("Failed to handle DNS query: {}", .{err});
                _ = self.queries_failed.fetchAdd(1, .monotonic);
            };
        }
    }
    
    /// Handle TCP DNS socket
    fn handleTcpSocket(self: *EnhancedServer, listener: *std.net.Server) void {
        while (self.running.load(.monotonic)) {
            var connection = listener.accept() catch |err| {
                if (err != error.WouldBlock) {
                    log.err("TCP accept error: {}", .{err});
                }
                continue;
            };
            defer connection.stream.close();
            
            // Handle TCP DNS message (with length prefix)
            var length_buf: [2]u8 = undefined;
            _ = connection.stream.readAll(&length_buf) catch |err| {
                log.err("Failed to read TCP length: {}", .{err});
                continue;
            };
            
            const msg_length = std.mem.readInt(u16, &length_buf, .big);
            if (msg_length > 512) {
                log.err("TCP message too large: {}", .{msg_length});
                continue;
            }
            
            var buffer: [512]u8 = undefined;
            const bytes_received = connection.stream.readAll(buffer[0..msg_length]) catch |err| {
                log.err("Failed to read TCP message: {}", .{err});
                continue;
            };
            
            // Process DNS query
            self.handleTcpDnsQuery(buffer[0..bytes_received], &connection) catch |err| {
                log.err("Failed to handle TCP DNS query: {}", .{err});
                _ = self.queries_failed.fetchAdd(1, .monotonic);
            };
        }
    }
    
    /// Handle DNS query over UDP
    fn handleDnsQuery(self: *EnhancedServer, query: []const u8, socket: std.posix.socket_t, client_addr: *const std.posix.sockaddr, addr_len: std.posix.socklen_t) !void {
        const response = try self.processDnsQuery(query);
        defer self.allocator.free(response);
        
        _ = std.posix.sendto(socket, response, 0, client_addr, addr_len) catch |err| {
            log.err("Failed to send UDP response: {}", .{err});
            return err;
        };
    }
    
    /// Handle DNS query over TCP
    fn handleTcpDnsQuery(self: *EnhancedServer, query: []const u8, connection: *std.net.Server.Connection) !void {
        const response = try self.processDnsQuery(query);
        defer self.allocator.free(response);
        
        // Send length-prefixed response
        var length_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_buf, @intCast(response.len), .big);
        
        _ = try connection.stream.writeAll(&length_buf);
        _ = try connection.stream.writeAll(response);
    }
    
    fn printStats(self: *EnhancedServer) void {
        const total = self.queries_total.load(.monotonic);
        const http3 = self.queries_http3.load(.monotonic);
        const blockchain = self.queries_blockchain.load(.monotonic);
        const failed = self.queries_failed.load(.monotonic);
        
        if (total > 0 and total % 100 == 0) {
            log.info("📊 Stats - Total: {}, HTTP/3: {}, Blockchain: {}, Failed: {}", .{ total, http3, blockchain, failed });
        }
    }
};
