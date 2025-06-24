const std = @import("std");
const dns = @import("dns.zig");
const cache = @import("cache.zig");
const config = @import("config.zig");

const log = std.log.scoped(.cns_server);

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    cache: cache.DNSCache,
    
    // Network listeners
    udp_threads: []std.Thread,
    tcp_listener: ?std.net.Server,
    quic_listener: ?*QuicListener, // TODO: Implement QUIC
    
    // Statistics
    queries_total: std.atomic.Value(u64),
    queries_failed: std.atomic.Value(u64),
    queries_blockchain: std.atomic.Value(u64),
    
    // Control
    running: std.atomic.Value(bool),
    
    pub fn init(allocator: std.mem.Allocator, config_path: ?[]const u8) !Server {
        const cfg = try config.Config.loadFromFile(allocator, config_path);
        const dns_cache = try cache.DNSCache.init(allocator, cfg.cache_size);
        
        return Server{
            .allocator = allocator,
            .config = cfg,
            .cache = dns_cache,
            .udp_threads = &[_]std.Thread{},
            .tcp_listener = null,
            .quic_listener = null,
            .queries_total = std.atomic.Value(u64).init(0),
            .queries_failed = std.atomic.Value(u64).init(0),
            .queries_blockchain = std.atomic.Value(u64).init(0),
            .running = std.atomic.Value(bool).init(false),
        };
    }
    
    pub fn deinit(self: *Server) void {
        self.stop();
        self.cache.deinit();
        self.config.deinit();
        self.allocator.free(self.udp_threads);
    }
    
    pub fn start(self: *Server) !void {
        self.running.store(true, .monotonic);
        
        log.info("🚀 Starting CNS server...", .{});
        log.info("📊 Cache size: {} entries", .{self.config.cache_size});
        log.info("🌐 Blockchain TLDs: .ghost, .chain, .bc (root zone)", .{});
        
        // Start UDP listeners
        if (self.config.enable_udp) {
            try self.startUDPListeners();
        }
        
        // Start TCP listener
        if (self.config.enable_tcp) {
            try self.startTCPListener();
        }
        
        // Start QUIC listener
        if (self.config.enable_quic) {
            log.info("🔐 QUIC support coming soon...", .{});
            // TODO: Implement QUIC
        }
        
        log.info("✅ CNS server started successfully!", .{});
        
        // Keep running until stopped
        while (self.running.load(.monotonic)) {
            std.time.sleep(std.time.ns_per_s);
            self.printStats();
        }
    }
    
    pub fn stop(self: *Server) void {
        self.running.store(false, .monotonic);
        
        // Stop all listeners
        for (self.udp_threads) |thread| {
            thread.join();
        }
        
        if (self.tcp_listener) |*listener| {
            listener.deinit();
        }
    }
    
    fn startUDPListeners(self: *Server) !void {
        var threads = std.ArrayList(std.Thread).init(self.allocator);
        defer threads.deinit();
        
        for (self.config.bind_addresses) |addr| {
            log.info("🔊 Starting UDP listener on {any}", .{addr});
            
            const thread = try std.Thread.spawn(.{}, udpListenerThread, .{ self, addr });
            try threads.append(thread);
        }
        
        self.udp_threads = try threads.toOwnedSlice();
    }
    
    fn startTCPListener(self: *Server) !void {
        _ = self; // TODO: Use when implementing TCP listener
        // TODO: Implement TCP listener
        log.info("📡 TCP listener coming soon...", .{});
    }
    
    fn udpListenerThread(self: *Server, bind_addr: std.net.Address) !void {
        const socket = try std.posix.socket(
            bind_addr.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer std.posix.close(socket);
        
        try std.posix.bind(socket, &bind_addr.any, bind_addr.getOsSockLen());
        
        var buf: [4096]u8 = undefined;
        var client_addr: std.posix.sockaddr = undefined;
        var client_addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(client_addr));
        
        while (self.running.load(.monotonic)) {
            const recv_len = std.posix.recvfrom(
                socket,
                &buf,
                0,
                &client_addr,
                &client_addr_len,
            ) catch |err| {
                if (err == error.WouldBlock) continue;
                log.err("UDP receive error: {any}", .{err});
                continue;
            };
            
            if (recv_len == 0) continue;
            
            // Process DNS query
            self.handleQuery(buf[0..recv_len], socket, client_addr, client_addr_len) catch |err| {
                log.err("Query handling error: {any}", .{err});
                _ = self.queries_failed.fetchAdd(1, .monotonic);
            };
        }
    }
    
    fn handleQuery(
        self: *Server,
        data: []const u8,
        socket: std.posix.socket_t,
        client_addr: std.posix.sockaddr,
        client_addr_len: std.posix.socklen_t,
    ) !void {
        _ = self.queries_total.fetchAdd(1, .monotonic);
        
        // Parse DNS packet
        var stream = std.io.fixedBufferStream(data);
        var packet = try dns.DNSPacket.deserialize(self.allocator, stream.reader());
        defer packet.deinit();
        
        if (packet.header.isQuery() and packet.questions.len > 0) {
            const question = packet.questions[0];
            
            if (self.config.log_queries) {
                log.info("Query: {s} ({s})", .{ question.name, question.qtype.toString() });
            }
            
            // Check cache first
            const cache_key = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}:{d}",
                .{ question.name, @intFromEnum(question.qtype), @intFromEnum(question.qclass) },
            );
            defer self.allocator.free(cache_key);
            
            if (self.cache.get(cache_key)) |cached_response| {
                // Send cached response
                var response_buf: [4096]u8 = undefined;
                var response_stream = std.io.fixedBufferStream(&response_buf);
                
                var response = cached_response;
                response.header.id = packet.header.id; // Update transaction ID
                try response.serialize(response_stream.writer());
                
                _ = try std.posix.sendto(
                    socket,
                    response_stream.getWritten(),
                    0,
                    &client_addr,
                    client_addr_len,
                );
                return;
            }
            
            // Handle based on domain
            var response: dns.DNSPacket = undefined;
            
            // Check if it's a blockchain domain
            var is_blockchain = false;
            for (self.config.blockchain_tlds) |tld| {
                const tld_with_dot = try std.fmt.allocPrint(self.allocator, ".{s}", .{tld});
                defer self.allocator.free(tld_with_dot);
                
                if (std.mem.endsWith(u8, question.name, tld_with_dot)) {
                    is_blockchain = true;
                    break;
                }
            }
            
            if (is_blockchain) {
                // Blockchain domain
                _ = self.queries_blockchain.fetchAdd(1, .monotonic);
                response = try self.resolveBlockchainDomain(&packet);
            } else {
                // Traditional domain - forward to upstream
                response = try self.forwardToUpstream(&packet);
            }
            defer response.deinit();
            
            // Cache the response
            if (response.header.getRcode() == dns.RCODE_OK and response.answers.len > 0) {
                const ttl = if (response.answers.len > 0) response.answers[0].ttl else self.config.default_ttl;
                try self.cache.put(cache_key, response, ttl);
            }
            
            // Send response
            var response_buf: [4096]u8 = undefined;
            var response_stream = std.io.fixedBufferStream(&response_buf);
            try response.serialize(response_stream.writer());
            
            _ = try std.posix.sendto(
                socket,
                response_stream.getWritten(),
                0,
                &client_addr,
                client_addr_len,
            );
        }
    }
    
    fn resolveBlockchainDomain(self: *Server, query: *const dns.DNSPacket) !dns.DNSPacket {
        // TODO: Implement actual blockchain resolution
        const question = query.questions[0];
        
        // Determine which blockchain TLD
        var tld_type: []const u8 = "";
        if (std.mem.endsWith(u8, question.name, ".bc")) {
            tld_type = ".bc (root zone - no registration needed)";
        } else if (std.mem.endsWith(u8, question.name, ".ghost")) {
            tld_type = ".ghost";
        } else if (std.mem.endsWith(u8, question.name, ".chain")) {
            tld_type = ".chain";
        }
        
        log.info("🔗 Blockchain query for {s} ({s})", .{ question.name, tld_type });
        
        // For now, return NXDOMAIN
        var response = dns.DNSPacket.init(self.allocator);
        response.header = query.header;
        response.header.setResponse();
        response.header.setRcode(dns.RCODE_NAME_ERROR);
        
        // Copy question
        response.questions = try self.allocator.dupe(dns.DNSQuestion, query.questions);
        response.header.qdcount = @intCast(response.questions.len);
        
        log.warn("Blockchain resolution not yet implemented", .{});
        
        return response;
    }
    
    fn forwardToUpstream(self: *Server, query: *const dns.DNSPacket) !dns.DNSPacket {
        // Serialize query
        var query_buf: [4096]u8 = undefined;
        var query_stream = std.io.fixedBufferStream(&query_buf);
        try query.serialize(query_stream.writer());
        const query_data = query_stream.getWritten();
        
        // Try each upstream resolver
        for (self.config.upstream_resolvers) |upstream| {
            const socket = try std.posix.socket(
                upstream.any.family,
                std.posix.SOCK.DGRAM,
                std.posix.IPPROTO.UDP,
            );
            defer std.posix.close(socket);
            
            // Set timeout
            const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
            
            // Send query
            _ = std.posix.sendto(
                socket,
                query_data,
                0,
                &upstream.any,
                upstream.getOsSockLen(),
            ) catch continue;
            
            // Receive response
            var response_buf: [4096]u8 = undefined;
            const recv_len = std.posix.recv(socket, &response_buf, 0) catch continue;
            
            if (recv_len > 0) {
                var response_stream = std.io.fixedBufferStream(response_buf[0..recv_len]);
                return try dns.DNSPacket.deserialize(self.allocator, response_stream.reader());
            }
        }
        
        // All upstreams failed
        var response = dns.DNSPacket.init(self.allocator);
        response.header = query.header;
        response.header.setResponse();
        response.header.setRcode(dns.RCODE_SERVER_FAILURE);
        response.questions = try self.allocator.dupe(dns.DNSQuestion, query.questions);
        response.header.qdcount = @intCast(response.questions.len);
        
        return response;
    }
    
    fn printStats(self: *Server) void {
        const total = self.queries_total.load(.monotonic);
        const failed = self.queries_failed.load(.monotonic);
        const blockchain = self.queries_blockchain.load(.monotonic);
        const cache_stats = self.cache.getStats();
        
        log.info("📊 Stats - Queries: {} | Failed: {} | Blockchain: {} | Cache hit rate: {d:.1}%", .{
            total,
            failed,
            blockchain,
            cache_stats.hitRate() * 100,
        });
    }
};

// Placeholder for QUIC implementation
const QuicListener = struct {
    // TODO: Implement QUIC listener
};

// Tests
test "Server initialization" {
    const allocator = std.testing.allocator;
    
    var server = try Server.init(allocator, null);
    defer server.deinit();
    
    try std.testing.expect(server.config.port == 53);
    try std.testing.expect(server.config.cache_size == 10000);
}