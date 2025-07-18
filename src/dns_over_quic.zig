//! DNS-over-QUIC (DoQ) Implementation using zquic and ghostnet
//! RFC 9250 compliant DNS transport over QUIC protocol

const std = @import("std");
const zquic = @import("zquic");
const ghostnet = @import("ghostnet");
const dns = @import("dns.zig");
const tls_manager = @import("tls_manager.zig");

const log = std.log.scoped(.dns_over_quic);

pub const DoQServer = struct {
    allocator: std.mem.Allocator,
    quic_server: *zquic.QuicServer,
    tls_manager: *tls_manager.TlsManager,
    dns_handler: DnsHandler,
    
    // Statistics
    connections_total: std.atomic.Value(u64),
    queries_processed: std.atomic.Value(u64),
    bytes_transferred: std.atomic.Value(u64),
    
    // Configuration
    config: DoQConfig,
    running: std.atomic.Value(bool),
    
    pub const DoQConfig = struct {
        bind_address: std.net.Address,
        max_connections: u32 = 1000,
        idle_timeout_ms: u32 = 30000,
        max_bidi_streams: u32 = 100,
        max_uni_streams: u32 = 3,
        initial_max_stream_data: u64 = 65536,
        initial_max_data: u64 = 1048576,
        initial_max_streams_bidi: u64 = 100,
        initial_max_streams_uni: u64 = 3,
        
        // DNS-specific settings
        max_query_size: u32 = 65535,
        query_timeout_ms: u32 = 5000,
        enable_0rtt: bool = false, // Disabled for security
    };
    
    pub const DnsHandler = struct {
        callback: *const fn (query: []const u8, context: *anyopaque) anyerror![]u8,
        context: *anyopaque,
    };
    
    pub fn init(
        allocator: std.mem.Allocator,
        config: DoQConfig,
        tls_mgr: *tls_manager.TlsManager,
        dns_handler: DnsHandler,
    ) !*DoQServer {
        // Create QUIC server configuration
        const server_config = zquic.QuicServerConfig{
            .bind_address = config.bind_address,
            .tls_config = tls_mgr.getServerConfig() orelse return error.TlsConfigRequired,
            
            // Connection limits
            .max_connections = config.max_connections,
            .idle_timeout = std.time.Duration.fromMillis(config.idle_timeout_ms),
            
            // Stream limits
            .max_bidi_streams = config.max_bidi_streams,
            .max_uni_streams = config.max_uni_streams,
            .initial_max_stream_data = config.initial_max_stream_data,
            .initial_max_data = config.initial_max_data,
            .initial_max_streams_bidi = config.initial_max_streams_bidi,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            
            // Disable 0-RTT for security
            .enable_0rtt = config.enable_0rtt,
        };
        
        const quic_server = try zquic.QuicServer.init(allocator, server_config);
        
        const server = try allocator.create(DoQServer);
        server.* = DoQServer{
            .allocator = allocator,
            .quic_server = quic_server,
            .tls_manager = tls_mgr,
            .dns_handler = dns_handler,
            .connections_total = std.atomic.Value(u64).init(0),
            .queries_processed = std.atomic.Value(u64).init(0),
            .bytes_transferred = std.atomic.Value(u64).init(0),
            .config = config,
            .running = std.atomic.Value(bool).init(false),
        };
        
        // Set up QUIC event handlers
        try server.setupEventHandlers();
        
        return server;
    }
    
    pub fn deinit(self: *DoQServer) void {
        self.stop();
        self.quic_server.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *DoQServer) !void {
        self.running.store(true, .monotonic);
        
        log.info("🚀 Starting DNS-over-QUIC server on {}", .{self.config.bind_address});
        log.info("🔒 TLS 1.3 encryption enabled", .{});
        log.info("📊 Max connections: {}, Max query size: {} bytes", .{ 
            self.config.max_connections, 
            self.config.max_query_size 
        });
        
        try self.quic_server.start();
        
        log.info("✅ DNS-over-QUIC server started successfully", .{});
        
        // Run the server
        try self.run();
    }
    
    pub fn stop(self: *DoQServer) void {
        self.running.store(false, .monotonic);
        self.quic_server.stop();
        
        log.info("🛑 DNS-over-QUIC server stopped", .{});
    }
    
    /// Set up QUIC event handlers for DNS processing
    fn setupEventHandlers(self: *DoQServer) !void {
        // Handle new connections
        try self.quic_server.setConnectionHandler(struct {
            server: *DoQServer,
            
            pub fn handle(server: *DoQServer, connection: *zquic.QuicConnection) void {
                server.connections_total.fetchAdd(1, .monotonic);
                
                log.debug("🔗 New DoQ connection from {}", .{connection.peer_address});
                
                // Set up stream handlers for this connection
                server.setupStreamHandlers(connection) catch |err| {
                    log.err("Failed to setup stream handlers: {}", .{err});
                };
            }
        }{ .server = self });
        
        // Handle connection closed
        try self.quic_server.setConnectionClosedHandler(struct {
            server: *DoQServer,
            
            pub fn handle(server: *DoQServer, connection: *zquic.QuicConnection, reason: zquic.CloseReason) void {
                _ = server;
                _ = reason;
                log.debug("📴 DoQ connection closed from {}", .{connection.peer_address});
            }
        }{ .server = self });
    }
    
    /// Set up stream handlers for DNS queries
    fn setupStreamHandlers(self: *DoQServer, connection: *zquic.QuicConnection) !void {
        // Handle bidirectional streams for DNS queries
        try connection.setStreamHandler(struct {
            server: *DoQServer,
            
            pub fn handle(server: *DoQServer, stream: *zquic.QuicStream) void {
                server.handleDnsQuery(stream) catch |err| {
                    log.err("DNS query handling failed: {}", .{err});
                };
            }
        }{ .server = self });
    }
    
    /// Handle DNS query on a QUIC stream
    fn handleDnsQuery(self: *DoQServer, stream: *zquic.QuicStream) !void {
        // Read DNS query length (2 bytes, big-endian)
        var length_buf: [2]u8 = undefined;
        const length_read = try stream.read(&length_buf);
        if (length_read != 2) {
            return error.InvalidQueryLength;
        }
        
        const query_length = std.mem.readInt(u16, &length_buf, .big);
        if (query_length == 0 or query_length > self.config.max_query_size) {
            return error.QueryTooLarge;
        }
        
        // Read DNS query data
        const query_data = try self.allocator.alloc(u8, query_length);
        defer self.allocator.free(query_data);
        
        const data_read = try stream.read(query_data);
        if (data_read != query_length) {
            return error.IncompleteQuery;
        }
        
        // Update statistics
        self.queries_processed.fetchAdd(1, .monotonic);
        self.bytes_transferred.fetchAdd(query_length + 2, .monotonic);
        
        log.debug("📥 Received DNS query: {} bytes", .{query_length});
        
        // Process DNS query
        const response = try self.dns_handler.callback(query_data, self.dns_handler.context);
        defer self.allocator.free(response);
        
        // Send DNS response
        try self.sendDnsResponse(stream, response);
        
        log.debug("📤 Sent DNS response: {} bytes", .{response.len});
    }
    
    /// Send DNS response on QUIC stream
    fn sendDnsResponse(self: *DoQServer, stream: *zquic.QuicStream, response: []const u8) !void {
        if (response.len > self.config.max_query_size) {
            return error.ResponseTooLarge;
        }
        
        // Send response length (2 bytes, big-endian)
        var length_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_buf, @intCast(response.len), .big);
        
        try stream.write(&length_buf);
        try stream.write(response);
        try stream.flush();
        
        // Update statistics
        self.bytes_transferred.fetchAdd(response.len + 2, .monotonic);
    }
    
    /// Main server run loop
    fn run(self: *DoQServer) !void {
        while (self.running.load(.monotonic)) {
            // Process QUIC events
            try self.quic_server.processEvents();
            
            // Small sleep to prevent busy waiting
            std.time.sleep(std.time.ns_per_ms);
        }
    }
    
    /// Get server statistics
    pub fn getStats(self: *DoQServer) DoQStats {
        return DoQStats{
            .connections_total = self.connections_total.load(.monotonic),
            .queries_processed = self.queries_processed.load(.monotonic),
            .bytes_transferred = self.bytes_transferred.load(.monotonic),
            .active_connections = self.quic_server.getActiveConnections(),
        };
    }
};

pub const DoQStats = struct {
    connections_total: u64,
    queries_processed: u64,
    bytes_transferred: u64,
    active_connections: u32,
};

/// DNS-over-QUIC client for upstream forwarding
pub const DoQClient = struct {
    allocator: std.mem.Allocator,
    quic_client: *zquic.QuicClient,
    tls_manager: *tls_manager.TlsManager,
    
    pub fn init(
        allocator: std.mem.Allocator,
        tls_mgr: *tls_manager.TlsManager,
    ) !*DoQClient {
        const client_config = zquic.QuicClientConfig{
            .tls_config = tls_mgr.getClientConfig() orelse return error.TlsConfigRequired,
            .idle_timeout = std.time.Duration.fromSecs(30),
            .keep_alive_interval = std.time.Duration.fromSecs(15),
        };
        
        const quic_client = try zquic.QuicClient.init(allocator, client_config);
        
        const client = try allocator.create(DoQClient);
        client.* = DoQClient{
            .allocator = allocator,
            .quic_client = quic_client,
            .tls_manager = tls_mgr,
        };
        
        return client;
    }
    
    pub fn deinit(self: *DoQClient) void {
        self.quic_client.deinit();
        self.allocator.destroy(self);
    }
    
    /// Query upstream DNS server using DNS-over-QUIC
    pub fn query(self: *DoQClient, server_address: std.net.Address, dns_query: []const u8) ![]u8 {
        // Connect to upstream server
        const connection = try self.quic_client.connect(server_address);
        defer connection.close();
        
        // Open bidirectional stream for DNS query
        const stream = try connection.openBidiStream();
        defer stream.close();
        
        // Send query length
        var length_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_buf, @intCast(dns_query.len), .big);
        try stream.write(&length_buf);
        
        // Send query data
        try stream.write(dns_query);
        try stream.flush();
        
        // Read response length
        var response_length_buf: [2]u8 = undefined;
        const length_read = try stream.read(&response_length_buf);
        if (length_read != 2) {
            return error.InvalidResponseLength;
        }
        
        const response_length = std.mem.readInt(u16, &response_length_buf, .big);
        if (response_length == 0) {
            return error.EmptyResponse;
        }
        
        // Read response data
        const response = try self.allocator.alloc(u8, response_length);
        const data_read = try stream.read(response);
        if (data_read != response_length) {
            self.allocator.free(response);
            return error.IncompleteResponse;
        }
        
        return response;
    }
};
