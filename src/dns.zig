const std = @import("std");
const identity_manager = @import("identity_manager.zig");
const web3_resolver = @import("web3_resolver.zig");

// DNS constants
pub const DNS_PORT = 53;
pub const DNS_HEADER_SIZE = 12;
pub const MAX_DOMAIN_LENGTH = 255;
pub const MAX_LABEL_LENGTH = 63;

// DNS opcodes
pub const OPCODE_QUERY = 0;
pub const OPCODE_IQUERY = 1;
pub const OPCODE_STATUS = 2;

// DNS response codes
pub const RCODE_OK = 0;
pub const RCODE_FORMAT_ERROR = 1;
pub const RCODE_SERVER_FAILURE = 2;
pub const RCODE_NAME_ERROR = 3;
pub const RCODE_NOT_IMPLEMENTED = 4;
pub const RCODE_REFUSED = 5;

// DNS record types
pub const RType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    // Web3 extensions
    ENS = 0xFF01,
    GHOST = 0xFF02,
    // Signed DNS extensions
    RRSIG = 46,
    DNSKEY = 48,
    
    pub fn toString(self: RType) []const u8 {
        return switch (self) {
            .A => "A",
            .NS => "NS",
            .CNAME => "CNAME",
            .SOA => "SOA",
            .PTR => "PTR",
            .MX => "MX",
            .TXT => "TXT",
            .AAAA => "AAAA",
            .SRV => "SRV",
            .ENS => "ENS",
            .GHOST => "GHOST",
            .RRSIG => "RRSIG",
            .DNSKEY => "DNSKEY",
        };
    }
};

// DNS classes
pub const RClass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
};

// DNS header structure
pub const DNSHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    
    pub fn isQuery(self: DNSHeader) bool {
        return (self.flags & 0x8000) == 0;
    }
    
    pub fn setResponse(self: *DNSHeader) void {
        self.flags |= 0x8000;
    }
    
    pub fn getOpcode(self: DNSHeader) u4 {
        return @truncate((self.flags >> 11) & 0x0F);
    }
    
    pub fn setOpcode(self: *DNSHeader, opcode: u4) void {
        self.flags = (self.flags & 0x87FF) | (@as(u16, opcode) << 11);
    }
    
    pub fn getRcode(self: DNSHeader) u4 {
        return @truncate(self.flags & 0x0F);
    }
    
    pub fn setRcode(self: *DNSHeader, rcode: u4) void {
        self.flags = (self.flags & 0xFFF0) | rcode;
    }
    
    pub fn serialize(self: DNSHeader, writer: anytype) !void {
        try writer.writeInt(u16, self.id, .big);
        try writer.writeInt(u16, self.flags, .big);
        try writer.writeInt(u16, self.qdcount, .big);
        try writer.writeInt(u16, self.ancount, .big);
        try writer.writeInt(u16, self.nscount, .big);
        try writer.writeInt(u16, self.arcount, .big);
    }
    
    pub fn deserialize(reader: anytype) !DNSHeader {
        return DNSHeader{
            .id = try reader.readInt(u16, .big),
            .flags = try reader.readInt(u16, .big),
            .qdcount = try reader.readInt(u16, .big),
            .ancount = try reader.readInt(u16, .big),
            .nscount = try reader.readInt(u16, .big),
            .arcount = try reader.readInt(u16, .big),
        };
    }
};

// DNS question structure
pub const DNSQuestion = struct {
    name: []const u8,
    qtype: RType,
    qclass: RClass,
    
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *DNSQuestion) void {
        self.allocator.free(self.name);
    }
    
    pub fn serialize(self: DNSQuestion, writer: anytype) !void {
        try serializeDomainName(self.name, writer);
        try writer.writeInt(u16, @intFromEnum(self.qtype), .big);
        try writer.writeInt(u16, @intFromEnum(self.qclass), .big);
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !DNSQuestion {
        const name = try deserializeDomainName(allocator, reader);
        const qtype = try reader.readInt(u16, .big);
        const qclass = try reader.readInt(u16, .big);
        
        return DNSQuestion{
            .name = name,
            .qtype = @enumFromInt(qtype),
            .qclass = @enumFromInt(qclass),
            .allocator = allocator,
        };
    }
};

// DNS resource record
pub const DNSRecord = struct {
    name: []const u8,
    rtype: RType,
    rclass: RClass,
    ttl: u32,
    data: []const u8,
    
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *DNSRecord) void {
        self.allocator.free(self.name);
        self.allocator.free(self.data);
    }
    
    pub fn serialize(self: DNSRecord, writer: anytype) !void {
        try serializeDomainName(self.name, writer);
        try writer.writeInt(u16, @intFromEnum(self.rtype), .big);
        try writer.writeInt(u16, @intFromEnum(self.rclass), .big);
        try writer.writeInt(u32, self.ttl, .big);
        try writer.writeInt(u16, @intCast(self.data.len), .big);
        try writer.writeAll(self.data);
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !DNSRecord {
        const name = try deserializeDomainName(allocator, reader);
        const rtype = try reader.readInt(u16, .big);
        const rclass = try reader.readInt(u16, .big);
        const ttl = try reader.readInt(u32, .big);
        const rdlength = try reader.readInt(u16, .big);
        
        const data = try allocator.alloc(u8, rdlength);
        _ = try reader.read(data);
        
        return DNSRecord{
            .name = name,
            .rtype = @enumFromInt(rtype),
            .rclass = @enumFromInt(rclass),
            .ttl = ttl,
            .data = data,
            .allocator = allocator,
        };
    }
};

// DNS packet structure
pub const DNSPacket = struct {
    header: DNSHeader,
    questions: []DNSQuestion,
    answers: []DNSRecord,
    authorities: []DNSRecord,
    additionals: []DNSRecord,
    
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) DNSPacket {
        return DNSPacket{
            .header = DNSHeader{
                .id = 0,
                .flags = 0,
                .qdcount = 0,
                .ancount = 0,
                .nscount = 0,
                .arcount = 0,
            },
            .questions = &[_]DNSQuestion{},
            .answers = &[_]DNSRecord{},
            .authorities = &[_]DNSRecord{},
            .additionals = &[_]DNSRecord{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *DNSPacket) void {
        for (self.questions) |*q| q.deinit();
        for (self.answers) |*r| r.deinit();
        for (self.authorities) |*r| r.deinit();
        for (self.additionals) |*r| r.deinit();
        
        self.allocator.free(self.questions);
        self.allocator.free(self.answers);
        self.allocator.free(self.authorities);
        self.allocator.free(self.additionals);
    }
    
    pub fn serialize(self: DNSPacket, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        const writer = buffer.writer();
        
        try self.serializeToWriter(writer);
        
        return buffer.toOwnedSlice();
    }
    
    pub fn serializeToWriter(self: DNSPacket, writer: anytype) !void {
        try self.header.serialize(writer);
        
        for (self.questions) |q| {
            try q.serialize(writer);
        }
        
        for (self.answers) |r| {
            try r.serialize(writer);
        }
        
        for (self.authorities) |r| {
            try r.serialize(writer);
        }
        
        for (self.additionals) |r| {
            try r.serialize(writer);
        }
    }
    
    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !DNSPacket {
        const header = try DNSHeader.deserialize(reader);
        
        const questions = try allocator.alloc(DNSQuestion, header.qdcount);
        errdefer allocator.free(questions);
        
        for (0..header.qdcount) |i| {
            questions[i] = try DNSQuestion.deserialize(allocator, reader);
        }
        
        const answers = try allocator.alloc(DNSRecord, header.ancount);
        errdefer allocator.free(answers);
        
        for (0..header.ancount) |i| {
            answers[i] = try DNSRecord.deserialize(allocator, reader);
        }
        
        const authorities = try allocator.alloc(DNSRecord, header.nscount);
        errdefer allocator.free(authorities);
        
        for (0..header.nscount) |i| {
            authorities[i] = try DNSRecord.deserialize(allocator, reader);
        }
        
        const additionals = try allocator.alloc(DNSRecord, header.arcount);
        errdefer allocator.free(additionals);
        
        for (0..header.arcount) |i| {
            additionals[i] = try DNSRecord.deserialize(allocator, reader);
        }
        
        return DNSPacket{
            .header = header,
            .questions = questions,
            .answers = answers,
            .authorities = authorities,
            .additionals = additionals,
            .allocator = allocator,
        };
    }
};

// Helper functions for domain name serialization
fn serializeDomainName(name: []const u8, writer: anytype) !void {
    var it = std.mem.tokenizeScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len > MAX_LABEL_LENGTH) return error.LabelTooLong;
        try writer.writeInt(u8, @intCast(label.len), .big);
        try writer.writeAll(label);
    }
    try writer.writeInt(u8, 0, .big); // Null terminator
}

fn deserializeDomainName(allocator: std.mem.Allocator, reader: anytype) ![]const u8 {
    var labels = std.ArrayList(u8).init(allocator);
    defer labels.deinit();
    
    while (true) {
        const len = try reader.readInt(u8, .big);
        if (len == 0) break;
        
        // Check for compression pointer
        if (len & 0xC0 == 0xC0) {
            // DNS compression not implemented in this basic version
            return error.CompressionNotSupported;
        }
        
        if (labels.items.len > 0) {
            try labels.append('.');
        }
        
        const label = try allocator.alloc(u8, len);
        defer allocator.free(label);
        _ = try reader.read(label);
        try labels.appendSlice(label);
    }
    
    return labels.toOwnedSlice();
}

// Tests
test "DNS header serialization" {
    const allocator = std.testing.allocator;
    
    var header = DNSHeader{
        .id = 0x1234,
        .flags = 0x0100,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try header.serialize(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    const deserialized = try DNSHeader.deserialize(stream.reader());
    
    try std.testing.expectEqual(header.id, deserialized.id);
    try std.testing.expectEqual(header.flags, deserialized.flags);
    try std.testing.expectEqual(header.qdcount, deserialized.qdcount);
}

// Main DNS query processing function with identity support
pub fn processQuery(allocator: std.mem.Allocator, query_data: []const u8) ![]u8 {
    return processQueryWithIdentity(allocator, query_data, null);
}

// Process query with optional identity manager and web3 resolver
pub fn processQueryWithIdentity(allocator: std.mem.Allocator, query_data: []const u8, id_manager: ?*identity_manager.IdentityManager) ![]u8 {
    return processQueryWithWeb3(allocator, query_data, id_manager, null);
}

// Process query with full feature set
pub fn processQueryWithWeb3(allocator: std.mem.Allocator, query_data: []const u8, id_manager: ?*identity_manager.IdentityManager, web3_res: ?*web3_resolver.Web3Resolver) ![]u8 {
    var stream = std.io.fixedBufferStream(query_data);
    const reader = stream.reader();
    
    // Parse the incoming DNS packet
    var packet = DNSPacket.deserialize(allocator, reader) catch |err| {
        std.log.err("Failed to parse DNS packet: {}", .{err});
        return createErrorResponse(allocator, 0, RCODE_FORMAT_ERROR);
    };
    defer packet.deinit();
    
    // Validate the packet is a query
    if (!packet.header.isQuery()) {
        return createErrorResponse(allocator, packet.header.id, RCODE_NOT_IMPLEMENTED);
    }
    
    // Process each question and build response
    var response = DNSPacket.init(allocator);
    response.header.id = packet.header.id;
    response.header.setResponse();
    response.header.qdcount = packet.header.qdcount;
    
    // Copy questions to response
    response.questions = try allocator.alloc(DNSQuestion, packet.questions.len);
    for (packet.questions, 0..) |q, i| {
        response.questions[i] = DNSQuestion{
            .name = try allocator.dupe(u8, q.name),
            .qtype = q.qtype,
            .qclass = q.qclass,
            .allocator = allocator,
        };
    }
    
    // Build answers
    var answers = std.ArrayList(DNSRecord).init(allocator);
    defer answers.deinit();
    
    for (packet.questions) |question| {
        if (try resolveQuestionWithWeb3(allocator, question, id_manager, web3_res)) |answer| {
            try answers.append(answer);
        }
        
        // Add RRSIG record if we have an identity manager
        if (id_manager) |manager| {
            if (try createSignedRecord(allocator, question, manager)) |rrsig| {
                try answers.append(rrsig);
            }
        }
    }
    
    response.answers = try answers.toOwnedSlice();
    response.header.ancount = @intCast(response.answers.len);
    
    // Serialize response
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try response.serializeToWriter(buffer.writer());
    response.deinit();
    
    return buffer.toOwnedSlice();
}

// Resolve a DNS question (backward compatibility)
fn resolveQuestion(allocator: std.mem.Allocator, question: DNSQuestion) !?DNSRecord {
    return resolveQuestionWithWeb3(allocator, question, null, null);
}

// Resolve a DNS question with identity support
fn resolveQuestionWithIdentity(allocator: std.mem.Allocator, question: DNSQuestion, id_manager: ?*identity_manager.IdentityManager) !?DNSRecord {
    return resolveQuestionWithWeb3(allocator, question, id_manager, null);
}

// Resolve a DNS question with full feature support
fn resolveQuestionWithWeb3(allocator: std.mem.Allocator, question: DNSQuestion, id_manager: ?*identity_manager.IdentityManager, web3_res: ?*web3_resolver.Web3Resolver) !?DNSRecord {
    std.log.debug("Resolving: {s} type: {s}", .{ question.name, question.qtype.toString() });
    
    // Check for Web3 domain first
    if (web3_res) |resolver| {
        if (web3_resolver.Web3DomainType.fromDomain(question.name) != null) {
            return resolveWeb3Domain(allocator, question, resolver);
        }
    }
    
    // Check if this is a QID-based query (IPv6 address format)
    if (id_manager) |manager| {
        if (isQIDQuery(question.name)) {
            return resolveQIDQuery(allocator, question, manager);
        }
        
        // Check for identity-enhanced resolution
        if (try resolveWithIdentity(allocator, question, manager)) |record| {
            return record;
        }
    }
    
    // Handle different record types
    switch (question.qtype) {
        .A => {
            // Simple A record resolution for testing
            if (std.mem.eql(u8, question.name, "localhost")) {
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .A,
                    .rclass = .IN,
                    .ttl = 300,
                    .data = try allocator.dupe(u8, &[_]u8{ 127, 0, 0, 1 }),
                    .allocator = allocator,
                };
            }
            // Default response for unknown domains
            return DNSRecord{
                .name = try allocator.dupe(u8, question.name),
                .rtype = .A,
                .rclass = .IN,
                .ttl = 300,
                .data = try allocator.dupe(u8, &[_]u8{ 8, 8, 8, 8 }),
                .allocator = allocator,
            };
        },
        .AAAA => {
            // IPv6 record for localhost
            if (std.mem.eql(u8, question.name, "localhost")) {
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .AAAA,
                    .rclass = .IN,
                    .ttl = 300,
                    .data = try allocator.dupe(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
                    .allocator = allocator,
                };
            }
        },
        .TXT => {
            // TXT record for testing
            const txt_data = "CNS Enhanced DNS Server v1.0";
            return DNSRecord{
                .name = try allocator.dupe(u8, question.name),
                .rtype = .TXT,
                .rclass = .IN,
                .ttl = 300,
                .data = try allocator.dupe(u8, txt_data),
                .allocator = allocator,
            };
        },
        .ENS => {
            // Web3 ENS resolution placeholder
            std.log.info("ENS resolution requested for: {s}", .{question.name});
            return null;
        },
        .DNSKEY => {
            // Return public key for verification
            if (id_manager) |manager| {
                const qid = manager.generateQID("default mnemonic", "default passphrase") catch return null;
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .DNSKEY,
                    .rclass = .IN,
                    .ttl = 3600,
                    .data = try allocator.dupe(u8, &qid.public_key),
                    .allocator = allocator,
                };
            }
            return null;
        },
        else => {
            std.log.warn("Unsupported record type: {s}", .{question.qtype.toString()});
            return null;
        }
    }
    
    return null;
}

// Check if query is for a QID (IPv6 address format)
fn isQIDQuery(name: []const u8) bool {
    // Check for IPv6 address pattern (simplified)
    return std.mem.count(u8, name, ":") >= 2 and std.mem.endsWith(u8, name, ".qid");
}

// Resolve QID-based query
fn resolveQIDQuery(allocator: std.mem.Allocator, question: DNSQuestion, id_manager: *identity_manager.IdentityManager) !?DNSRecord {
    // Extract IPv6 from QID query name
    const ipv6_str = std.mem.trimRight(u8, question.name, ".qid");
    
    // Parse IPv6 address (simplified)
    const ipv6: [16]u8 = std.mem.zeroes([16]u8);
    _ = ipv6_str; // We'd parse this properly in production
    
    // Look up QID by IPv6
    if (id_manager.getQIDByIpv6(ipv6)) |qid| {
        switch (question.qtype) {
            .A => {
                // Return mapped IPv4 for compatibility
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .A,
                    .rclass = .IN,
                    .ttl = 300,
                    .data = try allocator.dupe(u8, &[_]u8{ 127, 0, 0, 1 }),
                    .allocator = allocator,
                };
            },
            .AAAA => {
                // Return QID IPv6 address
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .AAAA,
                    .rclass = .IN,
                    .ttl = 300,
                    .data = try allocator.dupe(u8, &qid.ipv6),
                    .allocator = allocator,
                };
            },
            .TXT => {
                // Return QID information
                const qid_info = try qid.toString(allocator);
                defer allocator.free(qid_info);
                
                return DNSRecord{
                    .name = try allocator.dupe(u8, question.name),
                    .rtype = .TXT,
                    .rclass = .IN,
                    .ttl = 300,
                    .data = try allocator.dupe(u8, qid_info),
                    .allocator = allocator,
                };
            },
            else => return null,
        }
    }
    
    return null;
}

// Resolve Web3 domain
fn resolveWeb3Domain(allocator: std.mem.Allocator, question: DNSQuestion, web3_res: *web3_resolver.Web3Resolver) !?DNSRecord {
    _ = allocator;
    
    // Resolve the Web3 domain
    var web3_record = web3_res.resolveDomain(question.name) catch |err| {
        std.log.err("Failed to resolve Web3 domain {s}: {}", .{ question.name, err });
        return null;
    };
    
    if (web3_record) |*record| {
        // Convert Web3 record to DNS record
        return web3_res.toDNSRecord(record, question) catch |err| {
            std.log.err("Failed to convert Web3 record to DNS: {}", .{err});
            return null;
        };
    }
    
    return null;
}

// Resolve with identity enhancement
fn resolveWithIdentity(allocator: std.mem.Allocator, question: DNSQuestion, id_manager: *identity_manager.IdentityManager) !?DNSRecord {
    _ = allocator;
    _ = question;
    _ = id_manager;
    
    // Future: Implement identity-enhanced resolution
    // - Check trust scores
    // - Apply identity-based filtering
    // - Return personalized responses
    
    return null;
}

// Create signed DNS record (RRSIG)
fn createSignedRecord(allocator: std.mem.Allocator, question: DNSQuestion, id_manager: *identity_manager.IdentityManager) !?DNSRecord {
    // Create RRSIG data structure
    var rrsig_data = std.ArrayList(u8).init(allocator);
    defer rrsig_data.deinit();
    
    // Type covered (2 bytes)
    try rrsig_data.writer().writeInt(u16, @intFromEnum(question.qtype), .big);
    
    // Algorithm (1 byte) - Ed25519
    try rrsig_data.writer().writeInt(u8, 15, .big);
    
    // Labels (1 byte)
    const label_count = std.mem.count(u8, question.name, ".");
    try rrsig_data.writer().writeInt(u8, @intCast(label_count), .big);
    
    // Original TTL (4 bytes)
    try rrsig_data.writer().writeInt(u32, 300, .big);
    
    // Signature expiration (4 bytes)
    const expiration = @as(u32, @intCast(std.time.timestamp() + 3600)); // 1 hour from now
    try rrsig_data.writer().writeInt(u32, expiration, .big);
    
    // Signature inception (4 bytes)
    const inception = @as(u32, @intCast(std.time.timestamp()));
    try rrsig_data.writer().writeInt(u32, inception, .big);
    
    // Key tag (2 bytes)
    try rrsig_data.writer().writeInt(u16, 1234, .big);
    
    // Signer's name
    try serializeDomainName(question.name, rrsig_data.writer());
    
    // Sign the record
    const signature = id_manager.signature_manager.signDnsRecord(rrsig_data.items) catch return null;
    
    // Append signature to RRSIG data
    try rrsig_data.appendSlice(&signature);
    
    return DNSRecord{
        .name = try allocator.dupe(u8, question.name),
        .rtype = .RRSIG,
        .rclass = .IN,
        .ttl = 300,
        .data = try rrsig_data.toOwnedSlice(),
        .allocator = allocator,
    };
}

// Create error response
fn createErrorResponse(allocator: std.mem.Allocator, id: u16, rcode: u4) ![]u8 {
    var response = DNSPacket.init(allocator);
    response.header.id = id;
    response.header.setResponse();
    response.header.setRcode(rcode);
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try response.serializeToWriter(buffer.writer());
    response.deinit();
    
    return buffer.toOwnedSlice();
}

test "DNS query processing" {
    const allocator = std.testing.allocator;
    
    // Create a simple DNS query for "localhost" A record
    var query_packet = DNSPacket.init(allocator);
    query_packet.header.id = 0x1234;
    query_packet.header.qdcount = 1;
    
    const questions = try allocator.alloc(DNSQuestion, 1);
    questions[0] = DNSQuestion{
        .name = try allocator.dupe(u8, "localhost"),
        .qtype = .A,
        .qclass = .IN,
        .allocator = allocator,
    };
    query_packet.questions = questions;
    
    var query_buffer = std.ArrayList(u8).init(allocator);
    defer query_buffer.deinit();
    
    try query_packet.serialize(query_buffer.writer());
    query_packet.deinit();
    
    // Process the query
    const response = try processQuery(allocator, query_buffer.items);
    defer allocator.free(response);
    
    // Verify response is not empty
    try std.testing.expect(response.len > 0);
}

test "Domain name serialization" {
    const allocator = std.testing.allocator;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try serializeDomainName("example.com", buffer.writer());
    
    const expected = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    try std.testing.expectEqualSlices(u8, &expected, buffer.items);
}