const std = @import("std");

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
    
    pub fn serialize(self: DNSPacket, writer: anytype) !void {
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

test "Domain name serialization" {
    const allocator = std.testing.allocator;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try serializeDomainName("example.com", buffer.writer());
    
    const expected = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    try std.testing.expectEqualSlices(u8, &expected, buffer.items);
}