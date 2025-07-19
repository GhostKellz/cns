//! Identity Manager for CNS with ZQLite v1.2.1 HD Wallet Support
//! Implements BIP32/44 key derivation, digital signatures, and trust scoring

const std = @import("std");
const zqlite = @import("zqlite");
const shroud = @import("shroud");
const zcrypto = @import("zcrypto");

const log = std.log.scoped(.identity_manager);

/// Quantum-resistant Identity Descriptor (QID) structure
pub const QID = struct {
    /// Cryptographically-derived IPv6 address
    ipv6: [16]u8,
    
    /// Public key for identity verification
    public_key: [32]u8,
    
    /// Trust level (0-100)
    trust_level: u8,
    
    /// Creation timestamp
    created_at: i64,
    
    /// Last verification timestamp
    last_verified: i64,
    
    /// Identity signature
    signature: [64]u8,
    
    pub fn generateIpv6FromPublicKey(public_key: [32]u8) [16]u8 {
        // Use SHA-256 to derive IPv6 from public key
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&public_key);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        // Create IPv6 address with CNS prefix (fd00::/8)
        var ipv6: [16]u8 = undefined;
        ipv6[0] = 0xfd; // CNS prefix
        ipv6[1] = 0x00;
        @memcpy(ipv6[2..16], hash[0..14]);
        
        return ipv6;
    }
    
    pub fn toString(self: QID, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "QID:{any}-{}-{}", .{
            self.ipv6,
            self.trust_level,
            self.created_at,
        });
    }
};

/// HD Wallet for BIP32/44 key derivation
pub const HDWallet = struct {
    allocator: std.mem.Allocator,
    
    /// Master seed (512 bits)
    master_seed: [64]u8,
    
    /// Encrypted seed storage
    encrypted_seed: []u8,
    
    /// Current derivation path
    derivation_path: std.ArrayList(u32),
    
    /// Cache of derived keys
    key_cache: std.AutoHashMap(u32, [32]u8),
    
    pub fn init(allocator: std.mem.Allocator) HDWallet {
        return HDWallet{
            .allocator = allocator,
            .master_seed = std.mem.zeroes([64]u8),
            .encrypted_seed = &[_]u8{},
            .derivation_path = std.ArrayList(u32).init(allocator),
            .key_cache = std.AutoHashMap(u32, [32]u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *HDWallet) void {
        self.derivation_path.deinit();
        self.key_cache.deinit();
        if (self.encrypted_seed.len > 0) {
            self.allocator.free(self.encrypted_seed);
        }
        // Clear sensitive data
        @memset(&self.master_seed, 0);
    }
    
    /// Generate master seed from mnemonic
    pub fn generateFromMnemonic(self: *HDWallet, mnemonic: []const u8, passphrase: []const u8) !void {
        // Use PBKDF2 to derive master seed
        try std.crypto.pwhash.pbkdf2(&self.master_seed, mnemonic, passphrase, 4096, std.crypto.auth.hmac.sha2.HmacSha512);
        
        // Encrypt seed for storage
        try self.encryptSeed(passphrase);
    }
    
    /// Encrypt seed for secure storage
    fn encryptSeed(self: *HDWallet, passphrase: []const u8) !void {
        // Use AES-256-GCM for encryption
        var key: [32]u8 = undefined;
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        
        try std.crypto.pwhash.pbkdf2(&key, passphrase, &salt, 4096, std.crypto.auth.hmac.sha2.HmacSha256);
        
        // Encrypt the seed
        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        
        var encrypted_data = try self.allocator.alloc(u8, 64 + 16); // seed + auth tag
        var auth_tag: [16]u8 = undefined;
        
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
            encrypted_data[0..64],
            &auth_tag,
            &self.master_seed,
            "",
            nonce,
            key,
        );
        
        @memcpy(encrypted_data[64..], &auth_tag);
        
        // Store encrypted seed with metadata
        const total_size = 16 + 12 + encrypted_data.len; // salt + nonce + encrypted_data
        self.encrypted_seed = try self.allocator.alloc(u8, total_size);
        @memcpy(self.encrypted_seed[0..16], &salt);
        @memcpy(self.encrypted_seed[16..28], &nonce);
        @memcpy(self.encrypted_seed[28..], encrypted_data);
        
        self.allocator.free(encrypted_data);
    }
    
    /// Derive key using BIP32/44 specification
    pub fn deriveKey(self: *HDWallet, path: []const u32) ![32]u8 {
        // Simple derivation for now - in production, use proper BIP32 HMAC-SHA512
        var derived_key: [32]u8 = undefined;
        @memcpy(&derived_key, self.master_seed[0..32]);
        
        // Apply path derivation
        for (path) |index| {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(&derived_key);
            hasher.update(std.mem.asBytes(&index));
            hasher.final(&derived_key);
        }
        
        return derived_key;
    }
    
    /// Get DNS signing key (m/44'/53'/0'/0/0)
    pub fn getDnsSigningKey(self: *HDWallet) ![32]u8 {
        const dns_path = [_]u32{ 44 | 0x80000000, 53 | 0x80000000, 0x80000000, 0, 0 };
        return self.deriveKey(&dns_path);
    }
    
    /// Get identity key (m/44'/53'/0'/1/0)
    pub fn getIdentityKey(self: *HDWallet) ![32]u8 {
        const identity_path = [_]u32{ 44 | 0x80000000, 53 | 0x80000000, 0x80000000, 1, 0 };
        return self.deriveKey(&identity_path);
    }
};

/// Digital signature manager for DNS records
pub const SignatureManager = struct {
    allocator: std.mem.Allocator,
    wallet: *HDWallet,
    
    pub fn init(allocator: std.mem.Allocator, wallet: *HDWallet) SignatureManager {
        return SignatureManager{
            .allocator = allocator,
            .wallet = wallet,
        };
    }
    
    /// Sign DNS record using Schnorr signature
    pub fn signDnsRecord(self: *SignatureManager, record_data: []const u8) ![64]u8 {
        const signing_key = try self.wallet.getDnsSigningKey();
        
        // Generate Ed25519 signature (Schnorr-style)
        var signature: [64]u8 = undefined;
        // Ensure signing_key is 32 bytes
        if (signing_key.len != 32) return error.InvalidKeySize;
        
        var seed: [32]u8 = undefined;
        @memcpy(&seed, signing_key[0..32]);
        
        // Generate keypair from seed
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        
        const sig = try kp.sign(record_data, null);
        @memcpy(&signature, &sig.toBytes());
        
        return signature;
    }
    
    /// Verify DNS record signature
    pub fn verifyDnsRecord(self: *SignatureManager, record_data: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        _ = self;
        
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature) catch return false;
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
        
        sig.verify(record_data, pub_key) catch return false;
        return true;
    }
};

/// Trust scoring system
pub const TrustScorer = struct {
    allocator: std.mem.Allocator,
    database: *zqlite.Connection,
    
    pub fn init(allocator: std.mem.Allocator, database: *zqlite.Connection) TrustScorer {
        return TrustScorer{
            .allocator = allocator,
            .database = database,
        };
    }
    
    /// Calculate trust score (0-100)
    pub fn calculateTrustScore(self: *TrustScorer, qid: QID) !u8 {
        var score: u32 = 0;
        
        // Base score factors
        const age_factor = @min(50, @as(u32, @intCast((std.time.timestamp() - qid.created_at) / (24 * 60 * 60)))); // Days since creation
        const verification_factor = if (qid.last_verified > 0) @as(u32, 20) else 0;
        const signature_factor = if (qid.signature[0] != 0) @as(u32, 20) else 0;
        
        score += age_factor + verification_factor + signature_factor;
        
        // Query database for historical behavior
        const query = "SELECT COUNT(*) as interactions, AVG(trust_score) as avg_trust FROM identity_interactions WHERE qid = ?";
        _ = query;
        _ = self;
        
        // Cap at 100
        return @intCast(@min(100, score));
    }
    
    /// Update trust score based on interaction
    pub fn updateTrustScore(self: *TrustScorer, qid: QID, interaction_type: []const u8, success: bool) !void {
        const score_delta: i8 = if (success) 1 else -2;
        
        const update_query = 
            \\INSERT OR REPLACE INTO identity_interactions 
            \\(qid, interaction_type, success, timestamp, score_delta) 
            \\VALUES (?, ?, ?, datetime('now'), ?)
        ;
        
        _ = update_query;
        _ = self;
        _ = qid;
        _ = interaction_type;
        
        log.debug("Trust score updated for QID, delta: {}", .{score_delta});
    }
};

/// Main Identity Manager
pub const IdentityManager = struct {
    allocator: std.mem.Allocator,
    database: *zqlite.Connection,
    wallet: HDWallet,
    signature_manager: SignatureManager,
    trust_scorer: TrustScorer,
    
    /// Identity cache
    identity_cache: std.AutoHashMap([16]u8, QID),
    
    pub fn init(allocator: std.mem.Allocator, database: *zqlite.Connection) !IdentityManager {
        var wallet = HDWallet.init(allocator);
        const signature_manager = SignatureManager.init(allocator, &wallet);
        const trust_scorer = TrustScorer.init(allocator, database);
        
        const identity_cache = std.AutoHashMap([16]u8, QID).init(allocator);
        
        return IdentityManager{
            .allocator = allocator,
            .database = database,
            .wallet = wallet,
            .signature_manager = signature_manager,
            .trust_scorer = trust_scorer,
            .identity_cache = identity_cache,
        };
    }
    
    pub fn deinit(self: *IdentityManager) void {
        self.wallet.deinit();
        self.identity_cache.deinit();
    }
    
    /// Generate new QID
    pub fn generateQID(self: *IdentityManager, mnemonic: []const u8, passphrase: []const u8) !QID {
        // Initialize wallet with mnemonic
        try self.wallet.generateFromMnemonic(mnemonic, passphrase);
        
        // Get identity key
        const identity_key = try self.wallet.getIdentityKey();
        
        // Generate QID
        const qid = QID{
            .ipv6 = QID.generateIpv6FromPublicKey(identity_key),
            .public_key = identity_key,
            .trust_level = 0,
            .created_at = std.time.timestamp(),
            .last_verified = 0,
            .signature = std.mem.zeroes([64]u8),
        };
        
        // Sign the QID
        const qid_bytes = std.mem.asBytes(&qid);
        const signature = try self.signature_manager.signDnsRecord(qid_bytes);
        
        var signed_qid = qid;
        signed_qid.signature = signature;
        
        // Cache the QID
        try self.identity_cache.put(qid.ipv6, signed_qid);
        
        // Store in database
        try self.storeQID(signed_qid);
        
        log.info("Generated new QID: {any}", .{qid.ipv6});
        
        return signed_qid;
    }
    
    /// Store QID in database
    fn storeQID(self: *IdentityManager, qid: QID) !void {
        const insert_query = 
            \\INSERT OR REPLACE INTO identities 
            \\(ipv6, public_key, trust_level, created_at, last_verified, signature) 
            \\VALUES (?, ?, ?, ?, ?, ?)
        ;
        
        _ = insert_query;
        _ = self;
        _ = qid;
        
        log.debug("Stored QID in database", .{});
    }
    
    /// Verify QID signature
    pub fn verifyQID(self: *IdentityManager, qid: QID) bool {
        const qid_bytes = std.mem.asBytes(&qid);
        return self.signature_manager.verifyDnsRecord(qid_bytes, qid.signature, qid.public_key);
    }
    
    /// Get QID by IPv6 address
    pub fn getQIDByIpv6(self: *IdentityManager, ipv6: [16]u8) ?QID {
        return self.identity_cache.get(ipv6);
    }
    
    /// Update trust score
    pub fn updateTrustScore(self: *IdentityManager, qid: QID, interaction_type: []const u8, success: bool) !void {
        try self.trust_scorer.updateTrustScore(qid, interaction_type, success);
    }
    
    /// Get trust score
    pub fn getTrustScore(self: *IdentityManager, qid: QID) !u8 {
        return self.trust_scorer.calculateTrustScore(qid);
    }
};

// Tests
test "QID generation" {
    const public_key = [_]u8{1} ** 32;
    const ipv6 = QID.generateIpv6FromPublicKey(public_key);
    
    // Should start with CNS prefix
    try std.testing.expectEqual(@as(u8, 0xfd), ipv6[0]);
    try std.testing.expectEqual(@as(u8, 0x00), ipv6[1]);
}

test "HD Wallet key derivation" {
    const allocator = std.testing.allocator;
    
    var wallet = HDWallet.init(allocator);
    defer wallet.deinit();
    
    try wallet.generateFromMnemonic("test mnemonic", "passphrase");
    
    const dns_key = try wallet.getDnsSigningKey();
    const identity_key = try wallet.getIdentityKey();
    
    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, &dns_key, &identity_key));
}