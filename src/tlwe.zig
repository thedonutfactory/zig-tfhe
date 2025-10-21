//! TLWE (Torus Learning With Errors) implementation
//!
//! This module provides the core TLWE encryption scheme used in TFHE.
//! TLWE is the basic building block for all other TFHE operations.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");

// ============================================================================
// TLWE LEVEL 0 (Lv0) - Basic TLWE with smaller parameters
// ============================================================================

/// TLWE Level 0 ciphertext - used for basic operations
pub const TLWELv0 = struct {
    p: [params.implementation.tlwe_lv0.N + 1]params.Torus,

    const Self = @This();

    /// Create a new zero TLWE ciphertext
    pub fn new() TLWELv0 {
        return TLWELv0{
            .p = [_]params.Torus{0} ** (params.implementation.tlwe_lv0.N + 1),
        };
    }

    /// Get the b component (last element)
    pub fn b(self: *const Self) params.Torus {
        return self.p[params.implementation.tlwe_lv0.N];
    }

    /// Get mutable reference to the b component
    pub fn bMut(self: *Self) *params.Torus {
        return &self.p[params.implementation.tlwe_lv0.N];
    }

    /// Encrypt a floating-point value
    pub fn encryptF64(p: f64, alpha: f64, key: []const params.Torus) !TLWELv0 {
        var rng = std.Random.DefaultPrng.init(utils.getUniqueSeed());
        var tlwe = TLWELv0.new();
        var inner_product: params.Torus = 0;

        for (key, 0..) |key_val, i| {
            const rand_torus: params.Torus = rng.random().int(params.Torus);
            inner_product = inner_product +% (key_val *% rand_torus);
            tlwe.p[i] = rand_torus;
        }

        var normal_distr = utils.NormalDist.init(0.0, alpha);
        const noise = utils.gaussianF64(p, &normal_distr, rng.random());
        tlwe.bMut().* = inner_product +% noise;
        return tlwe;
    }

    /// Encrypt a boolean value
    pub fn encryptBool(p_bool: bool, alpha: f64, key: []const params.Torus) !TLWELv0 {
        const p: f64 = if (p_bool) 0.125 else -0.125;
        return Self.encryptF64(p, alpha, key);
    }

    /// Decrypt a boolean value
    pub fn decryptBool(self: *const Self, key: []const params.Torus) bool {
        var inner_product: params.Torus = 0;
        for (key, 0..) |key_val, i| {
            inner_product = inner_product +% (self.p[i] *% key_val);
        }

        const diff = self.p[params.implementation.tlwe_lv0.N] -% inner_product;
        // Convert to signed integer safely
        const res_torus = @as(params.HalfTorus, @bitCast(diff));
        return res_torus >= 0;
    }

    /// Encrypt a message using LWE message encoding for programmable bootstrapping
    ///
    /// This function encodes a message as `message * scale` where scale is `1/(2*message_modulus)`.
    /// This is the standard encoding used in programmable bootstrapping.
    ///
    /// # Arguments
    /// * `message` - Integer message to encrypt (should be in [0, message_modulus))
    /// * `message_modulus` - Size of the message space
    /// * `alpha` - Noise parameter
    /// * `key` - Secret key for encryption
    ///
    /// # Returns
    /// Encrypted TLWE ciphertext
    pub fn encryptLweMessage(
        message: usize,
        message_modulus: usize,
        alpha: f64,
        key: []const params.Torus,
    ) !TLWELv0 {
        // Normalize message to [0, message_modulus)
        const normalized_message = message % message_modulus;

        // Encode as message * scale where scale = 1/(2*message_modulus)
        const scale = 1.0 / (2.0 * @as(f64, @floatFromInt(message_modulus)));
        const encoded_value = @as(f64, @floatFromInt(normalized_message)) * scale;

        return Self.encryptF64(encoded_value, alpha, key);
    }

    /// Decrypt a message using LWE message decoding for programmable bootstrapping
    ///
    /// This function decodes a message from the LWE message encoding used in programmable bootstrapping.
    ///
    /// # Arguments
    /// * `message_modulus` - Size of the message space
    /// * `key` - Secret key for decryption
    ///
    /// # Returns
    /// Decrypted integer message
    pub fn decryptLweMessage(self: *const Self, message_modulus: usize, key: []const params.Torus) usize {
        var inner_product: params.Torus = 0;
        for (key, 0..) |key_val, i| {
            inner_product = inner_product +% (self.p[i] *% key_val);
        }

        const res_torus = self.p[params.implementation.tlwe_lv0.N] -% inner_product;
        const res_f64 = utils.torusToF64(res_torus);

        // Decode from message * scale where scale = 1/(2*message_modulus)
        const scale = 1.0 / (2.0 * @as(f64, @floatFromInt(message_modulus)));
        // Match Rust: (res_f64 / scale + 0.5) as usize
        // The +0.5 provides rounding, cast to usize truncates (no additional @round needed!)
        const message = @as(usize, @intFromFloat(res_f64 / scale + 0.5));

        // Normalize to [0, message_modulus)
        return message % message_modulus;
    }

    /// Add two TLWE ciphertexts
    pub fn add(self: *const Self, other: *const Self) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = self.p[i] +% other.p[i];
        }
        return res;
    }

    /// Subtract two TLWE ciphertexts
    pub fn sub(self: *const Self, other: *const Self) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = self.p[i] -% other.p[i];
        }
        return res;
    }

    /// Negate a TLWE ciphertext
    pub fn neg(self: *const Self) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = params.ZERO_TORUS -% self.p[i];
        }
        return res;
    }

    /// Multiply two TLWE ciphertexts (element-wise)
    pub fn mul(self: *const Self, other: *const Self) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = self.p[i] *% other.p[i];
        }
        return res;
    }

    /// Add-multiply operation: self + other * multiplier
    pub fn addMul(self: *const Self, other: *const Self, multiplier: params.Torus) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = self.p[i] +% (other.p[i] *% multiplier);
        }
        return res;
    }

    /// Subtract-multiply operation: self - other * multiplier
    pub fn subMul(self: *const Self, other: *const Self, multiplier: params.Torus) TLWELv0 {
        var res = TLWELv0.new();
        for (0..self.p.len) |i| {
            res.p[i] = self.p[i] -% (other.p[i] *% multiplier);
        }
        return res;
    }
};

// ============================================================================
// TLWE LEVEL 1 (Lv1) - Higher security TLWE with larger parameters
// ============================================================================

/// TLWE Level 1 ciphertext - used for higher security operations
pub const TLWELv1 = struct {
    p: [params.implementation.tlwe_lv1.N + 1]params.Torus,

    const Self = @This();

    /// Create a new zero TLWE ciphertext
    pub fn new() TLWELv1 {
        return TLWELv1{
            .p = [_]params.Torus{0} ** (params.implementation.tlwe_lv1.N + 1),
        };
    }

    /// Get mutable reference to the b component
    pub fn bMut(self: *Self) *params.Torus {
        return &self.p[params.implementation.tlwe_lv1.N];
    }

    /// Encrypt a floating-point value (for testing)
    pub fn encryptF64(p: f64, alpha: f64, key: []const params.Torus) !TLWELv1 {
        var rng = std.Random.DefaultPrng.init(utils.getUniqueSeed());
        var tlwe = TLWELv1.new();
        var inner_product: params.Torus = 0;

        for (key, 0..) |key_val, i| {
            const rand_torus: params.Torus = rng.random().int(params.Torus);
            inner_product = inner_product +% (key_val *% rand_torus);
            tlwe.p[i] = rand_torus;
        }

        var normal_distr = utils.NormalDist.init(0.0, alpha);
        const noise = utils.gaussianF64(p, &normal_distr, rng.random());
        tlwe.bMut().* = inner_product +% noise;
        return tlwe;
    }

    /// Encrypt a boolean value (for testing)
    pub fn encryptBool(b: bool, alpha: f64, key: []const params.Torus) !TLWELv1 {
        const p: f64 = if (b) 0.125 else -0.125;
        return Self.encryptF64(p, alpha, key);
    }

    /// Decrypt a boolean value (for testing)
    pub fn decryptBool(self: *const Self, key: []const params.Torus) bool {
        var inner_product: params.Torus = 0;
        for (key, 0..) |key_val, i| {
            inner_product = inner_product +% (self.p[i] *% key_val);
        }

        const diff = self.p[key.len] -% inner_product;
        // Convert to signed integer safely
        const res_torus = @as(params.HalfTorus, @bitCast(diff));
        return res_torus >= 0;
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "tlwe encryption and decryption" {
    var rng = std.Random.DefaultPrng.init(42);

    // Create test keys
    var key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N;
    var key_lv1 = [_]params.Torus{0} ** params.implementation.tlwe_lv1.N;

    // Fill with random values
    for (0..key_lv0.len) |i| {
        key_lv0[i] = rng.random().int(params.Torus);
    }
    for (0..key_lv1.len) |i| {
        key_lv1[i] = rng.random().int(params.Torus);
    }

    var correct: usize = 0;
    const try_num: usize = 1000;

    for (0..try_num) |_| {
        const sample = rng.random().boolean();
        const secret = try TLWELv0.encryptBool(sample, params.implementation.tlwe_lv0.ALPHA, &key_lv0);
        const plain = secret.decryptBool(&key_lv0);

        if (plain == sample) {
            correct += 1;
        }
    }

    const probability = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(try_num));
    try std.testing.expect(probability > 0.95); // Should be very high success rate
}

test "tlwe arithmetic operations" {
    var rng = std.Random.DefaultPrng.init(42);

    // Create test key
    var key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N;
    for (0..key_lv0.len) |i| {
        key_lv0[i] = rng.random().int(params.Torus);
    }

    // Test addition
    const a = try TLWELv0.encryptBool(true, params.implementation.tlwe_lv0.ALPHA, &key_lv0);
    const b = try TLWELv0.encryptBool(false, params.implementation.tlwe_lv0.ALPHA, &key_lv0);
    const sum = a.add(&b);

    // Test subtraction
    const diff = a.sub(&b);

    // Test negation
    const neg_a = a.neg();

    // Test multiplication
    const mul = a.mul(&b);

    // Test add-multiply
    const add_mul = a.addMul(&b, 2);

    // Test subtract-multiply
    const sub_mul = a.subMul(&b, 2);

    // All operations should complete without error
    _ = sum;
    _ = diff;
    _ = neg_a;
    _ = mul;
    _ = add_mul;
    _ = sub_mul;
}

test "tlwe lwe message encoding" {
    var rng = std.Random.DefaultPrng.init(42);

    // Create test key
    var key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N;
    for (0..key_lv0.len) |i| {
        key_lv0[i] = rng.random().int(params.Torus);
    }

    const message_modulus: usize = 4;
    const original_message: usize = 2;

    // Test multiple times to account for noise
    var success_count: usize = 0;
    const num_tests: usize = 10;

    for (0..num_tests) |_| {
        // Encrypt and decrypt message
        const encrypted = try TLWELv0.encryptLweMessage(
            original_message,
            message_modulus,
            params.implementation.tlwe_lv0.ALPHA,
            &key_lv0,
        );

        const decrypted = encrypted.decryptLweMessage(message_modulus, &key_lv0);

        if (decrypted == original_message) {
            success_count += 1;
        }
    }

    // Should succeed at least 80% of the time (accounting for noise)
    try std.testing.expect(success_count >= num_tests * 8 / 10);
}

test "tlwe lv1 encryption and decryption" {
    var rng = std.Random.DefaultPrng.init(42);

    // Create test key
    var key_lv1 = [_]params.Torus{0} ** params.implementation.tlwe_lv1.N;
    for (0..key_lv1.len) |i| {
        key_lv1[i] = rng.random().int(params.Torus);
    }

    var correct: usize = 0;
    const try_num: usize = 100;

    for (0..try_num) |_| {
        const sample = rng.random().boolean();
        const secret = try TLWELv1.encryptBool(sample, params.implementation.tlwe_lv1.ALPHA, &key_lv1);
        const plain = secret.decryptBool(&key_lv1);

        if (plain == sample) {
            correct += 1;
        }
    }

    const probability = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(try_num));
    try std.testing.expect(probability > 0.95); // Should be very high success rate
}
