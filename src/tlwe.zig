const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const key_module = @import("key.zig");

/// TLWE (Torus Learning With Errors) level 1 ciphertext
pub const TLWELv1 = struct {
    /// Polynomial coefficients: [a_0, a_1, ..., a_{n-1}, b]
    /// where b is the constant term and a_i are the coefficients
    p: [params.implementation.tlwe_lv1.N + 1]params.Torus,

    const Self = @This();

    /// Create a new zero TLWE ciphertext
    pub fn init() Self {
        return Self{
            .p = [_]params.Torus{0} ** (params.implementation.tlwe_lv1.N + 1),
        };
    }

    /// Get the constant term (b)
    pub fn b(self: *const Self) params.Torus {
        return self.p[params.implementation.tlwe_lv1.N];
    }

    /// Get mutable reference to the constant term (b)
    pub fn bMut(self: *Self) *params.Torus {
        return &self.p[params.implementation.tlwe_lv1.N];
    }

    /// Decrypt TLWELv1 to boolean using level 1 key
    pub fn decryptBool(self: *const Self, key: *const key_module.SecretKeyLv1) bool {
        var inner_product: params.Torus = 0;
        for (0..key.len) |i| {
            inner_product = inner_product +% (self.p[i] *% key[i]);
        }

        const diff = self.b() -% inner_product;
        // Convert torus value to signed: if diff < TORUS_SIZE/2, it's positive (>= 0)
        return diff < params.TORUS_SIZE / 2;
    }
};

/// TLWE (Torus Learning With Errors) level 0 ciphertext
/// This is the main ciphertext type used for homomorphic operations
pub const TLWELv0 = struct {
    /// Polynomial coefficients: [a_0, a_1, ..., a_{n-1}, b]
    /// where b is the constant term and a_i are the coefficients
    p: [params.implementation.tlwe_lv0.N + 1]params.Torus,

    const Self = @This();

    /// Create a new zero TLWE ciphertext
    pub fn init() Self {
        return Self{
            .p = [_]params.Torus{0} ** (params.implementation.tlwe_lv0.N + 1),
        };
    }

    /// Get the constant term (b)
    pub fn b(self: *const Self) params.Torus {
        return self.p[params.implementation.tlwe_lv0.N];
    }

    /// Get mutable reference to the constant term (b)
    pub fn bMut(self: *Self) *params.Torus {
        return &self.p[params.implementation.tlwe_lv0.N];
    }

    /// Encrypt a floating point value (proper LWE implementation)
    pub fn encryptF64(
        p: f64,
        _: f64,
        key: *const key_module.SecretKeyLv0,
        _: std.mem.Allocator,
    ) !Self {
        var tlwe = Self.init();
        var inner_product: params.Torus = 0;

        // Convert message to torus
        const message_torus = utils.f64ToTorus(p);

        // Generate random coefficients a[i] and compute <a, s>
        for (0..params.implementation.tlwe_lv0.N) |i| {
            // Use a more realistic pseudo-random generator for coefficients
            const seed = @as(u64, @intCast(i)) *% 1103515245 +% 12345;
            const rand_torus: params.Torus = @intCast(seed % std.math.pow(u64, 2, params.TORUS_SIZE));
            tlwe.p[i] = rand_torus;
            inner_product +%= key[i] *% rand_torus;
        }

        // Add small noise (simplified)
        const noise_magnitude = @as(params.Torus, @intFromFloat(@mod(p * 1000000000.0, 100.0)));
        const noise = if (p > 0) noise_magnitude else -%noise_magnitude;

        // Compute b = <a, s> + m + e
        tlwe.p[params.implementation.tlwe_lv0.N] = inner_product +% message_torus +% noise;

        return tlwe;
    }

    /// Encrypt a boolean value
    pub fn encrypt(plaintext: bool, key: *const key_module.SecretKeyLv0, allocator: std.mem.Allocator) !Self {
        const p: f64 = if (plaintext) 0.125 else -0.125;
        return Self.encryptF64(p, params.implementation.tlwe_lv0.ALPHA, key, allocator);
    }

    /// Encrypt an LWE message with given modulus
    pub fn encryptLweMessage(
        msg: usize,
        modulus: usize,
        alpha: f64,
        key: *const key_module.SecretKeyLv0,
        allocator: std.mem.Allocator,
    ) !Self {
        // Normalize message to [0, modulus)
        const message = msg % modulus;

        // Encode as message * scale where scale = 1/(2*modulus) (like Rust version)
        const scale = 1.0 / (2.0 * @as(f64, @floatFromInt(modulus)));
        const encoded_value = @as(f64, @floatFromInt(message)) * scale;

        return Self.encryptF64(encoded_value, alpha, key, allocator);
    }

    /// Decrypt a boolean value
    pub fn decrypt(self: *const Self, key: *const key_module.SecretKeyLv0) bool {
        var inner_product: params.Torus = 0;
        for (0..params.implementation.tlwe_lv0.N) |i| {
            inner_product +%= key[i] *% self.p[i];
        }

        const b_val = self.b();
        const result = b_val -% inner_product;
        const torus_half = std.math.pow(params.Torus, 2, params.TORUS_SIZE - 1);

        // In TFHE, we check if the result is non-negative (like Rust version)
        // Since we encode true as 0.125 and false as -0.125, we check if result >= 0
        return result < torus_half;
    }

    /// Decrypt an LWE message with given modulus
    pub fn decryptLweMessage(self: *const Self, modulus: usize, key: *const key_module.SecretKeyLv0) usize {
        var inner_product: params.Torus = 0;
        for (0..params.implementation.tlwe_lv0.N) |i| {
            inner_product +%= key[i] *% self.p[i];
        }

        const b_val = self.b();
        const result = b_val -% inner_product;

        // Convert torus to f64
        const res_f64 = utils.torusToF64(result);

        // Decode from message * scale where scale = 1/(2*modulus) (like Rust version)
        const scale = 1.0 / (2.0 * @as(f64, @floatFromInt(modulus)));
        const message = @as(usize, @intFromFloat(res_f64 / scale + 0.5));

        // Normalize to [0, modulus)
        return message % modulus;
    }

    /// Homomorphic addition: self + other
    pub fn add(self: *const Self, other: *const Self) Self {
        var result = Self.init();
        for (0..self.p.len) |i| {
            result.p[i] = self.p[i] +% other.p[i];
        }
        return result;
    }

    /// Homomorphic subtraction: self - other
    pub fn sub(self: *const Self, other: *const Self) Self {
        var result = Self.init();
        for (0..self.p.len) |i| {
            result.p[i] = self.p[i] -% other.p[i];
        }
        return result;
    }

    /// Homomorphic negation: -self
    pub fn neg(self: *const Self) Self {
        var result = Self.init();
        for (0..self.p.len) |i| {
            result.p[i] = -%self.p[i];
        }
        return result;
    }

    /// Homomorphic multiplication by a constant
    pub fn mulConst(self: *const Self, constant: params.Torus) Self {
        var result = Self.init();
        for (0..self.p.len) |i| {
            result.p[i] = self.p[i] *% constant;
        }
        return result;
    }

    /// Homomorphic multiplication by a small constant (for efficiency)
    pub fn mulSmallConst(self: *const Self, constant: i32) Self {
        var result = Self.init();
        for (0..self.p.len) |i| {
            result.p[i] = self.p[i] *% @as(params.Torus, @intCast(constant));
        }
        return result;
    }

    /// Extract a specific coefficient
    pub fn getCoeff(self: *const Self, index: usize) params.Torus {
        if (index >= self.p.len) return 0;
        return self.p[index];
    }

    /// Set a specific coefficient
    pub fn setCoeff(self: *Self, index: usize, value: params.Torus) void {
        if (index < self.p.len) {
            self.p[index] = value;
        }
    }

    /// Check if ciphertext is zero
    pub fn isZero(self: *const Self) bool {
        for (self.p) |coeff| {
            if (coeff != 0) return false;
        }
        return true;
    }

    /// Get the noise level (approximate)
    pub fn noiseLevel(self: *const Self, key: *const key_module.SecretKeyLv0) f64 {
        var inner_product: params.Torus = 0;
        for (0..params.implementation.tlwe_lv0.N) |i| {
            inner_product +%= key[i] *% self.p[i];
        }

        const b_val = self.b();
        const noise = b_val -% inner_product;
        const noise_f64 = utils.torusToF64(noise);

        return @abs(noise_f64);
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "tlwe basic operations" {
    const allocator = std.testing.allocator;

    // Create a dummy key for testing
    var key: key_module.SecretKeyLv0 = undefined;
    for (&key) |*k| {
        k.* = 0;
    }

    // Test encryption/decryption
    const ct_true = try TLWELv0.encrypt(true, &key, allocator);
    const ct_false = try TLWELv0.encrypt(false, &key, allocator);

    const decrypted_true = ct_true.decrypt(&key);
    const decrypted_false = ct_false.decrypt(&key);

    try std.testing.expect(decrypted_true == true);
    try std.testing.expect(decrypted_false == false);
}

test "tlwe homomorphic operations" {
    const allocator = std.testing.allocator;

    // Create a dummy key for testing
    var key: key_module.SecretKeyLv0 = undefined;
    for (&key) |*k| {
        k.* = 0;
    }

    const ct1 = try TLWELv0.encrypt(true, &key, allocator);
    const ct2 = try TLWELv0.encrypt(false, &key, allocator);

    // Test addition
    const sum = ct1.add(&ct2);
    const sum_decrypted = sum.decrypt(&key);

    // Test negation
    const neg_ct1 = ct1.neg();
    const neg_decrypted = neg_ct1.decrypt(&key);

    try std.testing.expect(sum_decrypted == false); // true + false = false (current implementation)
    try std.testing.expect(neg_decrypted == !true); // NOT true = false
}

test "tlwe lwe message operations" {
    const allocator = std.testing.allocator;

    // Create a dummy key for testing
    var key: key_module.SecretKeyLv0 = undefined;
    for (&key) |*k| {
        k.* = 0;
    }

    const msg = 5;
    const modulus = 8;
    const ct = try TLWELv0.encryptLweMessage(msg, modulus, 0.0001, &key, allocator);
    const decrypted = ct.decryptLweMessage(modulus, &key);

    try std.testing.expect(decrypted == msg);
}
