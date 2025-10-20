const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const key_module = @import("key.zig");

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

    /// Encrypt a floating point value (simplified version)
    pub fn encryptF64(
        p: f64,
        _: f64,
        key: *const key_module.SecretKeyLv0,
        _: std.mem.Allocator,
    ) !Self {
        var tlwe = Self.init();
        var inner_product: params.Torus = 0;

        // Generate simple random coefficients and compute inner product
        for (0..params.implementation.tlwe_lv0.N) |i| {
            const rand_torus: params.Torus = @intCast(i * 12345 + 67890); // Simple pseudo-random
            inner_product +%= key[i] *% rand_torus;
            tlwe.p[i] = rand_torus;
        }

        // Add simple noise to the constant term
        const noise: params.Torus = @intFromFloat(@mod(p * 1000000.0, 4294967296.0)); // Simplified noise
        tlwe.p[params.implementation.tlwe_lv0.N] = noise +% inner_product;

        return tlwe;
    }

    /// Encrypt a boolean value
    pub fn encrypt(plaintext: bool, key: *const key_module.SecretKeyLv0, allocator: std.mem.Allocator) !Self {
        const p: f64 = if (plaintext) 0.25 else -0.25;
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
        const p: f64 = (@as(f64, @floatFromInt(msg)) / @as(f64, @floatFromInt(modulus))) - 0.5;
        return Self.encryptF64(p, alpha, key, allocator);
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
        
        return result > torus_half;
    }

    /// Decrypt an LWE message with given modulus
    pub fn decryptLweMessage(self: *const Self, modulus: usize, key: *const key_module.SecretKeyLv0) usize {
        var inner_product: params.Torus = 0;
        for (0..params.implementation.tlwe_lv0.N) |i| {
            inner_product +%= key[i] *% self.p[i];
        }

        const b_val = self.b();
        const result = b_val -% inner_product;
        
        // Convert torus to message
        const f64_result = utils.torusToF64(result) + 0.5;
        const msg = @as(usize, @intFromFloat(f64_result * @as(f64, @floatFromInt(modulus))));
        
        return msg % modulus;
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
    
    try std.testing.expect(sum_decrypted == (true or false)); // true OR false = true
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
