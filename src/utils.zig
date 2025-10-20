const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");
const key_module = @import("key.zig");

/// Main ciphertext type - alias for TLWELv0
pub const Ciphertext = tlwe.TLWELv0;

/// Convert f64 to torus representation
pub fn f64ToTorus(d: f64) params.Torus {
    const torus = (@mod(d, 1.0)) * @as(f64, @floatFromInt(std.math.pow(u64, 2, params.TORUS_SIZE)));
    return @intCast(@as(params.IntTorus, @intFromFloat(torus)));
}

/// Convert torus to f64 representation
pub fn torusToF64(t: params.Torus) f64 {
    return @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(std.math.pow(u64, 2, params.TORUS_SIZE)));
}

/// Convert array of f64 to array of torus
pub fn f64ToTorusVec(allocator: std.mem.Allocator, d: []const f64) ![]params.Torus {
    const result = try allocator.alloc(params.Torus, d.len);
    for (d, 0..) |val, i| {
        result[i] = f64ToTorus(val);
    }
    return result;
}

/// Generate gaussian noise in torus representation
pub fn gaussianTorus(
    mu: params.Torus,
    normal_distr: *const std.rand.Normal(f64),
    rng: anytype,
) params.Torus {
    const sample = normal_distr.next(rng);
    return f64ToTorus(sample) +% mu;
}

/// Generate gaussian noise in f64 representation
pub fn gaussianF64(
    mu: f64,
    normal_distr: *const std.rand.Normal(f64),
    rng: anytype,
) params.Torus {
    const mu_torus = f64ToTorus(mu);
    return gaussianTorus(mu_torus, normal_distr, rng);
}

/// Generate array of gaussian noise in torus representation
pub fn gaussianTorusVec(
    allocator: std.mem.Allocator,
    mu: []const params.Torus,
    normal_distr: *const std.rand.Normal(f64),
    rng: anytype,
) ![]params.Torus {
    const result = try allocator.alloc(params.Torus, mu.len);
    for (mu, 0..) |val, i| {
        result[i] = gaussianTorus(val, normal_distr, rng);
    }
    return result;
}

/// Generate array of gaussian noise in f64 representation
pub fn gaussianF64Vec(
    allocator: std.mem.Allocator,
    mu: []const f64,
    normal_distr: *const std.rand.Normal(f64),
    rng: anytype,
) ![]params.Torus {
    const result = try allocator.alloc(params.Torus, mu.len);
    for (mu, 0..) |val, i| {
        result[i] = gaussianF64(val, normal_distr, rng);
    }
    return result;
}

/// Ciphertext operations and methods
pub const CiphertextOps = struct {
    /// Encrypt a boolean value
    pub fn encrypt(plaintext: bool, key: *const key_module.SecretKeyLv0, allocator: std.mem.Allocator) !Ciphertext {
        return tlwe.TLWELv0.encrypt(plaintext, key, allocator);
    }

    /// Decrypt a boolean value
    pub fn decrypt(ciphertext: *const Ciphertext, key: *const key_module.SecretKeyLv0) bool {
        return ciphertext.decrypt(key);
    }

    /// Encrypt an LWE message with given modulus
    pub fn encryptLweMessage(
        msg: usize,
        modulus: usize,
        alpha: f64,
        key: *const key_module.SecretKeyLv0,
        allocator: std.mem.Allocator,
    ) !Ciphertext {
        return tlwe.TLWELv0.encryptLweMessage(msg, modulus, alpha, key, allocator);
    }

    /// Decrypt an LWE message with given modulus
    pub fn decryptLweMessage(
        ciphertext: *const Ciphertext,
        modulus: usize,
        key: *const key_module.SecretKeyLv0,
    ) usize {
        return ciphertext.decryptLweMessage(modulus, key);
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "f64 to torus conversion" {
    const d: f64 = 0.5;
    const torus = f64ToTorus(d);
    const back = torusToF64(torus);
    
    // Should be approximately equal (within floating point precision)
    try std.testing.expectApproxEqAbs(d, back, 1e-10);
}

test "gaussian sampling" {
    var rng = std.rand.DefaultPrng.init(42);
    const normal = std.rand.Normal(f64).init(0.0, 0.1);
    
    const allocator = std.testing.allocator;
    const mu = [_]f64{12.0, 11.0};
    const torus_vec = try gaussianF64Vec(allocator, &mu, &normal, rng.random());
    defer allocator.free(torus_vec);
    
    try std.testing.expect(torus_vec.len == 2);
}

test "ciphertext operations" {
    const allocator = std.testing.allocator;
    
    // Create a dummy key for testing
    var key: key_module.SecretKeyLv0 = undefined;
    for (&key) |*k| {
        k.* = 0;
    }
    
    // Test boolean encryption/decryption
    const ct_true = try CiphertextOps.encrypt(true, &key, allocator);
    const ct_false = try CiphertextOps.encrypt(false, &key, allocator);
    
    const decrypted_true = CiphertextOps.decrypt(&ct_true, &key);
    const decrypted_false = CiphertextOps.decrypt(&ct_false, &key);
    
    try std.testing.expect(decrypted_true == true);
    try std.testing.expect(decrypted_false == false);
}
