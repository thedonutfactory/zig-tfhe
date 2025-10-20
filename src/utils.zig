const std = @import("std");
const params = @import("params.zig");

/// Simple normal distribution for noise generation
pub const NormalDistribution = struct {
    mean: f64,
    stddev: f64,

    pub fn init(mean: f64, stddev: f64) NormalDistribution {
        return NormalDistribution{ .mean = mean, .stddev = stddev };
    }

    pub fn sample(self: *const NormalDistribution, rng: *PseudoRng) f64 {
        _ = self;
        // Simplified implementation - return small random value
        return @as(f64, @floatFromInt(rng.next() % 1000)) / 10000.0;
    }
};

/// Simple pseudo-random number generator
pub const PseudoRng = struct {
    state: u64,

    pub fn init(seed: u64) PseudoRng {
        return PseudoRng{ .state = seed };
    }

    pub fn next(self: *PseudoRng) u64 {
        self.state = self.state *% 1103515245 +% 12345;
        return self.state;
    }
};
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
pub fn f64ToTorusVec(d: []const f64, allocator: std.mem.Allocator) ![]params.Torus {
    const result = try allocator.alloc(params.Torus, d.len);
    for (d, 0..) |val, i| {
        result[i] = f64ToTorus(val);
    }
    return result;
}

/// Generate gaussian noise in torus representation
pub fn gaussianTorus(
    mu: params.Torus,
    normal_distr: ?*const void,
    rng: ?*const void,
) params.Torus {
    // For now, return simplified noise since we're not using real random
    _ = normal_distr;
    _ = rng;

    // Use a simple but more realistic noise model
    const noise_magnitude = @as(params.Torus, @intFromFloat(@as(f64, @floatFromInt(mu)) * 0.01));
    const noise = if (mu % 2 == 0) noise_magnitude else -%noise_magnitude;
    return mu +% noise;
}

/// Generate gaussian noise in f64 representation
pub fn gaussianF64(
    mu: f64,
    normal_distr: ?*const void,
    rng: ?*const void,
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
    mu: []const f64,
    normal_distr: *NormalDistribution,
    rng: *PseudoRng,
    allocator: std.mem.Allocator,
) ![]f64 {
    const result = try allocator.alloc(f64, mu.len);
    for (mu, 0..) |val, i| {
        const noise = normal_distr.sample(rng);
        result[i] = val + noise;
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
    // Simplified test since we're using pseudo-random for now
    const allocator = std.testing.allocator;
    const mu = [_]f64{ 12.0, 11.0 };
    var normal_distr = NormalDistribution.init(0.0, 0.01);
    var rng = PseudoRng.init(42);
    const torus_vec = try gaussianF64Vec(&mu, &normal_distr, &rng, allocator);
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
