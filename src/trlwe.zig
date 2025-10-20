const std = @import("std");
const params = @import("params.zig");
const fft = @import("fft.zig");
const key_module = @import("key.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");

/// TRLWE (Torus Ring Learning With Errors) Level 1 ciphertext
///
/// This represents a polynomial ciphertext in the ring R[X]/(X^N+1)
/// where N is the polynomial degree (typically 1024 for level 1)
pub const TRLWELv1 = struct {
    /// Polynomial coefficients a[i] for i=0..N-1
    a: [params.implementation.trlwe_lv1.N]params.Torus,
    /// Polynomial coefficients b[i] for i=0..N-1 (includes message + noise)
    b: [params.implementation.trlwe_lv1.N]params.Torus,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .a = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
            .b = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
        };
    }

    /// Encrypt a polynomial message using TRLWE
    pub fn encryptF64(
        p: []const f64,
        alpha: f64,
        key: *const key_module.SecretKeyLv1,
        plan: *fft.FFTPlan,
        allocator: std.mem.Allocator,
    ) !Self {
        var trlwe = Self.init();

        // Generate random coefficients a[i]
        for (0..params.implementation.trlwe_lv1.N) |i| {
            const seed = @as(u64, @intCast(i)) *% 1103515245 +% 12345;
            trlwe.a[i] = @intCast(seed % std.math.pow(u64, 2, params.TORUS_SIZE));
        }

        // Generate noise for b coefficients
        var normal_distr = utils.NormalDistribution.init(0.0, alpha);
        const noise_vec = try utils.gaussianF64Vec(p, &normal_distr, allocator);
        defer allocator.free(noise_vec);

        // Copy to fixed-size array
        for (0..params.implementation.trlwe_lv1.N) |i| {
            trlwe.b[i] = utils.f64ToTorus(noise_vec[i]);
        }

        // Compute polynomial multiplication: b = b + a * s (where s is the secret key)
        const poly_res = try plan.processor.poly_mul(&trlwe.a, key);
        defer allocator.free(poly_res);

        for (0..params.implementation.trlwe_lv1.N) |i| {
            trlwe.b[i] = trlwe.b[i] +% poly_res[i];
        }

        return trlwe;
    }

    /// Decrypt a TRLWE ciphertext to get the polynomial message
    pub fn decryptF64(self: *const Self, key: *const key_module.SecretKeyLv1, plan: *fft.FFTPlan, allocator: std.mem.Allocator) ![]f64 {
        // Compute polynomial multiplication: result = b - a * s
        const poly_res = try plan.processor.poly_mul(&self.a, key);
        defer allocator.free(poly_res);

        var result = try allocator.alloc(f64, params.implementation.trlwe_lv1.N);
        for (0..params.implementation.trlwe_lv1.N) |i| {
            const diff = self.b[i] -% poly_res[i];
            result[i] = utils.torusToF64(diff);
        }

        return result;
    }

    /// Add two TRLWE ciphertexts
    pub fn add(self: *const Self, other: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trlwe_lv1.N) |i| {
            result.a[i] = self.a[i] +% other.a[i];
            result.b[i] = self.b[i] +% other.b[i];
        }

        return result;
    }

    /// Subtract two TRLWE ciphertexts
    pub fn sub(self: *const Self, other: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trlwe_lv1.N) |i| {
            result.a[i] = self.a[i] -% other.a[i];
            result.b[i] = self.b[i] -% other.b[i];
        }

        return result;
    }

    /// Multiply TRLWE ciphertext by a scalar
    pub fn mulScalar(self: *const Self, scalar: params.Torus) Self {
        var result = Self.init();

        for (0..params.implementation.trlwe_lv1.N) |i| {
            result.a[i] = self.a[i] *% scalar;
            result.b[i] = self.b[i] *% scalar;
        }

        return result;
    }

    /// Negate TRLWE ciphertext
    pub fn neg(self: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trlwe_lv1.N) |i| {
            result.a[i] = -%self.a[i];
            result.b[i] = -%self.b[i];
        }

        return result;
    }
};

/// TRLWE FFT structure for efficient operations
pub const TRLWELv1FFT = struct {
    a: [1024]f64,
    b: [1024]f64,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .a = [_]f64{0.0} ** 1024,
            .b = [_]f64{0.0} ** 1024,
        };
    }

    pub fn initFromTrlwe(trlwe: *const TRLWELv1, plan: *fft.FFTPlan, allocator: std.mem.Allocator) !Self {
        var result = Self.init();

        // Convert a polynomial to frequency domain
        const a_fft = try plan.processor.ifft(trlwe.a[0..]);
        defer allocator.free(a_fft);

        // Convert b polynomial to frequency domain
        const b_fft = try plan.processor.ifft(trlwe.b[0..]);
        defer allocator.free(b_fft);

        // Copy to fixed-size arrays
        for (0..1024) |i| {
            result.a[i] = a_fft[i];
            result.b[i] = b_fft[i];
        }

        return result;
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "trlwe initialization" {
    const trlwe = TRLWELv1.init();

    // Check that all coefficients are zero
    for (0..params.implementation.trlwe_lv1.N) |i| {
        try std.testing.expectEqual(@as(params.Torus, 0), trlwe.a[i]);
        try std.testing.expectEqual(@as(params.Torus, 0), trlwe.b[i]);
    }
}

test "trlwe encryption and decryption" {
    const allocator = std.testing.allocator;
    var plan = try fft.FFTPlan.new(allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var secret_key = try key_module.SecretKey.init(allocator);

    // Create test polynomial message
    var message = try allocator.alloc(f64, params.implementation.trlwe_lv1.N);
    defer allocator.free(message);

    for (0..params.implementation.trlwe_lv1.N) |i| {
        message[i] = @as(f64, @floatFromInt(i % 100)) / 100.0;
    }

    // Encrypt
    const encrypted = try TRLWELv1.encryptF64(message, 0.01, &secret_key.key_lv1, &plan, allocator);

    // Decrypt
    const decrypted = try encrypted.decryptF64(&secret_key.key_lv1, &plan, allocator);
    defer allocator.free(decrypted);

    // Check that decryption is close to original (within noise tolerance)
    for (0..params.implementation.trlwe_lv1.N) |i| {
        const diff = @abs(decrypted[i] - message[i]);
        try std.testing.expect(diff < 0.1); // Allow for noise
    }
}

test "trlwe homomorphic operations" {
    const allocator = std.testing.allocator;
    var plan = try fft.FFTPlan.new(allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var secret_key = try key_module.SecretKey.init(allocator);

    // Create test messages
    var message1 = try allocator.alloc(f64, params.implementation.trlwe_lv1.N);
    var message2 = try allocator.alloc(f64, params.implementation.trlwe_lv1.N);
    defer allocator.free(message1);
    defer allocator.free(message2);

    for (0..params.implementation.trlwe_lv1.N) |i| {
        message1[i] = @as(f64, @floatFromInt(i % 50)) / 100.0;
        message2[i] = @as(f64, @floatFromInt((i + 1) % 50)) / 100.0;
    }

    // Encrypt both messages
    const encrypted1 = try TRLWELv1.encryptF64(message1, 0.01, &secret_key.key_lv1, &plan, allocator);
    const encrypted2 = try TRLWELv1.encryptF64(message2, 0.01, &secret_key.key_lv1, &plan, allocator);

    // Test addition
    const sum = encrypted1.add(&encrypted2);
    const sum_decrypted = try sum.decryptF64(&secret_key.key_lv1, &plan, allocator);
    defer allocator.free(sum_decrypted);

    // Check that sum is approximately correct
    for (0..params.implementation.trlwe_lv1.N) |i| {
        const expected = message1[i] + message2[i];
        const diff = @abs(sum_decrypted[i] - expected);
        try std.testing.expect(diff < 0.2); // Allow for noise accumulation
    }

    // Test scalar multiplication
    const scalar = @as(params.Torus, 2);
    const scaled = encrypted1.mulScalar(scalar);
    const scaled_decrypted = try scaled.decryptF64(&secret_key.key_lv1, &plan, allocator);
    defer allocator.free(scaled_decrypted);

    // Check that scaling is approximately correct
    for (0..params.implementation.trlwe_lv1.N) |i| {
        const expected = message1[i] * 2.0;
        const diff = @abs(scaled_decrypted[i] - expected);
        try std.testing.expect(diff < 0.2); // Allow for noise
    }
}
