//! TRLWE (Ring Learning With Errors over the Torus) implementation
//!
//! This module provides TRLWE encryption, which is a ring-based variant of LWE
//! that operates over polynomial rings. TRLWE is essential for efficient
//! homomorphic operations in TFHE.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");
const fft = @import("fft.zig");
const key = @import("key.zig");

// ============================================================================
// TRLWE LEVEL 1 (Lv1) - Ring LWE over the torus
// ============================================================================

/// TRLWE Level 1 ciphertext - ring-based LWE with polynomial coefficients
pub const TRLWELv1 = struct {
    a: [params.implementation.trlwe_lv1.N]params.Torus,
    b: [params.implementation.trlwe_lv1.N]params.Torus,

    const Self = @This();

    /// Create a new zero TRLWE ciphertext
    pub fn new() TRLWELv1 {
        return TRLWELv1{
            .a = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
            .b = [_]params.Torus{0} ** params.implementation.trlwe_lv1.N,
        };
    }

    /// Encrypt a vector of floating-point values
    pub fn encryptF64(
        p: []const f64,
        alpha: f64,
        secret_key: []const params.Torus,
        plan: *fft.FFTPlan,
    ) !TRLWELv1 {
        var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        var trlwe = TRLWELv1.new();

        // Fill a with random values
        for (0..trlwe.a.len) |i| {
            trlwe.a[i] = rng.random().int(params.Torus);
        }

        // Generate noise for b
        var normal_distr = utils.NormalDist.init(0.0, alpha);
        const noise_vec = try utils.gaussianF64Vec(std.heap.page_allocator, p, &normal_distr, rng.random());
        defer std.heap.page_allocator.free(noise_vec);

        // Copy noise to b (assuming p.len == N)
        for (noise_vec, 0..) |noise, i| {
            trlwe.b[i] = noise;
        }

        // Compute polynomial multiplication: a * secret_key
        const poly_res = try plan.processor.poly_mul(&trlwe.a, secret_key);

        // Add polynomial result to b
        for (0..trlwe.b.len) |i| {
            trlwe.b[i] = trlwe.b[i] +% poly_res[i];
        }

        return trlwe;
    }

    /// Encrypt a vector of boolean values
    pub fn encryptBool(
        p_bool: []const bool,
        alpha: f64,
        secret_key: []const params.Torus,
        plan: *fft.FFTPlan,
    ) !TRLWELv1 {
        // Convert boolean values to floating-point
        var p_f64 = try std.heap.page_allocator.alloc(f64, p_bool.len);
        defer std.heap.page_allocator.free(p_f64);

        for (p_bool, 0..) |val, i| {
            p_f64[i] = if (val) 0.125 else -0.125;
        }

        return Self.encryptF64(p_f64, alpha, secret_key, plan);
    }

    /// Decrypt a vector of boolean values
    pub fn decryptBool(self: *const Self, secret_key: []const params.Torus, plan: *fft.FFTPlan) ![]bool {
        // Compute polynomial multiplication: a * secret_key
        const poly_res = try plan.processor.poly_mul(&self.a, secret_key);
        defer std.heap.page_allocator.free(poly_res);

        var res = try std.heap.page_allocator.alloc(bool, self.a.len);

        for (0..self.a.len) |i| {
            const value = @as(params.HalfTorus, @bitCast(self.b[i] -% poly_res[i]));
            res[i] = value >= 0;
        }

        return res;
    }
};

// ============================================================================
// TRLWE FFT REPRESENTATION
// ============================================================================

/// TRLWE Level 1 in FFT domain for efficient operations
pub const TRLWELv1FFT = struct {
    a: [params.implementation.trlwe_lv1.N]f64,
    b: [params.implementation.trlwe_lv1.N]f64,

    const Self = @This();

    /// Create FFT representation from TRLWE ciphertext
    pub fn new(trlwe: *const TRLWELv1, plan: *fft.FFTPlan) !TRLWELv1FFT {
        const a_fft = try plan.processor.ifft(&trlwe.a);
        defer plan.processor.allocator.free(a_fft);

        const b_fft = try plan.processor.ifft(&trlwe.b);
        defer plan.processor.allocator.free(b_fft);

        var result = TRLWELv1FFT{
            .a = [_]f64{0.0} ** params.implementation.trlwe_lv1.N,
            .b = [_]f64{0.0} ** params.implementation.trlwe_lv1.N,
        };

        // Copy FFT results to arrays
        for (a_fft, 0..) |val, i| {
            result.a[i] = val;
        }
        for (b_fft, 0..) |val, i| {
            result.b[i] = val;
        }

        return result;
    }

    /// Create a dummy FFT representation (all zeros)
    pub fn newDummy() TRLWELv1FFT {
        return TRLWELv1FFT{
            .a = [_]f64{0.0} ** params.implementation.trlwe_lv1.N,
            .b = [_]f64{0.0} ** params.implementation.trlwe_lv1.N,
        };
    }
};

// ============================================================================
// SAMPLE EXTRACTION FUNCTIONS
// ============================================================================

/// Extract a TLWE sample from TRLWE at a specific index
pub fn sampleExtractIndex(trlwe: *const TRLWELv1, k: usize) tlwe.TLWELv1 {
    var res = tlwe.TLWELv1.new();

    const N = params.implementation.trlwe_lv1.N;
    for (0..N) |i| {
        if (i <= k) {
            res.p[i] = trlwe.a[k - i];
        } else {
            res.p[i] = std.math.maxInt(params.Torus) - trlwe.a[N + k - i];
        }
    }
    res.bMut().* = trlwe.b[k];

    return res;
}

/// Extract a TLWE Level 0 sample from TRLWE at a specific index
pub fn sampleExtractIndex2(trlwe: *const TRLWELv1, k: usize) tlwe.TLWELv0 {
    var res = tlwe.TLWELv0.new();

    const N = params.implementation.tlwe_lv0.N;
    for (0..N) |i| {
        if (i <= k) {
            res.p[i] = trlwe.a[k - i];
        } else {
            res.p[i] = std.math.maxInt(params.Torus) - trlwe.a[N + k - i];
        }
    }
    res.bMut().* = trlwe.b[k];

    return res;
}

// ============================================================================
// TESTS
// ============================================================================

test "trlwe encryption and decryption" {
    var rng = std.Random.DefaultPrng.init(42);

    // Generate secret key
    const secret_key = key.SecretKey.new();
    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var correct: usize = 0;
    const try_num: usize = 100; // Reduced for faster testing
    const N = params.implementation.trlwe_lv1.N;

    for (0..try_num) |_| {
        // Generate random plaintext
        var plain_text = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text);

        for (0..N) |i| {
            plain_text[i] = rng.random().boolean();
        }

        // Encrypt
        const c = try TRLWELv1.encryptBool(
            plain_text,
            params.implementation.trlwe_lv1.ALPHA,
            &secret_key.key_lv1,
            &plan,
        );

        // Decrypt
        const dec = try c.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(dec);

        // Check correctness
        for (0..N) |j| {
            if (plain_text[j] == dec[j]) {
                correct += 1;
            }
        }
    }

    const probability = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(try_num * N));
    try std.testing.expect(probability > 0.95); // Should be very high success rate
}

test "sample extract index" {
    var rng = std.Random.DefaultPrng.init(42);

    // Generate secret key
    const secret_key = key.SecretKey.new();
    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var correct: usize = 0;
    const try_num: usize = 10;
    const N = params.implementation.trlwe_lv1.N;

    for (0..try_num) |_| {
        // Generate random plaintext
        var plain_text = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text);

        for (0..N) |i| {
            plain_text[i] = rng.random().boolean();
        }

        // Encrypt
        const c = try TRLWELv1.encryptBool(
            plain_text,
            params.implementation.trlwe_lv1.ALPHA,
            &secret_key.key_lv1,
            &plan,
        );

        // Test sample extraction
        for (0..N) |j| {
            const tlwe_sample = sampleExtractIndex(&c, j);
            const dec = tlwe_sample.decryptBool(&secret_key.key_lv1);

            if (plain_text[j] == dec) {
                correct += 1;
            }
        }
    }

    const probability = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(try_num * N));
    try std.testing.expect(probability > 0.95); // Should be very high success rate
}

test "trlwe fft representation" {
    var rng = std.Random.DefaultPrng.init(42);

    // Generate secret key
    _ = key.SecretKey.new();
    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    // Create a simple TRLWE
    var trlwe = TRLWELv1.new();
    for (0..trlwe.a.len) |i| {
        trlwe.a[i] = rng.random().int(params.Torus);
        trlwe.b[i] = rng.random().int(params.Torus);
    }

    // Convert to FFT representation
    const trlwe_fft = try TRLWELv1FFT.new(&trlwe, &plan);

    // Check that FFT representation was created
    try std.testing.expect(trlwe_fft.a.len == params.implementation.trlwe_lv1.N);
    try std.testing.expect(trlwe_fft.b.len == params.implementation.trlwe_lv1.N);
}

test "sample extraction deterministic" {
    // Create a simple TRLWE with known values
    var trlwe_ct = TRLWELv1.new();

    // Set only the b coefficients (a coefficients are all 0)
    trlwe_ct.b[0] = utils.f64ToTorus(0.125); // Should extract to 0.125
    trlwe_ct.b[1] = utils.f64ToTorus(0.0); // Should extract to 0.0
    trlwe_ct.b[2] = utils.f64ToTorus(0.25); // Should extract to 0.25

    // Test sample extraction at index 0
    const extracted = sampleExtractIndex(&trlwe_ct, 0);

    // Check that the extracted b value matches the original
    try std.testing.expect(extracted.p[params.implementation.tlwe_lv1.N] == trlwe_ct.b[0]);

    // Test sample extraction at index 1
    const extracted1 = sampleExtractIndex(&trlwe_ct, 1);
    try std.testing.expect(extracted1.p[params.implementation.tlwe_lv1.N] == trlwe_ct.b[1]);

    // Test sample extraction at index 2
    const extracted2 = sampleExtractIndex(&trlwe_ct, 2);
    try std.testing.expect(extracted2.p[params.implementation.tlwe_lv1.N] == trlwe_ct.b[2]);
}

test "trlwe encryption comparison" {
    std.debug.print("=== TRLWE ENCRYPTION COMPARISON - ZIG ===\n", .{});

    // Create deterministic test data
    const test_secret_key = key.SecretKey{
        .key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N,
        .key_lv1 = [_]params.Torus{0} ** params.implementation.tlwe_lv1.N,
    };

    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trgsw_lv1.N);
    defer plan.deinit();

    // Create deterministic message (all zeros)
    const message = [_]f64{0.0} ** params.implementation.trlwe_lv1.N;

    std.debug.print("Input message[0-4]: {d:.6} {d:.6} {d:.6} {d:.6} {d:.6}\n", .{ message[0], message[1], message[2], message[3], message[4] });
    std.debug.print("Secret key[0-4]: {} {} {} {} {}\n", .{ test_secret_key.key_lv1[0], test_secret_key.key_lv1[1], test_secret_key.key_lv1[2], test_secret_key.key_lv1[3], test_secret_key.key_lv1[4] });

    // Encrypt the message
    const encrypted = try TRLWELv1.encryptF64(&message, 0.01, &test_secret_key.key_lv1, &plan);

    std.debug.print("\nEncrypted TRLWE.a[0-4]: {} {} {} {} {}\n", .{ encrypted.a[0], encrypted.a[1], encrypted.a[2], encrypted.a[3], encrypted.a[4] });
    std.debug.print("Encrypted TRLWE.b[0-4]: {} {} {} {} {}\n", .{ encrypted.b[0], encrypted.b[1], encrypted.b[2], encrypted.b[3], encrypted.b[4] });

    // Test with non-zero message
    std.debug.print("\n=== Testing with non-zero message ===\n", .{});

    var message2 = [_]f64{0.0} ** params.implementation.trlwe_lv1.N;
    for (0..params.implementation.trlwe_lv1.N) |i| {
        message2[i] = @as(f64, @floatFromInt(i)) * 0.1;
    }

    std.debug.print("Input message2[0-4]: {d:.6} {d:.6} {d:.6} {d:.6} {d:.6}\n", .{ message2[0], message2[1], message2[2], message2[3], message2[4] });

    const encrypted2 = try TRLWELv1.encryptF64(&message2, 0.01, &test_secret_key.key_lv1, &plan);

    std.debug.print("Encrypted2 TRLWE.a[0-4]: {} {} {} {} {}\n", .{ encrypted2.a[0], encrypted2.a[1], encrypted2.a[2], encrypted2.a[3], encrypted2.a[4] });
    std.debug.print("Encrypted2 TRLWE.b[0-4]: {} {} {} {} {}\n", .{ encrypted2.b[0], encrypted2.b[1], encrypted2.b[2], encrypted2.b[3], encrypted2.b[4] });
}
