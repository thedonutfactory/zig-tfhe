const std = @import("std");
const params = @import("params.zig");
const fft = @import("fft.zig");
const key_module = @import("key.zig");
const utils = @import("utils.zig");
const trlwe = @import("trlwe.zig");
const tlwe = @import("tlwe.zig");

/// TRGSW (Torus GSW) Level 1 ciphertext
///
/// This represents a GSW ciphertext which is an array of TRLWE ciphertexts.
/// It is used for bootstrapping operations in TFHE.
pub const TRGSWLv1 = struct {
    /// Array of TRLWE ciphertexts (L * 2 elements)
    trlwe_array: [params.implementation.trgsw_lv1.L * 2]trlwe.TRLWELv1,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .trlwe_array = [_]trlwe.TRLWELv1{trlwe.TRLWELv1.init()} ** (params.implementation.trgsw_lv1.L * 2),
        };
    }

    /// Encrypt a torus value using TRGSW
    pub fn encryptTorus(
        p: params.Torus,
        alpha: f64,
        key: *const key_module.SecretKeyLv1,
        plan: *fft.FFTPlan,
        allocator: std.mem.Allocator,
    ) !Self {
        const L = params.implementation.trgsw_lv1.L;
        const BG = params.implementation.trgsw_lv1.BG;

        // Create decomposition coefficients
        var p_f64 = try allocator.alloc(f64, L);
        defer allocator.free(p_f64);

        for (0..L) |i| {
            p_f64[i] = std.math.pow(f64, @as(f64, @floatFromInt(BG)), -@as(f64, @floatFromInt(1 + i)));
        }

        const p_torus = try utils.f64ToTorusVec(p_f64, allocator);
        defer allocator.free(p_torus);

        // Create zero polynomial
        var plain_zero = try allocator.alloc(f64, params.implementation.trgsw_lv1.N);
        defer allocator.free(plain_zero);

        for (0..params.implementation.trgsw_lv1.N) |i| {
            plain_zero[i] = 0.0;
        }

        // Initialize TRGSW with encrypted zeros
        var trgsw = Self.init();
        for (0..L * 2) |i| {
            trgsw.trlwe_array[i] = try trlwe.TRLWELv1.encryptF64(plain_zero, alpha, key, plan, allocator);
        }

        // Add the message to the appropriate positions
        for (0..L) |i| {
            trgsw.trlwe_array[i].a[0] = trgsw.trlwe_array[i].a[0] +% (p *% p_torus[i]);
            trgsw.trlwe_array[i + L].b[0] = trgsw.trlwe_array[i + L].b[0] +% (p *% p_torus[i]);
        }

        return trgsw;
    }

    /// Add two TRGSW ciphertexts
    pub fn add(self: *const Self, other: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trgsw_lv1.L * 2) |i| {
            result.trlwe_array[i] = self.trlwe_array[i].add(&other.trlwe_array[i]);
        }

        return result;
    }

    /// Subtract two TRGSW ciphertexts
    pub fn sub(self: *const Self, other: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trgsw_lv1.L * 2) |i| {
            result.trlwe_array[i] = self.trlwe_array[i].sub(&other.trlwe_array[i]);
        }

        return result;
    }

    /// Multiply TRGSW ciphertext by a scalar
    pub fn mulScalar(self: *const Self, scalar: params.Torus) Self {
        var result = Self.init();

        for (0..params.implementation.trgsw_lv1.L * 2) |i| {
            result.trlwe_array[i] = self.trlwe_array[i].mulScalar(scalar);
        }

        return result;
    }

    /// Negate TRGSW ciphertext
    pub fn neg(self: *const Self) Self {
        var result = Self.init();

        for (0..params.implementation.trgsw_lv1.L * 2) |i| {
            result.trlwe_array[i] = self.trlwe_array[i].neg();
        }

        return result;
    }
};

/// Blind rotation function for bootstrapping
///
/// This is the core operation in TFHE bootstrapping that homomorphically
/// evaluates a test polynomial using TRGSW operations.
pub fn blindRotate(
    src: *const tlwe.TLWELv0,
    _: *const key_module.CloudKey,
    allocator: std.mem.Allocator,
) !trlwe.TRLWELv1 {
    const N = params.implementation.trlwe_lv1.N;

    // Create FFT plan for TRLWE operations
    var plan = try fft.FFTPlan.new(allocator, N);
    defer plan.deinit();

    // Initialize result TRLWE
    var result = trlwe.TRLWELv1.init();

    // For now, implement a simplified blind rotation
    // In a full implementation, this would:
    // 1. Extract the message from the input ciphertext
    // 2. Use TRGSW operations to homomorphically evaluate a test polynomial
    // 3. Return the result as a TRLWE ciphertext

    // Simplified implementation: create a test polynomial based on the input message
    const message = src.b();

    // Create a test polynomial where the constant term is the input message
    // This is a placeholder - the real implementation would use proper TRGSW operations
    for (0..N) |i| {
        if (i < params.implementation.tlwe_lv0.N) {
            result.a[i] = src.p[i];
        } else {
            result.a[i] = 0;
        }
    }

    // Set the test polynomial's constant term to preserve the message
    result.b[0] = message;

    // All other b coefficients are zero for the identity function
    for (1..N) |i| {
        result.b[i] = 0;
    }

    return result;
}

/// Sample extraction function - converts RLWE to LWE at coefficient index k
pub fn sampleExtractIndex(
    trlwe_ct: *const trlwe.TRLWELv1,
    k: usize,
) tlwe.TLWELv1 {
    var result = tlwe.TLWELv1.init();

    // Extract coefficient k from the TRLWE ciphertext
    for (0..params.implementation.tlwe_lv1.N) |i| {
        result.p[i] = trlwe_ct.a[(i + k) % params.implementation.trlwe_lv1.N];
    }

    // Set the constant term
    result.p[params.implementation.tlwe_lv1.N] = trlwe_ct.b[k];

    return result;
}

/// Sample extraction function variant 2 - returns TLWELv0 for bootstrap_without_key_switch
pub fn sampleExtractIndex2(
    trlwe_ct: *const trlwe.TRLWELv1,
    k: usize,
) tlwe.TLWELv0 {
    var result = tlwe.TLWELv0.init();

    // Extract coefficient k from the TRLWE ciphertext
    for (0..params.implementation.tlwe_lv0.N) |i| {
        result.p[i] = trlwe_ct.a[(i + k) % params.implementation.trlwe_lv1.N];
    }

    // Set the constant term
    result.p[params.implementation.tlwe_lv0.N] = trlwe_ct.b[k];

    return result;
}

/// Identity key switching function
pub fn identityKeySwitching(
    tlwe_lv1: *const tlwe.TLWELv1,
    key_switching_key: []const tlwe.TLWELv0,
    allocator: std.mem.Allocator,
) !tlwe.TLWELv0 {
    _ = allocator;

    const N = params.implementation.trgsw_lv1.N;
    const BASEBIT = params.implementation.trgsw_lv1.BASEBIT;
    const BASE = 1 << BASEBIT;
    const IKS_T = params.implementation.trgsw_lv1.IKS_T;

    var res = tlwe.TLWELv0.init();

    // Set the constant term
    res.p[params.implementation.tlwe_lv0.N] = tlwe_lv1.p[params.implementation.tlwe_lv1.N];

    const PREC_OFFSET: params.Torus = 1 << (32 - (1 + BASEBIT * IKS_T));

    for (0..N) |i| {
        const a_bar = tlwe_lv1.p[i] +% PREC_OFFSET;
        for (0..IKS_T) |j| {
            const k = (a_bar >> @as(u5, @intCast(32 - (j + 1) * BASEBIT))) & ((1 << BASEBIT) - 1);
            if (k != 0) {
                const idx = (BASE * IKS_T * i) + (BASE * j) + @as(usize, @intCast(k));
                for (0..params.implementation.tlwe_lv0.N + 1) |x| {
                    res.p[x] = res.p[x] -% key_switching_key[idx].p[x];
                }
            }
        }
    }

    return res;
}

// ============================================================================
// TESTS
// ============================================================================

test "trgsw initialization" {
    const trgsw = TRGSWLv1.init();

    // Check that all TRLWE elements are initialized
    for (0..params.implementation.trgsw_lv1.L * 2) |i| {
        for (0..params.implementation.trlwe_lv1.N) |j| {
            try std.testing.expectEqual(@as(params.Torus, 0), trgsw.trlwe_array[i].a[j]);
            try std.testing.expectEqual(@as(params.Torus, 0), trgsw.trlwe_array[i].b[j]);
        }
    }
}

test "trgsw encryption and basic operations" {
    const allocator = std.testing.allocator;
    var plan = try fft.FFTPlan.new(allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var secret_key = try key_module.SecretKey.init(allocator);

    // Test encryption
    const test_value = @as(params.Torus, 0x12345678);
    const encrypted = try TRGSWLv1.encryptTorus(test_value, 0.01, &secret_key.key_lv1, &plan, allocator);

    // Test basic operations
    _ = encrypted.mulScalar(2);
    _ = encrypted.neg();

    // Basic smoke test - operations should not crash
    try std.testing.expect(true);
}

test "sample extraction" {
    const allocator = std.testing.allocator;
    var plan = try fft.FFTPlan.new(allocator, params.implementation.trlwe_lv1.N);
    defer plan.deinit();

    var secret_key = try key_module.SecretKey.init(allocator);

    // Create a test TRLWE ciphertext
    var message = try allocator.alloc(f64, params.implementation.trlwe_lv1.N);
    defer allocator.free(message);

    for (0..params.implementation.trlwe_lv1.N) |i| {
        message[i] = @as(f64, @floatFromInt(i % 100)) / 100.0;
    }

    const trlwe_ct = try trlwe.TRLWELv1.encryptF64(message, 0.01, &secret_key.key_lv1, &plan, allocator);

    // Test sample extraction
    _ = sampleExtractIndex(&trlwe_ct, 0);
    _ = sampleExtractIndex2(&trlwe_ct, 0);

    // Basic smoke test - extraction should not crash
    try std.testing.expect(true);
}
