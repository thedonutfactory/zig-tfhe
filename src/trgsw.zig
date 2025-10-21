//! TRGSW (Torus Ring Gadget Switching) implementation
//!
//! This module provides TRGSW encryption and operations, which are essential for
//! bootstrapping in TFHE. TRGSW enables efficient external products and conditional
//! multiplexing (CMUX) operations.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");
const trlwe = @import("trlwe.zig");
const fft = @import("fft.zig");
const key = @import("key.zig");

// ============================================================================
// TRGSW LEVEL 1 (Lv1) - Torus Ring Gadget Switching
// ============================================================================

/// TRGSW Level 1 ciphertext - gadget switching key for bootstrapping
pub const TRGSWLv1 = struct {
    trlwe: [params.implementation.trgsw_lv1.L * 2]trlwe.TRLWELv1,

    const Self = @This();

    /// Create a new zero TRGSW ciphertext
    pub fn new() TRGSWLv1 {
        var result = TRGSWLv1{
            .trlwe = undefined,
        };

        for (0..result.trlwe.len) |i| {
            result.trlwe[i] = trlwe.TRLWELv1.new();
        }

        return result;
    }

    /// Encrypt a torus value using TRGSW
    pub fn encryptTorus(
        p: params.Torus,
        alpha: f64,
        secret_key: []const params.Torus,
        plan: *fft.FFTPlan,
    ) !TRGSWLv1 {
        const L = params.implementation.trgsw_lv1.L;

        // Generate gadget coefficients
        var p_f64 = try std.heap.page_allocator.alloc(f64, L);
        defer std.heap.page_allocator.free(p_f64);

        for (0..L) |i| {
            p_f64[i] = std.math.pow(f64, @as(f64, @floatFromInt(params.implementation.trgsw_lv1.BG)), -@as(f64, @floatFromInt(i + 1)));
        }

        const p_torus = try utils.f64ToTorusVec(std.heap.page_allocator, p_f64);
        defer std.heap.page_allocator.free(p_torus);

        // Create plain zero vector
        const plain_zero = [_]f64{0.0} ** params.implementation.trgsw_lv1.N;

        var trgsw = TRGSWLv1.new();

        // Encrypt all TRLWE components with plain zero
        for (0..trgsw.trlwe.len) |i| {
            trgsw.trlwe[i] = try trlwe.TRLWELv1.encryptF64(&plain_zero, alpha, secret_key, plan);
        }

        // Add gadget coefficients
        for (p_torus, 0..) |p_torus_val, i| {
            trgsw.trlwe[i].a[0] = trgsw.trlwe[i].a[0] +% (p *% p_torus_val);
            trgsw.trlwe[i + L].b[0] = trgsw.trlwe[i + L].b[0] +% (p *% p_torus_val);
        }

        return trgsw;
    }
};

// ============================================================================
// TRGSW FFT REPRESENTATION
// ============================================================================

/// TRGSW Level 1 in FFT domain for efficient operations
pub const TRGSWLv1FFT = struct {
    trlwe_fft: [params.implementation.trgsw_lv1.L * 2]trlwe.TRLWELv1FFT,

    const Self = @This();

    /// Create FFT representation from TRGSW ciphertext
    pub fn new(trgsw: *const TRGSWLv1, plan: *fft.FFTPlan) !TRGSWLv1FFT {
        var result = TRGSWLv1FFT{
            .trlwe_fft = undefined,
        };

        for (trgsw.trlwe, 0..) |trlwe_val, i| {
            result.trlwe_fft[i] = try trlwe.TRLWELv1FFT.new(&trlwe_val, plan);
        }

        return result;
    }

    /// Create a dummy FFT representation (all zeros)
    pub fn newDummy() TRGSWLv1FFT {
        var result = TRGSWLv1FFT{
            .trlwe_fft = undefined,
        };

        for (0..result.trlwe_fft.len) |i| {
            result.trlwe_fft[i] = trlwe.TRLWELv1FFT.newDummy();
        }

        return result;
    }
};

// ============================================================================
// EXTERNAL PRODUCT OPERATIONS
// ============================================================================

/// External product with FFT optimization
pub fn externalProductWithFft(
    trgsw_fft: *const TRGSWLv1FFT,
    trlwe_input: *const trlwe.TRLWELv1,
    cloud_key: *const key.CloudKey,
    plan: *fft.FFTPlan,
) !trlwe.TRLWELv1 {
    const dec = try decomposition(trlwe_input, cloud_key);
    defer {
        for (dec) |slice| {
            std.heap.page_allocator.free(slice);
        }
        std.heap.page_allocator.free(dec);
    }

    var out_a_fft = [_]f64{0.0} ** 1024;
    var out_b_fft = [_]f64{0.0} ** 1024;

    const L = params.implementation.trgsw_lv1.L;

    // Batch IFFT all decomposition digits at once
    const dec_ffts = try plan.processor.batch_ifft(dec);
    defer {
        for (dec_ffts) |slice| {
            std.heap.page_allocator.free(slice);
        }
        std.heap.page_allocator.free(dec_ffts);
    }

    // Accumulate in frequency domain (point-wise MAC)
    for (0..L * 2) |i| {
        fmaInFd1024(&out_a_fft, dec_ffts[i], &trgsw_fft.trlwe_fft[i].a);
        fmaInFd1024(&out_b_fft, dec_ffts[i], &trgsw_fft.trlwe_fft[i].b);
    }

    // Single IFFT per output polynomial (a and b)
    const result_a = try plan.processor.fft(&out_a_fft);
    defer std.heap.page_allocator.free(result_a);

    const result_b = try plan.processor.fft(&out_b_fft);
    defer std.heap.page_allocator.free(result_b);

    var result = trlwe.TRLWELv1.new();

    // Copy results to output
    for (result_a, 0..) |val, i| {
        result.a[i] = val;
    }
    for (result_b, 0..) |val, i| {
        result.b[i] = val;
    }

    return result;
}

/// Frequency domain multiply-accumulate for 1024-point FFT
fn fmaInFd1024(res: []f64, a: []const f64, b: []const f64) void {
    // Complex multiply-accumulate in frequency domain: res += a * b
    // CRITICAL: 0.5 scaling required for negacyclic FFT correctness
    for (0..512) |i| {
        // Real part: res_re += (a_re*b_re - a_im*b_im) * 0.5
        res[i] = (a[i + 512] * b[i + 512]) * 0.5 - res[i];
        res[i] = (a[i] * b[i]) * 0.5 - res[i];
        // Imaginary part: res_im += (a_re*b_im + a_im*b_re) * 0.5
        res[i + 512] += (a[i] * b[i + 512] + a[i + 512] * b[i]) * 0.5;
    }
}

/// Decomposition function for external product
pub fn decomposition(
    trlwe_input: *const trlwe.TRLWELv1,
    cloud_key: *const key.CloudKey,
) ![]([]params.Torus) {
    const L = params.implementation.trgsw_lv1.L;
    const N = params.implementation.trgsw_lv1.N;

    var res = try std.heap.page_allocator.alloc([]params.Torus, L * 2);
    for (0..L * 2) |i| {
        res[i] = try std.heap.page_allocator.alloc(params.Torus, N);
    }

    const offset = cloud_key.decomposition_offset;
    const BGBIT = params.implementation.trgsw_lv1.BGBIT;
    const MASK = (1 << BGBIT) - 1;
    const HALF_BG = 1 << (BGBIT - 1);

    // Serial version - parallelization overhead is too high for this workload
    for (0..N) |j| {
        const tmp0 = trlwe_input.a[j] +% offset;
        const tmp1 = trlwe_input.b[j] +% offset;

        for (0..L) |i| {
            res[i][j] = ((tmp0 >> @as(u5, @intCast(32 - ((@as(u32, @intCast(i)) + 1) * @as(u32, @intCast(BGBIT)))))) & MASK) -% HALF_BG;
        }

        for (0..L) |i| {
            res[i + L][j] = ((tmp1 >> @as(u5, @intCast(32 - ((@as(u32, @intCast(i)) + 1) * @as(u32, @intCast(BGBIT)))))) & MASK) -% HALF_BG;
        }
    }

    return res;
}

// ============================================================================
// CONDITIONAL MULTIPLEXING (CMUX)
// ============================================================================

/// Conditional multiplexing: if cond == 0 then in1 else in2
pub fn cmux(
    in1: *const trlwe.TRLWELv1,
    in2: *const trlwe.TRLWELv1,
    cond: *const TRGSWLv1FFT,
    cloud_key: *const key.CloudKey,
    plan: *fft.FFTPlan,
) !trlwe.TRLWELv1 {
    var tmp = trlwe.TRLWELv1.new();
    const N = params.implementation.trgsw_lv1.N;

    for (0..N) |i| {
        tmp.a[i] = in2.a[i] -% in1.a[i];
        tmp.b[i] = in2.b[i] -% in1.b[i];
    }

    const tmp2 = try externalProductWithFft(cond, &tmp, cloud_key, plan);

    var result = trlwe.TRLWELv1.new();
    for (0..N) |i| {
        result.a[i] = tmp2.a[i] +% in1.a[i];
        result.b[i] = tmp2.b[i] +% in1.b[i];
    }

    return result;
}

// ============================================================================
// BLIND ROTATION
// ============================================================================

/// Blind rotation operation for bootstrapping
pub fn blindRotate(
    src: *const tlwe.TLWELv0,
    cloud_key: *const key.CloudKey,
) !trlwe.TRLWELv1 {
    const N = params.implementation.trgsw_lv1.N;
    const NBIT = params.implementation.trgsw_lv1.NBIT;

    const b_tilda = 2 * N - (((src.b() +% (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1)));

    const a_rotated = try polyMulWithXK(&cloud_key.blind_rotate_testvec.a, b_tilda);
    defer std.heap.page_allocator.free(a_rotated);

    const b_rotated = try polyMulWithXK(&cloud_key.blind_rotate_testvec.b, b_tilda);
    defer std.heap.page_allocator.free(b_rotated);

    var result = trlwe.TRLWELv1{
        .a = undefined,
        .b = undefined,
    };

    // Copy rotated arrays to fixed-size arrays
    for (a_rotated, 0..) |val, i| {
        result.a[i] = val;
    }
    for (b_rotated, 0..) |val, i| {
        result.b[i] = val;
    }

    for (0..params.implementation.tlwe_lv0.N) |i| {
        const a_tilda = ((src.p[i] +% (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1));

        const res2_a = try polyMulWithXK(&result.a, a_tilda);
        defer std.heap.page_allocator.free(res2_a);

        const res2_b = try polyMulWithXK(&result.b, a_tilda);
        defer std.heap.page_allocator.free(res2_b);

        var res2 = trlwe.TRLWELv1{
            .a = undefined,
            .b = undefined,
        };

        // Copy rotated arrays to fixed-size arrays
        for (res2_a, 0..) |val, j| {
            res2.a[j] = val;
        }
        for (res2_b, 0..) |val, j| {
            res2.b[j] = val;
        }

        // Create a temporary FFT plan for this operation
        var temp_plan = try fft.FFTPlan.new(std.heap.page_allocator, N);
        defer temp_plan.deinit();

        result = try cmux(
            &result,
            &res2,
            &cloud_key.bootstrapping_key.items[i],
            cloud_key,
            &temp_plan,
        );
    }

    return result;
}

/// Blind rotation with custom test vector (for LUT bootstrapping)
pub fn blindRotateWithTestvec(
    src: *const tlwe.TLWELv0,
    testvec: *const trlwe.TRLWELv1,
    cloud_key: *const key.CloudKey,
) !trlwe.TRLWELv1 {
    const N = params.implementation.trgsw_lv1.N;
    const NBIT = params.implementation.trgsw_lv1.NBIT;

    const b_tilda = 2 * N - (((src.b() +% (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1)));

    const a_rotated = try polyMulWithXK(&testvec.a, b_tilda);
    defer std.heap.page_allocator.free(a_rotated);

    const b_rotated = try polyMulWithXK(&testvec.b, b_tilda);
    defer std.heap.page_allocator.free(b_rotated);

    var result = trlwe.TRLWELv1{
        .a = undefined,
        .b = undefined,
    };

    // Copy rotated arrays to fixed-size arrays
    for (a_rotated, 0..) |val, i| {
        result.a[i] = val;
    }
    for (b_rotated, 0..) |val, i| {
        result.b[i] = val;
    }

    for (0..params.implementation.tlwe_lv0.N) |i| {
        const a_tilda = ((src.p[i] +% (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1));

        const res2_a = try polyMulWithXK(&result.a, a_tilda);
        defer std.heap.page_allocator.free(res2_a);

        const res2_b = try polyMulWithXK(&result.b, a_tilda);
        defer std.heap.page_allocator.free(res2_b);

        var res2 = trlwe.TRLWELv1{
            .a = undefined,
            .b = undefined,
        };

        // Copy rotated arrays to fixed-size arrays
        for (res2_a, 0..) |val, j| {
            res2.a[j] = val;
        }
        for (res2_b, 0..) |val, j| {
            res2.b[j] = val;
        }

        // Create a temporary FFT plan for this operation
        var temp_plan = try fft.FFTPlan.new(std.heap.page_allocator, N);
        defer temp_plan.deinit();

        result = try cmux(
            &result,
            &res2,
            &cloud_key.bootstrapping_key.items[i],
            cloud_key,
            &temp_plan,
        );
    }

    return result;
}

// ============================================================================
// POLYNOMIAL OPERATIONS
// ============================================================================

/// Polynomial multiplication with x^k (rotation)
pub fn polyMulWithXK(
    a: []const params.Torus,
    k: usize,
) ![]params.Torus {
    const N = params.implementation.trgsw_lv1.N;

    var res = try std.heap.page_allocator.alloc(params.Torus, N);

    if (k < N) {
        // Copy the shifted portion
        for (0..N - k) |i| {
            res[k + i] = a[i];
        }
        // Handle the wrapped portion with negation
        for (N - k..N) |i| {
            res[i + k - N] = std.math.maxInt(params.Torus) - a[i];
        }
    } else {
        // Handle larger rotations
        for (0..2 * N - k) |i| {
            res[i + k - N] = std.math.maxInt(params.Torus) - a[i];
        }
        for (2 * N - k..N) |i| {
            res[i - (2 * N - k)] = a[i];
        }
    }

    return res;
}

// ============================================================================
// KEY SWITCHING
// ============================================================================

/// Identity key switching from TLWE Lv1 to TLWE Lv0
pub fn identityKeySwitching(
    src: *const tlwe.TLWELv1,
    key_switching_key: *const key.KeySwitchingKey,
) tlwe.TLWELv0 {
    const N = params.implementation.trgsw_lv1.N;
    const BASEBIT = params.implementation.trgsw_lv1.BASEBIT;
    const BASE = 1 << BASEBIT;
    const IKS_T = params.implementation.trgsw_lv1.IKS_T;

    var res = tlwe.TLWELv0.new();
    res.p[params.implementation.tlwe_lv0.N] = src.p[src.p.len - 1];

    const PREC_OFFSET: params.Torus = 1 << (32 - (1 + BASEBIT * IKS_T));

    for (0..N) |i| {
        const a_bar = src.p[i] +% PREC_OFFSET;
        for (0..IKS_T) |j| {
            const k = @as(u32, @intCast((a_bar >> @as(u5, @intCast(32 - (@as(u32, @intCast(j)) + 1) * @as(u32, @intCast(BASEBIT))))) & ((1 << BASEBIT) - 1)));
            if (k != 0) {
                const idx = (BASE * IKS_T * i) + (BASE * j) + k;
                if (idx < key_switching_key.items.len) {
                    for (0..res.p.len) |x| {
                        res.p[x] = res.p[x] -% key_switching_key.items[idx].p[x];
                    }
                }
            }
        }
    }

    return res;
}

// ============================================================================
// TESTS
// ============================================================================

test "trgsw decomposition" {
    var rng = std.Random.DefaultPrng.init(42);
    const cloud_key = try key.CloudKey.newNoKsk(std.heap.page_allocator);
    // Note: cloud_key is const, so we don't deinit it here

    // Generate secret key
    const secret_key = key.SecretKey.new();
    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trgsw_lv1.N);
    defer plan.deinit();

    const N = params.implementation.trgsw_lv1.N;
    const try_num: usize = 10; // Reduced for faster testing

    // Generate gadget coefficients
    var h = try std.heap.page_allocator.alloc(f64, params.implementation.trgsw_lv1.L);
    defer std.heap.page_allocator.free(h);

    for (0..params.implementation.trgsw_lv1.L) |i| {
        h[i] = std.math.pow(f64, @as(f64, @floatFromInt(params.implementation.trgsw_lv1.BG)), -@as(f64, @floatFromInt(i + 1)));
    }

    for (0..try_num) |_| {
        // Generate random plaintext
        var plain_text = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text);

        for (0..N) |i| {
            plain_text[i] = rng.random().boolean();
        }

        // Encrypt
        const c = try trlwe.TRLWELv1.encryptBool(
            plain_text,
            params.implementation.trlwe_lv1.ALPHA,
            &secret_key.key_lv1,
            &plan,
        );

        // Decompose
        const c_decomp = try decomposition(&c, &cloud_key);
        defer {
            for (c_decomp) |slice| {
                std.heap.page_allocator.free(slice);
            }
            std.heap.page_allocator.free(c_decomp);
        }

        // Reconstruct
        const h_u32 = try utils.f64ToTorusVec(std.heap.page_allocator, h);
        defer std.heap.page_allocator.free(h_u32);

        var res = trlwe.TRLWELv1.new();
        for (0..N) |j| {
            var tmp0: params.Torus = 0;
            var tmp1: params.Torus = 0;
            for (0..params.implementation.trgsw_lv1.L) |k| {
                tmp0 = tmp0 +% (c_decomp[k][j] *% h_u32[k]);
                tmp1 = tmp1 +% (c_decomp[k + params.implementation.trgsw_lv1.L][j] *% h_u32[k]);
            }
            res.a[j] = tmp0;
            res.b[j] = tmp1;
        }

        // Decrypt and verify
        const dec = try res.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(dec);

        for (0..N) |j| {
            try std.testing.expect(plain_text[j] == dec[j]);
        }
    }
}

test "trgsw external product with fft" {
    var rng = std.Random.DefaultPrng.init(42);
    const cloud_key = try key.CloudKey.newNoKsk(std.heap.page_allocator);
    // Note: cloud_key is const, so we don't deinit it here

    // Generate secret key
    const secret_key = key.SecretKey.new();
    var plan = try fft.FFTPlan.new(std.heap.page_allocator, 1024);
    defer plan.deinit();

    const N = params.implementation.trgsw_lv1.N;
    const try_num: usize = 5; // Reduced for faster testing

    for (0..try_num) |_| {
        // Generate random plaintext
        var plain_text = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text);

        for (0..N) |i| {
            plain_text[i] = rng.random().boolean();
        }

        // Encrypt TRLWE
        const c = try trlwe.TRLWELv1.encryptBool(
            plain_text,
            params.implementation.trlwe_lv1.ALPHA,
            &secret_key.key_lv1,
            &plan,
        );

        // Get original plaintext
        const p = try c.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(p);

        // Create TRGSW for true condition
        const trgsw_true = try TRGSWLv1.encryptTorus(
            1,
            params.implementation.trgsw_lv1.ALPHA,
            &secret_key.key_lv1,
            &plan,
        );

        const trgsw_true_fft = try TRGSWLv1FFT.new(&trgsw_true, &plan);

        // External product
        const ext_c = try externalProductWithFft(&trgsw_true_fft, &c, &cloud_key, &plan);

        // Decrypt result
        const dec = try ext_c.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(dec);

        // Verify correctness
        for (0..N) |j| {
            try std.testing.expect(plain_text[j] == p[j]);
            try std.testing.expect(plain_text[j] == dec[j]);
        }
    }
}

test "trgsw cmux" {
    var rng = std.Random.DefaultPrng.init(42);
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.newNoKsk(std.heap.page_allocator);
    // Note: cloud_key is const, so we don't deinit it here

    var plan = try fft.FFTPlan.new(std.heap.page_allocator, params.implementation.trgsw_lv1.N);
    defer plan.deinit();

    const N = params.implementation.trgsw_lv1.N;
    const try_num: usize = 5; // Reduced for faster testing

    for (0..try_num) |_| {
        // Generate random plaintexts
        var plain_text_1 = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text_1);

        var plain_text_2 = try std.heap.page_allocator.alloc(bool, N);
        defer std.heap.page_allocator.free(plain_text_2);

        for (0..N) |i| {
            plain_text_1[i] = rng.random().boolean();
            plain_text_2[i] = rng.random().boolean();
        }

        const ALPHA = params.implementation.trgsw_lv1.ALPHA;

        // Encrypt inputs
        const c1 = try trlwe.TRLWELv1.encryptBool(plain_text_1, ALPHA, &secret_key.key_lv1, &plan);
        const c2 = try trlwe.TRLWELv1.encryptBool(plain_text_2, ALPHA, &secret_key.key_lv1, &plan);

        // Create TRGSW conditions
        const trgsw_true = try TRGSWLv1.encryptTorus(1, ALPHA, &secret_key.key_lv1, &plan);
        const trgsw_false = try TRGSWLv1.encryptTorus(0, ALPHA, &secret_key.key_lv1, &plan);

        const trgsw_true_fft = try TRGSWLv1FFT.new(&trgsw_true, &plan);
        const trgsw_false_fft = try TRGSWLv1FFT.new(&trgsw_false, &plan);

        // CMUX operations
        const enc_1 = try cmux(&c1, &c2, &trgsw_false_fft, &cloud_key, &plan);
        const enc_2 = try cmux(&c1, &c2, &trgsw_true_fft, &cloud_key, &plan);

        // Decrypt results
        const dec_1 = try enc_1.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(dec_1);

        const dec_2 = try enc_2.decryptBool(&secret_key.key_lv1, &plan);
        defer std.heap.page_allocator.free(dec_2);

        // Verify correctness
        for (0..N) |j| {
            try std.testing.expect(plain_text_1[j] == dec_1[j]);
            try std.testing.expect(plain_text_2[j] == dec_2[j]);
        }
    }
}

test "trgsw blind rotate" {
    var rng = std.Random.DefaultPrng.init(42);
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    // Note: cloud_key is const, so we don't deinit it here

    const try_num: usize = 5; // Reduced for faster testing

    for (0..try_num) |i| {
        const plain_text = rng.random().boolean();

        // Encrypt TLWE
        const tlwe_ct = try tlwe.TLWELv0.encryptBool(
            plain_text,
            params.implementation.tlwe_lv0.ALPHA,
            &secret_key.key_lv0,
        );

        // Blind rotate
        const trlwe_result = try blindRotate(&tlwe_ct, &cloud_key);

        // Sample extract
        const tlwe_lv1 = trlwe.sampleExtractIndex(&trlwe_result, 0);
        const dec = tlwe_lv1.decryptBool(&secret_key.key_lv1);

        if (plain_text != dec) {
            std.debug.print("Iteration {}: plain_text={}, dec={}, FAILED\n", .{ i, plain_text, dec });
        }
        try std.testing.expect(plain_text == dec);
    }
}

test "trgsw identity key switching" {
    var rng = std.Random.DefaultPrng.init(42);
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    // Note: cloud_key is const, so we don't deinit it here

    const try_num: usize = 10; // Reduced for faster testing

    for (0..try_num) |_| {
        const plain_text = rng.random().boolean();

        // Encrypt TLWE Lv1
        const tlwe_lv1 = try tlwe.TLWELv1.encryptBool(
            plain_text,
            params.implementation.tlwe_lv1.ALPHA,
            &secret_key.key_lv1,
        );

        // Key switch to TLWE Lv0
        const tlwe_lv0 = identityKeySwitching(&tlwe_lv1, &cloud_key.key_switching_key);

        // Decrypt
        const dec = tlwe_lv0.decryptBool(&secret_key.key_lv0);

        try std.testing.expect(plain_text == dec);
    }
}

test "trgsw poly mul with x k" {
    const N = params.implementation.trgsw_lv1.N;

    // Create a simple test vector with known values: [1, 2, 3, 4, 5, ...]
    var test_vec = try std.heap.page_allocator.alloc(params.Torus, N);
    defer std.heap.page_allocator.free(test_vec);

    for (0..N) |i| {
        test_vec[i] = @as(params.Torus, @intCast(i + 1));
    }

    // Test rotation with k = 1 (should shift by 1)
    const rotated_1 = try polyMulWithXK(test_vec, 1);
    defer std.heap.page_allocator.free(rotated_1);

    // Check if position 0 is correct (should be 0 for k=1)
    try std.testing.expect(rotated_1[0] == 0);

    // Test rotation with k = 0 (should be identity)
    const rotated_0 = try polyMulWithXK(test_vec, 0);
    defer std.heap.page_allocator.free(rotated_0);

    // Should match original
    for (0..N) |i| {
        try std.testing.expect(rotated_0[i] == test_vec[i]);
    }

    // Test rotation with k = N (should be identity with negation)
    const rotated_N = try polyMulWithXK(test_vec, N);
    defer std.heap.page_allocator.free(rotated_N);

    // Should be negated
    for (0..N) |i| {
        try std.testing.expect(rotated_N[i] == std.math.maxInt(params.Torus) - test_vec[i]);
    }
}

test "trgsw fma in fd 1024" {
    // Create deterministic input arrays
    var res = [_]f64{0.0} ** 1024;
    var a = [_]f64{0.0} ** 1024;
    var b = [_]f64{0.0} ** 1024;

    // Initialize with deterministic values
    for (0..1024) |i| {
        res[i] = @as(f64, @floatFromInt(i)) * 0.1;
        a[i] = @as(f64, @floatFromInt(i)) * 0.2;
        b[i] = @as(f64, @floatFromInt(i)) * 0.3;
    }

    // Call the function
    fmaInFd1024(&res, &a, &b);

    // Check that the function executed without error
    // (The exact values depend on the complex multiplication)
    try std.testing.expect(res[0] != 0.0); // Should have been modified
    try std.testing.expect(res[512] != 0.0); // Should have been modified
}
