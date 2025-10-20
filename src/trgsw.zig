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

/// Polynomial multiplication by x^k for negacyclic polynomials
///
/// This implements the negacyclic polynomial multiplication where x^N = -1
pub fn polyMulWithXK(
    a: []const params.Torus,
    k: usize,
    allocator: std.mem.Allocator,
) ![]params.Torus {
    const N = params.implementation.trgsw_lv1.N;
    var result = try allocator.alloc(params.Torus, N);

    if (k < N) {
        // Copy elements from position k onwards
        for (0..N - k) |i| {
            result[k + i] = a[i];
        }
        // Handle wraparound with negation (negacyclic property)
        for (N - k..N) |i| {
            result[i + k - N] = 0 -% a[i];
        }
    } else {
        // Handle case where k >= N
        for (0..2 * N - k) |i| {
            result[i + k - N] = 0 -% a[i];
        }
        for (2 * N - k..N) |i| {
            result[i - (2 * N - k)] = a[i];
        }
    }

    return result;
}

/// Decomposition function for TRGSW operations
///
/// Decomposes a TRLWE ciphertext into its base-BG representation
pub fn decomposition(
    trlwe_ct: *const trlwe.TRLWELv1,
    cloud_key: *const key_module.CloudKey,
    allocator: std.mem.Allocator,
) ![][]params.Torus {
    const L = params.implementation.trgsw_lv1.L;
    const N = params.implementation.trgsw_lv1.N;
    const BGBIT = params.implementation.trgsw_lv1.BGBIT;
    const MASK: params.Torus = (1 << BGBIT) - 1;
    const HALF_BG: params.Torus = 1 << (BGBIT - 1);

    var result = try allocator.alloc([]params.Torus, L * 2);
    for (0..L * 2) |i| {
        result[i] = try allocator.alloc(params.Torus, N);
    }

    const offset = cloud_key.decomposition_offset;

    for (0..N) |j| {
        const tmp0 = trlwe_ct.a[j] +% offset;
        const tmp1 = trlwe_ct.b[j] +% offset;

        for (0..L) |i| {
            result[i][j] = ((tmp0 >> @as(u5, @intCast(32 - ((i + 1) * BGBIT)))) & MASK) -% HALF_BG;
        }

        for (0..L) |i| {
            result[i + L][j] = ((tmp1 >> @as(u5, @intCast(32 - ((i + 1) * BGBIT)))) & MASK) -% HALF_BG;
        }
    }

    return result;
}

/// FMA (Fused Multiply-Add) in frequency domain for 1024-point FFT
///
/// Performs complex multiply-accumulate: res += a * b
/// with proper scaling for negacyclic FFT
fn fmaInFd1024(
    res: []f64,
    a: []const f64,
    b: []const f64,
) void {
    // Complex multiply-accumulate in frequency domain: res += a * b
    // with 0.5 scaling for negacyclic FFT
    for (0..512) |i| {
        // Real part: res_re += (a_re*b_re - a_im*b_im) * 0.5
        res[i] = (a[i + 512] * b[i + 512]) * 0.5 - res[i];
        res[i] = (a[i] * b[i]) * 0.5 - res[i];
        // Imaginary part: res_im += (a_re*b_im + a_im*b_re) * 0.5
        res[i + 512] += (a[i] * b[i + 512] + a[i + 512] * b[i]) * 0.5;
    }
}

/// External product with FFT for TRGSW operations
///
/// This is the core operation for TRGSW multiplication
pub fn externalProductWithFft(
    trgsw_fft: *const TRGSWLv1FFT,
    trlwe_ct: *const trlwe.TRLWELv1,
    cloud_key: *const key_module.CloudKey,
    plan: *fft.FFTPlan,
    allocator: std.mem.Allocator,
) !trlwe.TRLWELv1 {
    const L = params.implementation.trgsw_lv1.L;
    const N = params.implementation.trgsw_lv1.N;

    // Decompose the input TRLWE
    const dec = try decomposition(trlwe_ct, cloud_key, allocator);
    defer {
        for (dec) |row| {
            allocator.free(row);
        }
        allocator.free(dec);
    }

    // Initialize output arrays
    var out_a_fft = try allocator.alloc(f64, 1024);
    defer allocator.free(out_a_fft);
    var out_b_fft = try allocator.alloc(f64, 1024);
    defer allocator.free(out_b_fft);

    // Initialize to zero
    for (0..1024) |i| {
        out_a_fft[i] = 0.0;
        out_b_fft[i] = 0.0;
    }

    // Batch IFFT all decomposition digits
    const dec_ffts = try plan.processor.batch_ifft(dec);
    defer {
        for (dec_ffts) |fft_result| {
            allocator.free(fft_result);
        }
        allocator.free(dec_ffts);
    }

    // Accumulate in frequency domain
    for (0..L * 2) |i| {
        fmaInFd1024(out_a_fft, dec_ffts[i], trgsw_fft.trlwe_fft_array[i].a[0..1024]);
        fmaInFd1024(out_b_fft, dec_ffts[i], trgsw_fft.trlwe_fft_array[i].b[0..1024]);
    }

    // Single IFFT per output polynomial
    const result_a = try plan.processor.fft(out_a_fft);
    defer allocator.free(result_a);
    const result_b = try plan.processor.fft(out_b_fft);
    defer allocator.free(result_b);

    var result = trlwe.TRLWELv1.init();
    for (0..N) |i| {
        result.a[i] = result_a[i];
        result.b[i] = result_b[i];
    }

    return result;
}

/// TRGSW FFT structure for efficient operations
pub const TRGSWLv1FFT = struct {
    trlwe_fft_array: [params.implementation.trgsw_lv1.L * 2]trlwe.TRLWELv1FFT,

    const Self = @This();

    pub fn init(trgsw: *const TRGSWLv1, plan: *fft.FFTPlan, allocator: std.mem.Allocator) !Self {
        var result = Self{
            .trlwe_fft_array = [_]trlwe.TRLWELv1FFT{trlwe.TRLWELv1FFT.init()} ** (params.implementation.trgsw_lv1.L * 2),
        };

        for (0..params.implementation.trgsw_lv1.L * 2) |i| {
            result.trlwe_fft_array[i] = try trlwe.TRLWELv1FFT.initFromTrlwe(&trgsw.trlwe_array[i], plan, allocator);
        }

        return result;
    }

    /// Initialize an empty TRGSWLv1FFT for testing purposes
    pub fn initEmpty() Self {
        return Self{
            .trlwe_fft_array = [_]trlwe.TRLWELv1FFT{trlwe.TRLWELv1FFT.init()} ** (params.implementation.trgsw_lv1.L * 2),
        };
    }
};

/// CMUX (Conditional Multiplexer) operation
///
/// Returns in1 if cond == 0, else in2
pub fn cmux(
    in1: *const trlwe.TRLWELv1,
    in2: *const trlwe.TRLWELv1,
    cond: *const TRGSWLv1FFT,
    cloud_key: *const key_module.CloudKey,
    plan: *fft.FFTPlan,
    allocator: std.mem.Allocator,
) !trlwe.TRLWELv1 {
    const N = params.implementation.trgsw_lv1.N;

    // Compute difference: tmp = in2 - in1
    var tmp = trlwe.TRLWELv1.init();
    for (0..N) |i| {
        tmp.a[i] = in2.a[i] -% in1.a[i];
        tmp.b[i] = in2.b[i] -% in1.b[i];
    }

    // External product: tmp2 = cond * tmp
    const tmp2 = try externalProductWithFft(cond, &tmp, cloud_key, plan, allocator);

    // Add in1: result = tmp2 + in1
    var result = trlwe.TRLWELv1.init();
    for (0..N) |i| {
        result.a[i] = tmp2.a[i] +% in1.a[i];
        result.b[i] = tmp2.b[i] +% in1.b[i];
    }

    return result;
}

/// Blind rotation function for bootstrapping
///
/// This is the core operation in TFHE bootstrapping that homomorphically
/// evaluates a test polynomial using TRGSW operations.
pub fn blindRotate(
    src: *const tlwe.TLWELv0,
    cloud_key: *const key_module.CloudKey,
    allocator: std.mem.Allocator,
) !trlwe.TRLWELv1 {
    const N = params.implementation.trgsw_lv1.N;
    const NBIT = params.implementation.trgsw_lv1.NBIT;

    // Create FFT plan for TRLWE operations
    var plan = try fft.FFTPlan.new(allocator, N);
    defer plan.deinit();

    // Compute b_tilda for initial rotation
    const b_tilda = 2 * N - (((@as(usize, @intCast(src.b())) + (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1)));

    // Initialize result with rotated test vector
    const testvec_a_rotated = try polyMulWithXK(cloud_key.blind_rotate_testvec.a[0..N], b_tilda, allocator);
    defer allocator.free(testvec_a_rotated);
    const testvec_b_rotated = try polyMulWithXK(cloud_key.blind_rotate_testvec.b[0..N], b_tilda, allocator);
    defer allocator.free(testvec_b_rotated);

    var result = trlwe.TRLWELv1.init();
    for (0..N) |i| {
        result.a[i] = testvec_a_rotated[i];
        result.b[i] = testvec_b_rotated[i];
    }

    // Iterate through each coefficient of the input ciphertext
    for (0..params.implementation.tlwe_lv0.N) |i| {
        const a_tilda = @as(usize, @intCast((src.p[i] +% (1 << (params.TORUS_SIZE - 1 - NBIT - 1))) >> (params.TORUS_SIZE - NBIT - 1)));

        // Create rotated version of current result
        const res_a_rotated = try polyMulWithXK(result.a[0..N], a_tilda, allocator);
        defer allocator.free(res_a_rotated);
        const res_b_rotated = try polyMulWithXK(result.b[0..N], a_tilda, allocator);
        defer allocator.free(res_b_rotated);

        var res2 = trlwe.TRLWELv1.init();
        for (0..N) |j| {
            res2.a[j] = res_a_rotated[j];
            res2.b[j] = res_b_rotated[j];
        }

        // Bootstrapping key is already in FFT form
        const bk_fft = &cloud_key.bootstrapping_key[i];

        // CMUX operation: result = cmux(result, res2, bk_fft)
        result = try cmux(&result, &res2, bk_fft, cloud_key, &plan, allocator);
    }

    return result;
}

/// Sample extraction function - converts RLWE to LWE at coefficient index k
pub fn sampleExtractIndex(
    trlwe_ct: *const trlwe.TRLWELv1,
    k: usize,
) tlwe.TLWELv1 {
    var result = tlwe.TLWELv1.init();

    const N = params.implementation.trlwe_lv1.N;

    // Extract coefficient k from the TRLWE ciphertext using negacyclic logic
    for (0..N) |i| {
        if (i <= k) {
            result.p[i] = trlwe_ct.a[k - i];
        } else {
            result.p[i] = 0 -% trlwe_ct.a[N + k - i];
        }
    }

    // Set the constant term
    result.p[N] = trlwe_ct.b[k];

    return result;
}

/// Sample extraction function variant 2 - returns TLWELv0 for bootstrap_without_key_switch
pub fn sampleExtractIndex2(
    trlwe_ct: *const trlwe.TRLWELv1,
    k: usize,
) tlwe.TLWELv0 {
    var result = tlwe.TLWELv0.init();

    const N = params.implementation.tlwe_lv0.N;
    const TRLWE_N = params.implementation.trlwe_lv1.N;

    // Extract coefficient k from the TRLWE ciphertext using negacyclic logic
    for (0..N) |i| {
        if (i <= k) {
            result.p[i] = trlwe_ct.a[k - i];
        } else {
            result.p[i] = 0 -% trlwe_ct.a[TRLWE_N + k - i];
        }
    }

    // Set the constant term
    result.p[N] = trlwe_ct.b[k];

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
