const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");
const trgsw = @import("trgsw.zig");
const fft = @import("fft.zig");
const trlwe = @import("trlwe.zig");
const utils = @import("utils.zig");

// Type aliases for key components
pub const SecretKeyLv0 = [params.implementation.tlwe_lv0.N]params.Torus;
pub const SecretKeyLv1 = [params.implementation.tlwe_lv1.N]params.Torus;

/// Secret key containing both level 0 and level 1 keys
pub const SecretKey = struct {
    key_lv0: SecretKeyLv0,
    key_lv1: SecretKeyLv1,

    const Self = @This();

    /// Initialize a new secret key with random values
    pub fn init(_: std.mem.Allocator) !Self {
        var key = Self{
            .key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N,
            .key_lv1 = [_]params.Torus{0} ** params.implementation.tlwe_lv1.N,
        };

        // Generate random binary keys using cryptographically secure random number generator
        for (&key.key_lv0) |*k| {
            k.* = if (std.crypto.random.boolean()) 1 else 0;
        }
        for (&key.key_lv1) |*k| {
            k.* = if (std.crypto.random.boolean()) 1 else 0;
        }

        return key;
    }

    /// Initialize a secret key with specific values (for testing)
    pub fn initWithValues(key_lv0: SecretKeyLv0, key_lv1: SecretKeyLv1) Self {
        return Self{
            .key_lv0 = key_lv0,
            .key_lv1 = key_lv1,
        };
    }
};

/// Cloud key containing all public parameters needed for homomorphic operations
pub const CloudKey = struct {
    decomposition_offset: params.Torus,
    blind_rotate_testvec: trlwe.TRLWELv1,
    key_switching_key: []tlwe.TLWELv0,
    bootstrapping_key: []trgsw.TRGSWLv1FFT,

    const Self = @This();

    /// Initialize a new cloud key from a secret key
    pub fn init(allocator: std.mem.Allocator, secret_key: *const SecretKey) !Self {
        return Self{
            .decomposition_offset = try genDecompositionOffset(allocator),
            .blind_rotate_testvec = try genTestvec(allocator),
            .key_switching_key = try genKeySwitchingKey(allocator, secret_key),
            .bootstrapping_key = try genBootstrappingKey(allocator, secret_key),
        };
    }

    /// Initialize a cloud key without key switching key (for testing)
    pub fn initNoKsk(allocator: std.mem.Allocator) !Self {
        const TRGSWLV1_BASE = std.math.pow(usize, 2, params.implementation.trgsw_lv1.BASEBIT);
        const TRGSWLV1_IKS_T = params.implementation.trgsw_lv1.IKS_T;
        const TRGSWLV1_N = params.implementation.trgsw_lv1.N;

        const key_switching_key = try allocator.alloc(tlwe.TLWELv0, TRGSWLV1_BASE * TRGSWLV1_IKS_T * TRGSWLV1_N);
        for (key_switching_key) |*ksk| {
            ksk.* = tlwe.TLWELv0.init();
        }

        const bootstrapping_key = try allocator.alloc(trgsw.TRGSWLv1FFT, params.implementation.tlwe_lv0.N);
        for (bootstrapping_key) |*bsk| {
            bsk.* = trgsw.TRGSWLv1FFT.initEmpty();
        }

        return Self{
            .decomposition_offset = try genDecompositionOffset(allocator),
            .blind_rotate_testvec = try genTestvec(allocator),
            .key_switching_key = key_switching_key,
            .bootstrapping_key = bootstrapping_key,
        };
    }

    /// Deinitialize the cloud key and free all resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.key_switching_key);
        allocator.free(self.bootstrapping_key);
    }
};

/// Generate decomposition offset for TRGSW operations
pub fn genDecompositionOffset(allocator: std.mem.Allocator) !params.Torus {
    _ = allocator; // Suppress unused parameter warning
    var offset: params.Torus = 0;

    for (0..params.implementation.trgsw_lv1.L) |i| {
        const i_torus = @as(params.Torus, @intCast(i));
        const bg_half = params.implementation.trgsw_lv1.BG / 2;
        const shift = params.TORUS_SIZE - (@as(usize, @intCast(i_torus + 1)) * params.implementation.trgsw_lv1.BGBIT);
        offset +%= bg_half *% std.math.pow(params.Torus, 2, @intCast(shift));
    }

    return offset;
}

/// Generate test vector for blind rotation
pub fn genTestvec(allocator: std.mem.Allocator) !trlwe.TRLWELv1 {
    _ = allocator; // Suppress unused parameter warning
    var testvec = trlwe.TRLWELv1.init();
    const b_torus = utils.f64ToTorus(0.125);

    for (0..params.implementation.trgsw_lv1.N) |i| {
        testvec.a[i] = 0;
        testvec.b[i] = b_torus;
    }

    return testvec;
}

/// Generate key switching key
pub fn genKeySwitchingKey(allocator: std.mem.Allocator, secret_key: *const SecretKey) ![]tlwe.TLWELv0 {
    const BASEBIT = params.implementation.trgsw_lv1.BASEBIT;
    const IKS_T = params.implementation.trgsw_lv1.IKS_T;
    const TRGSWLV1_BASE = std.math.pow(usize, 2, BASEBIT);
    const TRGSWLV1_IKS_T = IKS_T;
    const TRGSWLV1_N = params.implementation.trgsw_lv1.N;

    const res = try allocator.alloc(tlwe.TLWELv0, TRGSWLV1_BASE * TRGSWLV1_IKS_T * TRGSWLV1_N);

    for (0..params.implementation.trgsw_lv1.N) |i| {
        for (0..IKS_T) |j| {
            for (0..TRGSWLV1_BASE) |k| {
                if (k == 0) continue;

                const p = (@as(f64, @floatFromInt(k * secret_key.key_lv1[i])) /
                    @as(f64, @floatFromInt(std.math.pow(usize, 2, (j + 1) * BASEBIT))));
                const idx = (TRGSWLV1_BASE * TRGSWLV1_IKS_T * i) + (TRGSWLV1_BASE * j) + k;

                res[idx] = try tlwe.TLWELv0.encryptF64(p, params.KSK_ALPHA, &secret_key.key_lv0, allocator);
            }
        }
    }

    return res;
}

/// Generate bootstrapping key
pub fn genBootstrappingKey(allocator: std.mem.Allocator, secret_key: *const SecretKey) ![]trgsw.TRGSWLv1FFT {
    const res = try allocator.alloc(trgsw.TRGSWLv1FFT, params.implementation.tlwe_lv0.N);

    // Use thread-local FFT plan (matches Rust's FFT_PLAN approach)
    const plan = try fft.getFFTPlan(allocator);

    // Generate TRGSW encryptions for each coefficient of the level 0 key
    for (0..params.implementation.tlwe_lv0.N) |i| {
        const kval = secret_key.key_lv0[i];

        // Create TRGSW encryption of the key value using shared FFT plan
        const trgsw_enc = try trgsw.TRGSWLv1.encryptTorus(kval, params.BSK_ALPHA, &secret_key.key_lv1, plan, allocator);

        // Convert to FFT form using shared FFT plan
        res[i] = try trgsw.TRGSWLv1FFT.init(&trgsw_enc, plan, allocator);
    }

    return res;
}

/// Generate bootstrapping key with parallel processing
pub fn genBootstrappingKeyParallel(allocator: std.mem.Allocator, secret_key: *const SecretKey) ![]trgsw.TRGSWLv1FFT {
    const res = try allocator.alloc(trgsw.TRGSWLv1, params.implementation.tlwe_lv0.N);

    // Use Zig's built-in parallel processing
    const num_threads = std.Thread.getCpuCount() catch 1;
    const chunk_size = (params.implementation.tlwe_lv0.N + num_threads - 1) / num_threads;

    var threads = std.ArrayList(std.Thread).init(allocator);
    defer threads.deinit();

    for (0..num_threads) |thread_id| {
        const start = thread_id * chunk_size;
        const end = @min(start + chunk_size, params.implementation.tlwe_lv0.N);

        if (start >= params.implementation.tlwe_lv0.N) break;

        const thread = try std.Thread.spawn(.{}, struct {
            fn worker(
                secret_key_lv0: SecretKeyLv0,
                secret_key_lv1: SecretKeyLv1,
                result: []trgsw.TRGSWLv1FFT,
                start_idx: usize,
                end_idx: usize,
            ) !void {
                for (start_idx..end_idx) |i| {
                    const kval = secret_key_lv0[i];

                    // Create TRGSW encryption of the key value
                    const trgsw_enc = try trgsw.TRGSWLv1.encryptTorus(kval, params.BSK_ALPHA, &secret_key_lv1, std.heap.page_allocator);

                    // Convert to FFT representation
                    result[i] = try trgsw.TRGSWLv1FFT.init(std.heap.page_allocator, &trgsw_enc);
                }
            }
        }.worker, .{
            secret_key.key_lv0,
            secret_key.key_lv1,
            res.items,
            start,
            end,
        });

        try threads.append(thread);
    }

    // Wait for all threads to complete
    for (threads.items) |thread| {
        thread.join();
    }

    return res;
}

// ============================================================================
// TESTS
// ============================================================================

test "secret key generation" {
    const allocator = std.testing.allocator;
    const secret_key = try SecretKey.init(allocator);

    // Check that keys are not all zeros
    var has_nonzero_lv0 = false;
    var has_nonzero_lv1 = false;

    for (secret_key.key_lv0) |k| {
        if (k != 0) {
            has_nonzero_lv0 = true;
            break;
        }
    }

    for (secret_key.key_lv1) |k| {
        if (k != 0) {
            has_nonzero_lv1 = true;
            break;
        }
    }

    try std.testing.expect(has_nonzero_lv0);
    try std.testing.expect(has_nonzero_lv1);
}

test "cloud key generation" {
    const allocator = std.testing.allocator;
    const secret_key = try SecretKey.init(allocator);
    var cloud_key = try CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    // Check that all components are initialized
    try std.testing.expect(cloud_key.key_switching_key.len > 0);
    try std.testing.expect(cloud_key.bootstrapping_key.len > 0);
}

test "decomposition offset" {
    const allocator = std.testing.allocator;
    const offset = try genDecompositionOffset(allocator);

    // Offset should be non-zero
    try std.testing.expect(offset != 0);
}

test "test vector generation" {
    const allocator = std.testing.allocator;
    const testvec = try genTestvec(allocator);

    // Test vector should have non-zero b coefficients
    var has_nonzero = false;
    for (testvec.b) |b| {
        if (b != 0) {
            has_nonzero = true;
            break;
        }
    }

    try std.testing.expect(has_nonzero);
}
