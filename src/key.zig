//! Key generation and management for TFHE
//!
//! This module provides functionality for generating secret keys, cloud keys,
//! and other cryptographic keys needed for TFHE operations.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");
const fft = @import("fft.zig");

// Import TRLWE module
const trlwe = @import("trlwe.zig");

// Type alias for TRLWELv1
pub const TRLWELv1 = trlwe.TRLWELv1;

// Import TRGSW module
const trgsw = @import("trgsw.zig");

// Type alias for TRGSWLv1FFT
pub const TRGSWLv1FFT = trgsw.TRGSWLv1FFT;

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

pub const SecretKeyLv0 = [params.implementation.tlwe_lv0.N]params.Torus;
pub const SecretKeyLv1 = [params.implementation.tlwe_lv1.N]params.Torus;
pub const KeySwitchingKey = std.ArrayListUnmanaged(tlwe.TLWELv0);
pub const BootstrappingKey = std.ArrayListUnmanaged(TRGSWLv1FFT);

// ============================================================================
// SECRET KEY STRUCTURE
// ============================================================================

/// Secret key containing both level 0 and level 1 keys
pub const SecretKey = struct {
    key_lv0: SecretKeyLv0,
    key_lv1: SecretKeyLv1,

    const Self = @This();

    /// Create a new secret key with random values
    pub fn new() SecretKey {
        var rng = std.Random.DefaultPrng.init(utils.getUniqueSeed());
        var key = SecretKey{
            .key_lv0 = [_]params.Torus{0} ** params.implementation.tlwe_lv0.N,
            .key_lv1 = [_]params.Torus{0} ** params.implementation.tlwe_lv1.N,
        };

        // Fill with random boolean values (0 or 1)
        for (0..key.key_lv0.len) |i| {
            key.key_lv0[i] = if (rng.random().boolean()) 1 else 0;
        }
        for (0..key.key_lv1.len) |i| {
            key.key_lv1[i] = if (rng.random().boolean()) 1 else 0;
        }

        return key;
    }
};

// ============================================================================
// CLOUD KEY STRUCTURE
// ============================================================================

/// Cloud key containing all public parameters needed for homomorphic operations
pub const CloudKey = struct {
    decomposition_offset: params.Torus,
    blind_rotate_testvec: TRLWELv1,
    key_switching_key: KeySwitchingKey,
    bootstrapping_key: BootstrappingKey,

    const Self = @This();

    /// Create a new cloud key from a secret key
    pub fn new(allocator: std.mem.Allocator, secret_key: *const SecretKey) !CloudKey {
        return CloudKey{
            .decomposition_offset = genDecompositionOffset(),
            .blind_rotate_testvec = try genTestvec(allocator),
            .key_switching_key = try genKeySwitchingKey(allocator, secret_key),
            .bootstrapping_key = try genBootstrappingKey(allocator, secret_key),
        };
    }

    /// Create a new cloud key without key switching key (for testing)
    pub fn newNoKsk(allocator: std.mem.Allocator) !CloudKey {
        const TRGSWLV1_N = params.implementation.trgsw_lv1.N;
        const TRGSWLV1_IKS_T = params.implementation.trgsw_lv1.IKS_T;
        const TRGSWLV1_BASE = 1 << params.implementation.trgsw_lv1.BASEBIT;

        var key_switching_key = KeySwitchingKey{};
        try key_switching_key.resize(allocator, TRGSWLV1_BASE * TRGSWLV1_IKS_T * TRGSWLV1_N);

        var bootstrapping_key = BootstrappingKey{};
        try bootstrapping_key.resize(allocator, params.implementation.tlwe_lv0.N);
        for (0..bootstrapping_key.items.len) |i| {
            bootstrapping_key.items[i] = TRGSWLv1FFT.newDummy();
        }

        return CloudKey{
            .decomposition_offset = genDecompositionOffset(),
            .blind_rotate_testvec = try genTestvec(allocator),
            .key_switching_key = key_switching_key,
            .bootstrapping_key = bootstrapping_key,
        };
    }

    /// Deinitialize the cloud key and free all resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        _ = self.blind_rotate_testvec; // TRLWELv1 doesn't need deinit

        // Free key switching key items
        for (self.key_switching_key.items) |*item| {
            _ = item; // TLWELv0 doesn't need deinit
        }
        self.key_switching_key.deinit(allocator);

        // Free bootstrapping key items
        for (self.bootstrapping_key.items) |*item| {
            _ = item; // TRGSWLv1FFT doesn't need deinit
        }
        self.bootstrapping_key.deinit(allocator);
    }
};

// ============================================================================
// KEY GENERATION FUNCTIONS
// ============================================================================

/// Generate decomposition offset for gadget decomposition
pub fn genDecompositionOffset() params.Torus {
    var offset: params.Torus = 0;

    for (0..params.implementation.trgsw_lv1.L) |i| {
        const i_torus = @as(params.Torus, @intCast(i));
        const shift_amount = params.TORUS_SIZE - (@as(usize, @intCast(i_torus + 1)) * @as(usize, @intCast(params.implementation.trgsw_lv1.BGBIT)));
        offset = offset +% (params.implementation.trgsw_lv1.BG / 2) * (@as(params.Torus, @intCast(1)) << @intCast(shift_amount));
    }

    return offset;
}

/// Generate test vector for blind rotation
pub fn genTestvec(allocator: std.mem.Allocator) !TRLWELv1 {
    _ = allocator; // TRLWELv1 doesn't need allocator
    var testvec = TRLWELv1.new();
    const b_torus = utils.f64ToTorus(0.125);

    for (0..params.implementation.trgsw_lv1.N) |i| {
        testvec.a[i] = 0;
        testvec.b[i] = b_torus;
    }

    return testvec;
}

/// Generate key switching key
pub fn genKeySwitchingKey(allocator: std.mem.Allocator, secret_key: *const SecretKey) !KeySwitchingKey {
    const BASEBIT = params.implementation.trgsw_lv1.BASEBIT;
    const IKS_T = params.implementation.trgsw_lv1.IKS_T;
    const TRGSWLV1_BASE = 1 << BASEBIT;
    const TRGSWLV1_IKS_T = IKS_T;
    const TRGSWLV1_N = params.implementation.trgsw_lv1.N;

    var res = KeySwitchingKey{};
    try res.resize(allocator, TRGSWLV1_BASE * TRGSWLV1_IKS_T * TRGSWLV1_N);

    for (0..TRGSWLV1_N) |i| {
        for (0..IKS_T) |j| {
            for (0..TRGSWLV1_BASE) |k| {
                if (k == 0) continue;

                const shift_amount = (j + 1) * BASEBIT;
                const p = (@as(f64, @floatFromInt(k)) * @as(f64, @floatFromInt(secret_key.key_lv1[i]))) / @as(f64, @floatFromInt(@as(u32, @intCast(1)) << @intCast(shift_amount)));
                const idx = (TRGSWLV1_BASE * TRGSWLV1_IKS_T * i) + (TRGSWLV1_BASE * j) + k;
                res.items[idx] = try tlwe.TLWELv0.encryptF64(p, params.KSK_ALPHA, &secret_key.key_lv0);
            }
        }
    }

    return res;
}

/// Generate bootstrapping key
pub fn genBootstrappingKey(allocator: std.mem.Allocator, secret_key: *const SecretKey) !BootstrappingKey {
    // For now, use a simple sequential implementation
    // TODO: Implement parallel version when parallel module is available
    return genBootstrappingKeyWithRailgun(allocator, secret_key, null);
}

/// Generate bootstrapping key with railgun (parallel processing)
pub fn genBootstrappingKeyWithRailgun(
    allocator: std.mem.Allocator,
    secret_key: *const SecretKey,
    railgun: ?void, // Will be properly typed when parallel module is available
) !BootstrappingKey {
    _ = railgun; // Will be used when parallel module is available

    var bootstrapping_key = BootstrappingKey{};
    try bootstrapping_key.resize(allocator, params.implementation.tlwe_lv0.N);

    // Get or create thread-local FFT plan
    var temp_plan = try fft.FFTPlan.new(allocator, params.implementation.trgsw_lv1.N);
    defer temp_plan.deinit();

    // Sequential implementation: encrypt each key value
    for (0..params.implementation.tlwe_lv0.N) |i| {
        // Encrypt the i-th secret key value into a TRGSW ciphertext
        const kval = secret_key.key_lv0[i];
        const trgsw_encrypted = try trgsw.TRGSWLv1.encryptTorus(
            kval,
            params.BSK_ALPHA,
            &secret_key.key_lv1,
            &temp_plan,
        );

        // Convert to FFT representation for efficient operations
        bootstrapping_key.items[i] = try TRGSWLv1FFT.new(&trgsw_encrypted, &temp_plan);
    }

    return bootstrapping_key;
}

// ============================================================================
// TESTS
// ============================================================================

test "secret key generation" {
    const key = SecretKey.new();

    // Check that keys are not all zeros
    var has_nonzero_lv0 = false;
    var has_nonzero_lv1 = false;

    for (key.key_lv0) |val| {
        if (val != 0) {
            has_nonzero_lv0 = true;
            break;
        }
    }

    for (key.key_lv1) |val| {
        if (val != 0) {
            has_nonzero_lv1 = true;
            break;
        }
    }

    try std.testing.expect(has_nonzero_lv0);
    try std.testing.expect(has_nonzero_lv1);
}

test "cloud key generation" {
    const allocator = std.testing.allocator;
    const secret_key = SecretKey.new();
    var cloud_key = try CloudKey.new(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    // Check that cloud key was created successfully
    try std.testing.expect(cloud_key.key_switching_key.items.len > 0);
    try std.testing.expect(cloud_key.bootstrapping_key.items.len > 0);
}

test "decomposition offset generation" {
    const offset = genDecompositionOffset();
    // Offset should be non-zero
    try std.testing.expect(offset != 0);
}

test "test vector generation" {
    const allocator = std.testing.allocator;
    const testvec = try genTestvec(allocator);
    // TRLWELv1 doesn't need deinit

    // Check that test vector was created successfully
    try std.testing.expect(testvec.a.len == params.implementation.trgsw_lv1.N);
    try std.testing.expect(testvec.b.len == params.implementation.trgsw_lv1.N);
}
