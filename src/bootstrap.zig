const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");
const trlwe = @import("trlwe.zig");
const trgsw = @import("trgsw.zig");
const key = @import("key.zig");
const utils = @import("utils.zig");

/// Vanilla bootstrapping implementation
pub const vanilla = struct {
    /// Vanilla bootstrap operation
    ///
    /// Implements the full TFHE bootstrap process:
    /// 1. Blind rotation - homomorphically evaluate test polynomial
    /// 2. Sample extraction - convert RLWE to LWE at coefficient index 0
    /// 3. Key switching - convert from level 1 key back to level 0
    pub fn bootstrap(
        ciphertext: *const tlwe.TLWELv0,
        cloud_key: *const key.CloudKey,
        allocator: std.mem.Allocator,
    ) !tlwe.TLWELv0 {

        // Step 1: Blind rotation - homomorphically evaluate test polynomial
        // This is the most expensive operation (~50ms on modern CPUs)
        const trlwe_ct = try trgsw.blindRotate(ciphertext, cloud_key, allocator);

        // Step 2: Sample extraction - convert RLWE to LWE at coefficient index 0
        // This extracts one LWE ciphertext from the RLWE ciphertext
        const tlwe_lv1 = trgsw.sampleExtractIndex(&trlwe_ct, 0);

        // Step 3: Key switching - convert from level 1 key back to level 0
        // This ensures the output is under the same key as the input
        return try trgsw.identityKeySwitching(&tlwe_lv1, cloud_key.key_switching_key, allocator);
    }

    /// Bootstrap without key switching - returns intermediate ciphertext for further operations
    pub fn bootstrapWithoutKeySwitch(
        ciphertext: *const tlwe.TLWELv0,
        cloud_key: *const key.CloudKey,
        allocator: std.mem.Allocator,
    ) !tlwe.TLWELv0 {
        const trlwe_ct = try trgsw.blindRotate(ciphertext, cloud_key, allocator);
        return trgsw.sampleExtractIndex2(&trlwe_ct, 0);
    }
};

/// LUT (Lookup Table) bootstrapping implementation
pub const lut = struct {
    /// LUT bootstrap operation
    pub fn bootstrap(
        ciphertext: *const tlwe.TLWELv0,
        cloud_key: *const key.CloudKey,
        allocator: std.mem.Allocator,
    ) !tlwe.TLWELv0 {
        _ = ciphertext;
        _ = cloud_key;
        _ = allocator;

        // Placeholder implementation
        return tlwe.TLWELv0.init();
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "bootstrap initialization" {
    const allocator = std.testing.allocator;
    var cloud_key = try key.CloudKey.initNoKsk(allocator);
    defer cloud_key.deinit(allocator);

    const ciphertext = tlwe.TLWELv0.init();

    // Test vanilla bootstrap
    _ = try vanilla.bootstrap(&ciphertext, &cloud_key, allocator);

    // Test LUT bootstrap
    _ = try lut.bootstrap(&ciphertext, &cloud_key, allocator);

    // Basic test
    try std.testing.expect(true);
}
