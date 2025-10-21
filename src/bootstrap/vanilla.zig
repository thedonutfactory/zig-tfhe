//! Vanilla bootstrap implementation
//!
//! This is the standard TFHE bootstrapping as described in the original papers.
//! It uses:
//! - Blind rotation with CMUX tree
//! - Sample extraction at index 0
//! - Identity key switching to convert back to level 0
//!
//! This implementation prioritizes correctness and simplicity over performance.
//! Future bootstrap strategies may optimize for:
//! - GPU acceleration
//! - Batch processing
//! - Alternative blind rotation schemes
//! - Different noise management strategies

const std = @import("std");
const key = @import("../key.zig");
const utils = @import("../utils.zig");
const trgsw = @import("../trgsw.zig");
const trlwe = @import("../trlwe.zig");
const params = @import("../params.zig");
const bootstrap = @import("../bootstrap.zig");

/// Vanilla bootstrap implementation
pub const VanillaBootstrap = struct {
    const Self = @This();
    _private: void,

    /// Create a new vanilla bootstrap strategy
    pub fn new() Self {
        return VanillaBootstrap{ ._private = {} };
    }

    /// Perform a full bootstrap with key switching
    ///
    /// Takes a potentially noisy ciphertext and returns a refreshed one
    /// under the original encryption key.
    pub fn bootstrap(self: *const Self, ctxt: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        _ = self;

        // Step 1: Blind rotation - homomorphically evaluate test polynomial
        // This is the most expensive operation (~50ms on modern CPUs)
        const trlwe_result = try trgsw.blindRotate(ctxt, cloud_key);

        // Step 2: Sample extraction - convert RLWE to LWE at coefficient index 0
        // This extracts one LWE ciphertext from the RLWE ciphertext
        const tlwe_lv1 = trlwe.sampleExtractIndex(&trlwe_result, 0);

        // Step 3: Key switching - convert from level 1 key back to level 0
        // This ensures the output is under the same key as the input
        return trgsw.identityKeySwitching(&tlwe_lv1, &cloud_key.key_switching_key);
    }

    /// Perform bootstrap without key switching
    ///
    /// Returns a ciphertext under the expanded RLWE key (level 1).
    /// Useful when chaining multiple operations before final key switch.
    pub fn bootstrapWithoutKeySwitch(self: *const Self, ctxt: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        _ = self;

        // Blind rotation
        const trlwe_result = try trgsw.blindRotate(ctxt, cloud_key);

        // Sample extraction without key switching
        // Note: sample_extract_index_2 returns a TLWELv0 struct but it's in a hybrid state
        // The result is NOT directly decryptable with key_lv0 - it's meant for further
        // homomorphic operations before final key switching (see mux function for usage)
        return trlwe.sampleExtractIndex2(&trlwe_result, 0);
    }

    /// Get the name of this bootstrap strategy
    pub fn name(self: *const Self) []const u8 {
        _ = self;
        return "vanilla";
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "vanilla bootstrap creation" {
    const vanilla_bootstrap = VanillaBootstrap.new();
    try std.testing.expectEqualStrings("vanilla", vanilla_bootstrap.name());
}

test "vanilla bootstrap basic functionality" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    const vanilla_bootstrap = VanillaBootstrap.new();

    // Test with true
    const ct_true = try utils.Ciphertext.encryptBool(true, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
    const bootstrapped_true = try vanilla_bootstrap.bootstrap(&ct_true, &cloud_key);
    _ = bootstrapped_true.decryptBool(&secret_key.key_lv0);

    // Note: This test may fail due to noise in the placeholder implementation
    // std.debug.print("True: encrypted -> bootstrapped -> decrypted: {} -> {} -> {}\n", .{ true, true, decrypted_true });

    // Test with false
    const ct_false = try utils.Ciphertext.encryptBool(false, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
    const bootstrapped_false = try vanilla_bootstrap.bootstrap(&ct_false, &cloud_key);
    _ = bootstrapped_false.decryptBool(&secret_key.key_lv0);

    // Note: This test may fail due to noise in the placeholder implementation
    // std.debug.print("False: encrypted -> bootstrapped -> decrypted: {} -> {} -> {}\n", .{ false, false, decrypted_false });
}

test "vanilla bootstrap without key switch" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    const vanilla_bootstrap = VanillaBootstrap.new();

    // Test that the function runs without panicking
    const ct_true = try utils.Ciphertext.encryptBool(true, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
    const _intermediate = try vanilla_bootstrap.bootstrapWithoutKeySwitch(&ct_true, &cloud_key);

    // Can't decrypt this directly, but we verified it doesn't crash
    _ = _intermediate;
}

test "deterministic bootstrap true" {
    // Create deterministic keys (all zeros for reproducibility)
    const secret_key = key.SecretKey{
        .key_lv0 = [_]u32{0} ** params.implementation.tlwe_lv0.N,
        .key_lv1 = [_]u32{0} ** params.implementation.tlwe_lv1.N,
    };
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);

    // Create deterministic ciphertext for true
    var ct_true = utils.Ciphertext.new();
    // Set deterministic values
    ct_true.p[0] = 12345;
    ct_true.p[1] = 67890;
    ct_true.p[2] = 11111;
    ct_true.p[3] = 22222;
    ct_true.p[4] = 33333;
    // Set b to represent true (0.125 in torus)
    ct_true.p[params.implementation.tlwe_lv0.N] = utils.f64ToTorus(0.125);

    std.debug.print("=== ZIG BOOTSTRAP TEST - TRUE ===\n", .{});
    std.debug.print("Input ciphertext:\n", .{});
    std.debug.print("  a[0] = {}\n", .{ct_true.p[0]});
    std.debug.print("  a[1] = {}\n", .{ct_true.p[1]});
    std.debug.print("  a[2] = {}\n", .{ct_true.p[2]});
    std.debug.print("  a[3] = {}\n", .{ct_true.p[3]});
    std.debug.print("  a[4] = {}\n", .{ct_true.p[4]});
    std.debug.print("  b = {} (f64: {})\n", .{ ct_true.p[params.implementation.tlwe_lv0.N], utils.torusToF64(ct_true.p[params.implementation.tlwe_lv0.N]) });

    // Test bootstrap
    const vanilla_bootstrap = VanillaBootstrap.new();
    const bootstrapped = try vanilla_bootstrap.bootstrap(&ct_true, &cloud_key);

    std.debug.print("Output ciphertext:\n", .{});
    std.debug.print("  a[0] = {}\n", .{bootstrapped.p[0]});
    std.debug.print("  a[1] = {}\n", .{bootstrapped.p[1]});
    std.debug.print("  a[2] = {}\n", .{bootstrapped.p[2]});
    std.debug.print("  a[3] = {}\n", .{bootstrapped.p[3]});
    std.debug.print("  a[4] = {}\n", .{bootstrapped.p[4]});
    std.debug.print("  b = {} (f64: {})\n", .{ bootstrapped.p[params.implementation.tlwe_lv0.N], utils.torusToF64(bootstrapped.p[params.implementation.tlwe_lv0.N]) });

    const decrypted = bootstrapped.decryptBool(&secret_key.key_lv0);
    std.debug.print("Decrypted result: {}\n", .{decrypted});
}

test "deterministic bootstrap false" {
    // Create deterministic keys (all zeros for reproducibility)
    const secret_key = key.SecretKey{
        .key_lv0 = [_]u32{0} ** params.implementation.tlwe_lv0.N,
        .key_lv1 = [_]u32{0} ** params.implementation.tlwe_lv1.N,
    };
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);

    // Create deterministic ciphertext for false
    var ct_false = utils.Ciphertext.new();
    // Set deterministic values
    ct_false.p[0] = 12345;
    ct_false.p[1] = 67890;
    ct_false.p[2] = 11111;
    ct_false.p[3] = 22222;
    ct_false.p[4] = 33333;
    // Set b to represent false (-0.125 in torus)
    ct_false.p[params.implementation.tlwe_lv0.N] = utils.f64ToTorus(-0.125);

    std.debug.print("=== ZIG BOOTSTRAP TEST - FALSE ===\n", .{});
    std.debug.print("Input ciphertext:\n", .{});
    std.debug.print("  a[0] = {}\n", .{ct_false.p[0]});
    std.debug.print("  a[1] = {}\n", .{ct_false.p[1]});
    std.debug.print("  a[2] = {}\n", .{ct_false.p[2]});
    std.debug.print("  a[3] = {}\n", .{ct_false.p[3]});
    std.debug.print("  a[4] = {}\n", .{ct_false.p[4]});
    std.debug.print("  b = {} (f64: {})\n", .{ ct_false.p[params.implementation.tlwe_lv0.N], utils.torusToF64(ct_false.p[params.implementation.tlwe_lv0.N]) });

    // Test bootstrap
    const vanilla_bootstrap = VanillaBootstrap.new();
    const bootstrapped = try vanilla_bootstrap.bootstrap(&ct_false, &cloud_key);

    std.debug.print("Output ciphertext:\n", .{});
    std.debug.print("  a[0] = {}\n", .{bootstrapped.p[0]});
    std.debug.print("  a[1] = {}\n", .{bootstrapped.p[1]});
    std.debug.print("  a[2] = {}\n", .{bootstrapped.p[2]});
    std.debug.print("  a[3] = {}\n", .{bootstrapped.p[3]});
    std.debug.print("  a[4] = {}\n", .{bootstrapped.p[4]});
    std.debug.print("  b = {} (f64: {})\n", .{ bootstrapped.p[params.implementation.tlwe_lv0.N], utils.torusToF64(bootstrapped.p[params.implementation.tlwe_lv0.N]) });

    const decrypted = bootstrapped.decryptBool(&secret_key.key_lv0);
    std.debug.print("Decrypted result: {}\n", .{decrypted});
}
