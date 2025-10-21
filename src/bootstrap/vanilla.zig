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

/// Vanilla bootstrap implementation.
pub const VanillaBootstrap = struct {
    const Self = @This();
    _private: void,

    /// Create a new vanilla bootstrap strategy.
    pub fn new() Self {
        return VanillaBootstrap{ ._private = {} };
    }

    /// Perform a full bootstrap with key switching.
    ///
    /// Takes a potentially noisy ciphertext and returns a refreshed one.
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

    /// Perform bootstrap without key switching.
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

    /// Get the name of this bootstrap strategy.
    pub fn name(self: *const Self) []const u8 {
        _ = self;
        return "vanilla";
    }
};
