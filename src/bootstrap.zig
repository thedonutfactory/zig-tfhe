//! Bootstrap module for TFHE
//!
//! This module provides bootstrapping functionality that refreshes noisy ciphertexts
//! by homomorphically evaluating the decryption function. Different strategies
//! can optimize for different tradeoffs (speed, accuracy, memory, hardware).

const std = @import("std");
const key = @import("key.zig");
const utils = @import("utils.zig");
const trgsw = @import("trgsw.zig");
const trlwe = @import("trlwe.zig");

// Import submodules
pub const vanilla = @import("bootstrap/vanilla.zig");

/// Trait for bootstrapping strategies
///
/// Bootstrapping is the core operation in TFHE that refreshes a noisy ciphertext
/// by homomorphically evaluating the decryption function. Different strategies
/// can optimize for different tradeoffs (speed, accuracy, memory, hardware).
///
/// # Core Operation
/// Bootstrap takes a noisy LWE ciphertext at level 0 and returns a refreshed
/// ciphertext with reduced noise, enabling unbounded homomorphic operations.
///
/// # Typical Flow
/// 1. Blind rotation: Homomorphically evaluate a test polynomial
/// 2. Sample extraction: Convert RLWE to LWE
/// 3. Key switching: Convert back to original key
pub const Bootstrap = struct {
    const Self = @This();

    /// Perform a full bootstrap with key switching
    ///
    /// Takes a potentially noisy ciphertext and returns a refreshed one
    /// under the original encryption key.
    bootstrap: *const fn (self: *const Self, ctxt: *const utils.Ciphertext, cloud_key: *const key.CloudKey) anyerror!utils.Ciphertext,

    /// Perform bootstrap without key switching
    ///
    /// Returns a ciphertext under the expanded RLWE key (level 1).
    /// Useful when chaining multiple operations before final key switch.
    bootstrap_without_key_switch: *const fn (self: *const Self, ctxt: *const utils.Ciphertext, cloud_key: *const key.CloudKey) anyerror!utils.Ciphertext,

    /// Get the name of this bootstrap strategy
    name: *const fn (self: *const Self) []const u8,
};

/// Get the default bootstrap strategy
pub fn defaultBootstrap() vanilla.VanillaBootstrap {
    return vanilla.VanillaBootstrap.new();
}

// ============================================================================
// TESTS
// ============================================================================

test "bootstrap module imports" {
    _ = vanilla;
    _ = defaultBootstrap;
}
