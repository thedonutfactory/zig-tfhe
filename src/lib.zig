//! zig-tfhe: A high-performance Zig implementation of TFHE (Torus Fully Homomorphic Encryption)
//!
//! This is the main library file that exports all TFHE functionality.

// Core modules
pub const params = @import("params.zig");
pub const utils = @import("utils.zig");
pub const tlwe = @import("tlwe.zig");
pub const trlwe = @import("trlwe.zig");
pub const trgsw = @import("trgsw.zig");
pub const key = @import("key.zig");
pub const gates = @import("gates.zig");
pub const fft = @import("fft.zig");
pub const bootstrap = @import("bootstrap.zig");
pub const lut = @import("lut.zig");

// Re-export main types for convenience
pub const SecretKey = key.SecretKey;
pub const CloudKey = key.CloudKey;
pub const TLWELv0 = tlwe.TLWELv0;
pub const Ciphertext = utils.Ciphertext;
pub const Gates = gates.Gates;
