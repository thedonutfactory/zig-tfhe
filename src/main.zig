//! Zig TFHE Library
//!
//! A port of the rs-tfhe library to Zig, providing fully homomorphic encryption
//! capabilities with the TFHE (Torus Fully Homomorphic Encryption) scheme.
//!
//! This library implements the TFHE scheme, which allows computation on encrypted data
//! without decrypting it. It provides TLWE (basic torus learning with errors encryption),
//! TRLWE (ring learning with errors over the torus), TRGSW (gadget switching keys for
//! bootstrapping), FFT (fast Fourier transform for polynomial operations), homomorphic
//! logic gates (AND, OR, NOT, etc.), and noise reduction through bootstrapping.
//!
//! Example usage:
//! ```zig
//! const tfhe = @import("main");
//! const std = @import("std");
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     defer _ = gpa.deinit();
//!     const allocator = gpa.allocator();
//!
//!     const secret_key = tfhe.key.SecretKey.new();
//!     const cloud_key = try tfhe.key.CloudKey.new(allocator, &secret_key);
//!     defer cloud_key.deinit(allocator);
//!
//!     const encrypted_a = try tfhe.tlwe.TLWELv0.encryptBool(true, tfhe.params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
//!     const encrypted_b = try tfhe.tlwe.TLWELv0.encryptBool(false, tfhe.params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
//!
//!     const result = encrypted_a.add(&encrypted_b);
//!     const decrypted = result.decryptBool(&secret_key.key_lv0);
//! }
//! ```

const std = @import("std");

/// Security parameters and configuration.
pub const params = @import("params.zig");

/// Utility functions for torus operations and noise generation.
pub const utils = @import("utils.zig");

/// Bit manipulation utilities.
pub const bit_utils = @import("bit_utils.zig");

/// Fast Fourier Transform for polynomial operations.
pub const fft = @import("fft.zig");

/// TLWE (Torus Learning With Errors) encryption.
pub const tlwe = @import("tlwe.zig");

/// Key generation and management.
pub const key = @import("key.zig");

/// TRLWE (Ring Learning With Errors) encryption.
pub const trlwe = @import("trlwe.zig");

/// TRGSW (Ring GSW) encryption for bootstrapping.
pub const trgsw = @import("trgsw.zig");

/// Homomorphic logic gates.
pub const gates = @import("gates.zig");

/// Bootstrapping operations.
pub const bootstrap = @import("bootstrap.zig");

/// Lookup table operations for programmable bootstrapping.
pub const lut = @import("lut.zig");

/// Parallel processing utilities.
pub const parallel = @import("parallel.zig");

/// Library version.
pub const version = "0.1.0";

/// Library name.
pub const name = "zig-tfhe";

/// Library description.
pub const description = "A Zig port of the rs-tfhe library for fully homomorphic encryption";

/// Get library information.
pub fn getInfo() struct { name: []const u8, version: []const u8, description: []const u8 } {
    return .{
        .name = name,
        .version = version,
        .description = description,
    };
}

/// Print library information to debug output.
pub fn printInfo() void {
    const info = getInfo();
    std.debug.print("{} v{} - {s}\n", .{ info.name, info.version, info.description });
}

test "library info" {
    const info = getInfo();
    try std.testing.expectEqualStrings("zig-tfhe", info.name);
    try std.testing.expectEqualStrings("0.1.0", info.version);
    try std.testing.expectEqualStrings("A Zig port of the rs-tfhe library for fully homomorphic encryption", info.description);
}

test "basic functionality" {
    // Test that we can create a secret key
    const secret_key = key.SecretKey.new();

    // Test that we can encrypt and decrypt
    const encrypted = try tlwe.TLWELv0.encryptBool(true, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
    const decrypted = encrypted.decryptBool(&secret_key.key_lv0);

    try std.testing.expect(decrypted == true);
}

test "module imports" {
    // Test that all core modules can be imported
    _ = params;
    _ = utils;
    _ = bit_utils;
    _ = fft;
    _ = tlwe;
    _ = trlwe;
    _ = trgsw;
    _ = gates;
    _ = bootstrap;
    _ = lut;
    _ = parallel;
    _ = key;
}
