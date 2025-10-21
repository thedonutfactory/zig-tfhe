//! Lookup Table (LUT) support for programmable bootstrapping
//!
//! This module provides functionality for creating and using lookup tables
//! in programmable bootstrapping operations. LUT bootstrapping allows
//! evaluating arbitrary functions on encrypted data during the bootstrapping
//! process, combining noise refreshing with function evaluation.
//!
//! # Key Concepts
//!
//! - **Lookup Table**: A TRLWE ciphertext that encodes a function for evaluation
//! - **Programmable Bootstrapping**: Apply arbitrary functions during bootstrapping
//! - **Message Encoding**: Support for different message moduli (binary, multi-bit)
//! - **Function Evaluation**: Evaluate f(x) on encrypted x during bootstrapping
//!
//! # Example
//!
//! ```zig
//! const lut = @import("lut.zig");
//! const bootstrap = @import("bootstrap.zig");
//! const key = @import("key.zig");
//! const utils = @import("utils.zig");
//! const params = @import("params.zig");
//!
//! // Create a generator for binary messages
//! const generator = lut.Generator.new(2);
//!
//! // Define a function (e.g., NOT)
//! const not_func = struct {
//!     fn call(x: usize) usize {
//!         return 1 - x;
//!     }
//! }.call;
//!
//! // Generate lookup table
//! const lut_table = generator.generateLookupTable(not_func);
//!
//! // Use in programmable bootstrapping
//! const bootstrap_impl = bootstrap.vanilla.VanillaBootstrap.new();
//! const secret_key = key.SecretKey.new();
//! const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
//! const ciphertext = try utils.Ciphertext.encryptLweMessage(1, 2, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
//! const result = try bootstrap_impl.bootstrapLut(&ciphertext, &lut_table, &cloud_key);
//! ```

const std = @import("std");

// Import submodules
pub const encoder = @import("lut/encoder.zig");
pub const generator = @import("lut/generator.zig");
pub const lookup_table = @import("lut/lookup_table.zig");

// Re-export main types
pub const Encoder = encoder.Encoder;
pub const Generator = generator.Generator;
pub const LookupTable = lookup_table.LookupTable;

// TESTS

test "lut module imports" {
    _ = encoder;
    _ = generator;
    _ = lookup_table;
    _ = Encoder;
    _ = Generator;
    _ = LookupTable;
}
