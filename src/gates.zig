//! Homomorphic Logic Gates Implementation
//!
//! This module provides homomorphic gate operations (AND, OR, NAND, etc.) that
//! use bootstrapping for noise management. The gates enable building complex
//! homomorphic circuits for computation on encrypted data.

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");
const key = @import("key.zig");
const trgsw = @import("trgsw.zig");
const trlwe = @import("trlwe.zig");
const fft = @import("fft.zig");
const bootstrap = @import("bootstrap.zig");

// ============================================================================
// BOOTSTRAP INTEGRATION
// ============================================================================

// Use the real bootstrap implementation
pub const VanillaBootstrap = bootstrap.vanilla.VanillaBootstrap;

// ============================================================================
// GATES STRUCT
// ============================================================================

/// Gates struct that uses a configurable bootstrap strategy
///
/// This struct provides homomorphic gate operations (AND, OR, NAND, etc.) that
/// use a bootstrap strategy for noise management. The bootstrap strategy can be
/// configured at construction time, enabling experimentation with different
/// optimization approaches.
pub const Gates = struct {
    bootstrap: VanillaBootstrap,

    const Self = @This();

    /// Create a new Gates instance with the default bootstrap strategy
    pub fn new() Self {
        return Gates{
            .bootstrap = VanillaBootstrap.new(),
        };
    }

    /// Create a Gates instance with a specific bootstrap strategy
    pub fn withBootstrap(bootstrap_strategy: VanillaBootstrap) Self {
        return Gates{ .bootstrap = bootstrap_strategy };
    }

    /// Get the name of the bootstrap strategy being used
    pub fn bootstrapStrategy(self: *const Self) []const u8 {
        return self.bootstrap.name();
    }

    /// Homomorphic NAND gate
    pub fn nand(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_nand = tlwe_a.neg().add(tlwe_b.neg());
        tlwe_nand.bMut().* = tlwe_nand.b() +% utils.f64ToTorus(0.125);
        return self.bootstrap.bootstrap(&tlwe_nand, cloud_key);
    }

    /// Homomorphic OR gate
    pub fn orGate(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_or = tlwe_a.add(tlwe_b);
        tlwe_or.bMut().* = tlwe_or.b() +% utils.f64ToTorus(0.125);
        return self.bootstrap.bootstrap(&tlwe_or, cloud_key);
    }

    /// Homomorphic AND gate
    pub fn andGate(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_and = tlwe_a.add(tlwe_b);
        tlwe_and.bMut().* = tlwe_and.b() +% utils.f64ToTorus(-0.125);
        return self.bootstrap.bootstrap(&tlwe_and, cloud_key);
    }

    /// Homomorphic XOR gate
    pub fn xor(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_xor = tlwe_a.addMul(tlwe_b, 2);
        tlwe_xor.bMut().* = tlwe_xor.b() +% utils.f64ToTorus(0.25);
        return self.bootstrap.bootstrap(&tlwe_xor, cloud_key);
    }

    /// Homomorphic XNOR gate
    pub fn xnor(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_xnor = tlwe_a.subMul(tlwe_b, 2);
        tlwe_xnor.bMut().* = tlwe_xnor.b() +% utils.f64ToTorus(-0.25);
        return self.bootstrap.bootstrap(&tlwe_xnor, cloud_key);
    }

    /// Homomorphic NOR gate
    pub fn nor(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_nor = tlwe_a.neg().add(tlwe_b.neg());
        tlwe_nor.bMut().* = tlwe_nor.b() +% utils.f64ToTorus(-0.125);
        return self.bootstrap.bootstrap(&tlwe_nor, cloud_key);
    }

    /// Homomorphic AND-NOT-Y gate (a AND NOT b)
    pub fn andNy(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_and_ny = tlwe_a.neg().add(tlwe_b);
        tlwe_and_ny.bMut().* = tlwe_and_ny.b() +% utils.f64ToTorus(-0.125);
        return self.bootstrap.bootstrap(&tlwe_and_ny, cloud_key);
    }

    /// Homomorphic AND-Y-NOT gate (a AND NOT b)
    pub fn andYn(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_and_yn = tlwe_a.sub(tlwe_b);
        tlwe_and_yn.bMut().* = tlwe_and_yn.b() +% utils.f64ToTorus(-0.125);
        return self.bootstrap.bootstrap(&tlwe_and_yn, cloud_key);
    }

    /// Homomorphic OR-NOT-Y gate (NOT a OR b)
    pub fn orNy(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_or_ny = tlwe_a.neg().add(tlwe_b);
        tlwe_or_ny.bMut().* = tlwe_or_ny.b() +% utils.f64ToTorus(0.125);
        return self.bootstrap.bootstrap(&tlwe_or_ny, cloud_key);
    }

    /// Homomorphic OR-Y-NOT gate (a OR NOT b)
    pub fn orYn(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        var tlwe_or_yn = tlwe_a.sub(tlwe_b);
        tlwe_or_yn.bMut().* = tlwe_or_yn.b() +% utils.f64ToTorus(0.125);
        return self.bootstrap.bootstrap(&tlwe_or_yn, cloud_key);
    }

    /// Homomorphic MUX gate (a ? b : c) - naive version
    pub fn muxNaive(self: *const Self, tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, tlwe_c: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
        const a_and_b = try self.andGate(tlwe_a, tlwe_b, cloud_key);
        const not_a = self.not(tlwe_a);
        const nand_a_c = try self.andGate(&not_a, tlwe_c, cloud_key);
        return self.orGate(&a_and_b, &nand_a_c, cloud_key);
    }

    /// Homomorphic NOT gate (no bootstrapping needed)
    pub fn not(self: *const Self, tlwe_a: *const utils.Ciphertext) utils.Ciphertext {
        _ = self;
        return tlwe_a.neg();
    }

    /// Copy a ciphertext (no bootstrapping needed)
    pub fn copy(self: *const Self, tlwe_a: *const utils.Ciphertext) utils.Ciphertext {
        _ = self;
        return tlwe_a.*;
    }

    /// Create a constant encrypted value (no bootstrapping needed)
    pub fn constant(self: *const Self, value: bool) utils.Ciphertext {
        _ = self;
        var mu: params.Torus = utils.f64ToTorus(0.125);
        mu = if (value) mu else (1 -% mu);
        var res = utils.Ciphertext.new();
        res.bMut().* = mu;
        return res;
    }
};

// ============================================================================
// CONVENIENCE FREE FUNCTIONS
// ============================================================================

/// Convenience function for NAND gate using default bootstrap
pub fn nand(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.nand(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for OR gate using default bootstrap
pub fn orGate(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.orGate(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for AND gate using default bootstrap
pub fn andGate(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.andGate(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for XOR gate using default bootstrap
pub fn xor(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.xor(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for XNOR gate using default bootstrap
pub fn xnor(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.xnor(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for NOR gate using default bootstrap
pub fn nor(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.nor(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for AND_NY gate using default bootstrap
pub fn andNy(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.andNy(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for AND_YN gate using default bootstrap
pub fn andYn(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.andYn(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for OR_NY gate using default bootstrap
pub fn orNy(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.orNy(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for OR_YN gate using default bootstrap
pub fn orYn(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.orYn(tlwe_a, tlwe_b, cloud_key);
}

/// Convenience function for naive MUX gate using default bootstrap
pub fn muxNaive(tlwe_a: *const utils.Ciphertext, tlwe_b: *const utils.Ciphertext, tlwe_c: *const utils.Ciphertext, cloud_key: *const key.CloudKey) !utils.Ciphertext {
    const gates = Gates.new();
    return gates.muxNaive(tlwe_a, tlwe_b, tlwe_c, cloud_key);
}

/// Convenience function for NOT gate
pub fn not(tlwe_a: *const utils.Ciphertext) utils.Ciphertext {
    const gates = Gates.new();
    return gates.not(tlwe_a);
}

/// Convenience function for COPY
pub fn copy(tlwe_a: *const utils.Ciphertext) utils.Ciphertext {
    const gates = Gates.new();
    return gates.copy(tlwe_a);
}

/// Convenience function for CONSTANT
pub fn constant(value: bool) utils.Ciphertext {
    const gates = Gates.new();
    return gates.constant(value);
}

// ============================================================================
// BATCH GATE OPERATIONS (PLACEHOLDER)
// ============================================================================

/// Batch NAND operation - placeholder implementation
/// Will be implemented when parallel module is available
pub fn batchNand(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

/// Batch AND operation - placeholder implementation
pub fn batchAnd(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

/// Batch OR operation - placeholder implementation
pub fn batchOr(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

/// Batch XOR operation - placeholder implementation
pub fn batchXor(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

/// Batch NOR operation - placeholder implementation
pub fn batchNor(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

/// Batch XNOR operation - placeholder implementation
pub fn batchXnor(inputs: []const struct { utils.Ciphertext, utils.Ciphertext }, cloud_key: *const key.CloudKey) ![]utils.Ciphertext {
    _ = inputs;
    _ = cloud_key;

    // Placeholder - will be implemented with parallel processing
    return error.NotImplemented;
}

// ============================================================================
// TESTS
// ============================================================================

test "gates basic operations" {
    const secret_key = key.SecretKey.new();
    _ = try key.CloudKey.new(std.heap.page_allocator, &secret_key); // Suppress unused warning

    const gates = Gates.new();

    // Test constant gate
    const ct_true = gates.constant(true);
    const ct_false = gates.constant(false);

    try std.testing.expect(ct_true.decryptBool(&secret_key.key_lv0) == true);
    try std.testing.expect(ct_false.decryptBool(&secret_key.key_lv0) == false);

    // Test NOT gate
    const not_true = gates.not(&ct_true);
    const not_false = gates.not(&ct_false);

    try std.testing.expect(not_true.decryptBool(&secret_key.key_lv0) == false);
    try std.testing.expect(not_false.decryptBool(&secret_key.key_lv0) == true);

    // Test COPY gate
    const copy_true = gates.copy(&ct_true);
    const copy_false = gates.copy(&ct_false);

    try std.testing.expect(copy_true.decryptBool(&secret_key.key_lv0) == true);
    try std.testing.expect(copy_false.decryptBool(&secret_key.key_lv0) == false);
}

test "gates convenience functions" {
    const secret_key = key.SecretKey.new();
    _ = try key.CloudKey.new(std.heap.page_allocator, &secret_key); // Suppress unused warning

    // Test convenience functions
    const ct_true = constant(true);
    const ct_false = constant(false);

    try std.testing.expect(ct_true.decryptBool(&secret_key.key_lv0) == true);
    try std.testing.expect(ct_false.decryptBool(&secret_key.key_lv0) == false);

    const not_true = not(&ct_true);
    const not_false = not(&ct_false);

    try std.testing.expect(not_true.decryptBool(&secret_key.key_lv0) == false);
    try std.testing.expect(not_false.decryptBool(&secret_key.key_lv0) == true);
}

test "gates bootstrap strategy" {
    const gates = Gates.new();
    try std.testing.expectEqualStrings("vanilla", gates.bootstrapStrategy());

    const custom_bootstrap = VanillaBootstrap.new();
    const custom_gates = Gates.withBootstrap(custom_bootstrap);
    try std.testing.expectEqualStrings("vanilla", custom_gates.bootstrapStrategy());
}

test "gates all and cases" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    const gates = Gates.new();

    const test_cases = [_]struct { bool, bool, bool }{
        .{ true, true, true },
        .{ true, false, false },
        .{ false, true, false },
        .{ false, false, false },
    };

    for (test_cases) |case| {
        const a = case[0];
        const b = case[1];
        const expected = case[2];

        // Clear FFT plan before each test case to ensure clean state
        //const fft_mod = @import("fft.zig");
        //fft_mod.cleanupFFTPlan();

        const ct_a = try utils.Ciphertext.encryptBool(a, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
        const ct_b = try utils.Ciphertext.encryptBool(b, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);

        const result = try gates.andGate(&ct_a, &ct_b, &cloud_key);
        const decrypted = result.decryptBool(&secret_key.key_lv0);

        std.debug.print("{} AND {} = {} (expected: {})\n", .{ a, b, decrypted, expected });
        try std.testing.expect(decrypted == expected);
    }
}

test "gates all OR cases" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    const gates = Gates.new();

    const test_cases = [_]struct { bool, bool, bool }{
        .{ true, true, true },
    };

    for (test_cases) |case| {
        const a = case[0];
        const b = case[1];
        const expected = case[2];

        const ct_a = try utils.Ciphertext.encryptBool(a, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
        const ct_b = try utils.Ciphertext.encryptBool(b, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);

        const result = try gates.orGate(&ct_a, &ct_b, &cloud_key);
        const decrypted = result.decryptBool(&secret_key.key_lv0);

        std.debug.print("{} OR {} = {} (expected: {})\n", .{ a, b, decrypted, expected });
        try std.testing.expectEqual(expected, decrypted);
    }
}

test "gates mux naive" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    const gates = Gates.new();

    const test_cases = [_]struct { bool, bool, bool, bool }{
        .{ true, true, false, true }, // a=true, b=true, c=false -> (a&b)|(!a&c) = true|false = true
        .{ true, false, true, false }, // a=true, b=false, c=true -> (a&b)|(!a&c) = false|false = false
        .{ false, true, false, false }, // a=false, b=true, c=false -> (a&b)|(!a&c) = false|true = true
        .{ false, false, true, true }, // a=false, b=false, c=true -> (a&b)|(!a&c) = false|true = true
    };

    for (test_cases) |case| {
        const a = case[0];
        const b = case[1];
        const c = case[2];
        const expected = case[3];

        // Clear FFT plan before each test case to ensure clean state
        const fft_mod = @import("fft.zig");
        fft_mod.cleanupFFTPlan();

        const ct_a = try utils.Ciphertext.encryptBool(a, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
        const ct_b = try utils.Ciphertext.encryptBool(b, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
        const ct_c = try utils.Ciphertext.encryptBool(c, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);

        const result = try gates.muxNaive(&ct_a, &ct_b, &ct_c, &cloud_key);
        const decrypted = result.decryptBool(&secret_key.key_lv0);

        std.debug.print("MUX({}, {}, {}) = {} (expected: {})\n", .{ a, b, c, decrypted, expected });
        try std.testing.expectEqual(expected, decrypted);
    }
}

test "gates batch operations placeholder" {
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(std.heap.page_allocator, &secret_key);
    // Note: cloud_key is const, so we don't deinit it in tests

    const inputs = [_]struct { utils.Ciphertext, utils.Ciphertext }{
        .{ constant(true), constant(false) },
        .{ constant(false), constant(true) },
    };

    // Test that batch operations return NotImplemented error (as expected)
    try std.testing.expectError(error.NotImplemented, batchNand(&inputs, &cloud_key));
    try std.testing.expectError(error.NotImplemented, batchAnd(&inputs, &cloud_key));
    try std.testing.expectError(error.NotImplemented, batchOr(&inputs, &cloud_key));
    try std.testing.expectError(error.NotImplemented, batchXor(&inputs, &cloud_key));
    try std.testing.expectError(error.NotImplemented, batchNor(&inputs, &cloud_key));
    try std.testing.expectError(error.NotImplemented, batchXnor(&inputs, &cloud_key));
}
