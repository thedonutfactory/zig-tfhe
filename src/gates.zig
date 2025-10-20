const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");
const utils = @import("utils.zig");
const key = @import("key.zig");
const bootstrap = @import("bootstrap.zig");

/// Homomorphic gates implementation
pub const Gates = struct {
    cloud_key: *const key.CloudKey,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize gates with cloud key
    pub fn init(allocator: std.mem.Allocator, cloud_key: *const key.CloudKey) Self {
        return Self{
            .cloud_key = cloud_key,
            .allocator = allocator,
        };
    }

    /// Homomorphic AND gate
    pub fn homAnd(self: *Self, a: *const tlwe.TLWELv0, b: *const tlwe.TLWELv0, allocator: std.mem.Allocator) !tlwe.TLWELv0 {

        // AND gate: a + b - 0.125 (like Rust implementation)
        var result = a.add(b);
        const offset = utils.f64ToTorus(-0.125);
        result.bMut().* = result.b() +% offset;

        // Apply bootstrapping for noise management
        return try bootstrap.vanilla.bootstrap(&result, self.cloud_key, allocator);
    }

    /// Homomorphic OR gate
    pub fn homOr(self: *Self, a: *const tlwe.TLWELv0, b: *const tlwe.TLWELv0, allocator: std.mem.Allocator) !tlwe.TLWELv0 {
        // OR gate: a + b + 0.125 (like Rust implementation)
        var result = a.add(b);
        const offset = utils.f64ToTorus(0.125);
        result.bMut().* = result.b() +% offset;

        // Apply bootstrapping for noise management
        return try bootstrap.vanilla.bootstrap(&result, self.cloud_key, allocator);
    }

    /// Homomorphic XOR gate
    pub fn homXor(self: *Self, a: *const tlwe.TLWELv0, b: *const tlwe.TLWELv0, allocator: std.mem.Allocator) !tlwe.TLWELv0 {
        // XOR gate: a + 2*b + 0.25 (like Rust implementation)
        // First, compute 2*b by adding b to itself
        const b_doubled = b.add(b);
        var result = a.add(&b_doubled);
        const offset = utils.f64ToTorus(0.25);
        result.bMut().* = result.b() +% offset;

        // Apply bootstrapping for noise management
        return try bootstrap.vanilla.bootstrap(&result, self.cloud_key, allocator);
    }

    /// Homomorphic NOT gate
    pub fn homNot(self: *Self, a: *const tlwe.TLWELv0, _: std.mem.Allocator) !tlwe.TLWELv0 {
        _ = self;

        // NOT gate: -a (like Rust implementation)
        // No bootstrapping needed for NOT gate
        return a.neg();
    }

    /// Homomorphic MUX (multiplexer) gate
    /// MUX(a, b, c) = (a AND b) OR (NOT a AND c)
    pub fn mux(self: *Self, a: *const tlwe.TLWELv0, b: *const tlwe.TLWELv0, c: *const tlwe.TLWELv0, allocator: std.mem.Allocator) !tlwe.TLWELv0 {
        // Implement MUX gate exactly like the Rust version:
        // 1. and(a, b): tlwe_and = a + b, then tlwe_and.b += -0.125, then bootstrap_without_key_switch
        // 2. and(not(a), c): tlwe_and_ny = not(a) + c, then tlwe_and_ny.b += -0.125, then bootstrap_without_key_switch
        // 3. or(u1, u2): tlwe_or = u1 + u2, then tlwe_or.b += 0.125, then bootstrap

        // Step 1: and(a, b)
        var tlwe_and = a.add(b);
        tlwe_and.bMut().* = tlwe_and.b() +% utils.f64ToTorus(-0.125);
        const and_bootstrapped = try bootstrap.vanilla.bootstrapWithoutKeySwitch(&tlwe_and, self.cloud_key, allocator);

        // Step 2: and(not(a), c)
        const not_a = a.neg();
        var tlwe_and_ny = not_a.add(c);
        tlwe_and_ny.bMut().* = tlwe_and_ny.b() +% utils.f64ToTorus(-0.125);
        const not_and_bootstrapped = try bootstrap.vanilla.bootstrapWithoutKeySwitch(&tlwe_and_ny, self.cloud_key, allocator);

        // Step 3: or(u1, u2)
        var tlwe_or = and_bootstrapped.add(&not_and_bootstrapped);
        tlwe_or.bMut().* = tlwe_or.b() +% utils.f64ToTorus(0.125);
        return try bootstrap.vanilla.bootstrap(&tlwe_or, self.cloud_key, allocator);
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "gates initialization" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    _ = Gates.init(allocator, &cloud_key);

    // Basic initialization test
    try std.testing.expect(true);
}

test "homomorphic AND gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test all combinations of AND gate
    const test_cases = [_]struct { a: bool, b: bool, expected: bool }{
        .{ .a = true, .b = true, .expected = true },
        .{ .a = true, .b = false, .expected = false },
        .{ .a = false, .b = true, .expected = false },
        .{ .a = false, .b = false, .expected = false },
    };

    for (test_cases) |case| {
        const ct_a = try tlwe.TLWELv0.encrypt(case.a, &secret_key.key_lv0, allocator);
        const ct_b = try tlwe.TLWELv0.encrypt(case.b, &secret_key.key_lv0, allocator);

        const result = try gates_impl.homAnd(&ct_a, &ct_b, allocator);
        const decrypted = result.decrypt(&secret_key.key_lv0);

        try std.testing.expectEqual(case.expected, decrypted);
    }
}

test "homomorphic OR gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test all combinations of OR gate
    const test_cases = [_]struct { a: bool, b: bool, expected: bool }{
        .{ .a = true, .b = true, .expected = true },
        .{ .a = true, .b = false, .expected = true },
        .{ .a = false, .b = true, .expected = true },
        .{ .a = false, .b = false, .expected = false },
    };

    for (test_cases) |case| {
        const ct_a = try tlwe.TLWELv0.encrypt(case.a, &secret_key.key_lv0, allocator);
        const ct_b = try tlwe.TLWELv0.encrypt(case.b, &secret_key.key_lv0, allocator);

        const result = try gates_impl.homOr(&ct_a, &ct_b, allocator);
        const decrypted = result.decrypt(&secret_key.key_lv0);

        try std.testing.expectEqual(case.expected, decrypted);
    }
}

test "homomorphic XOR gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test all combinations of XOR gate
    const test_cases = [_]struct { a: bool, b: bool, expected: bool }{
        .{ .a = true, .b = true, .expected = false },
        .{ .a = true, .b = false, .expected = true },
        .{ .a = false, .b = true, .expected = true },
        .{ .a = false, .b = false, .expected = false },
    };

    for (test_cases) |case| {
        const ct_a = try tlwe.TLWELv0.encrypt(case.a, &secret_key.key_lv0, allocator);
        const ct_b = try tlwe.TLWELv0.encrypt(case.b, &secret_key.key_lv0, allocator);

        const result = try gates_impl.homXor(&ct_a, &ct_b, allocator);
        const decrypted = result.decrypt(&secret_key.key_lv0);

        try std.testing.expectEqual(case.expected, decrypted);
    }
}

test "homomorphic NOT gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test NOT gate
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const not_true = try gates_impl.homNot(&ct_true, allocator);
    const not_false = try gates_impl.homNot(&ct_false, allocator);

    const decrypted_not_true = not_true.decrypt(&secret_key.key_lv0);
    const decrypted_not_false = not_false.decrypt(&secret_key.key_lv0);

    try std.testing.expectEqual(false, decrypted_not_true);
    try std.testing.expectEqual(true, decrypted_not_false);
}

test "homomorphic MUX gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test MUX gate: MUX(a, b, c) = (a AND b) OR (NOT a AND c)
    const test_cases = [_]struct { a: bool, b: bool, c: bool, expected: bool }{
        .{ .a = true, .b = true, .c = false, .expected = true }, // MUX(true, true, false) = true
        .{ .a = true, .b = false, .c = true, .expected = false }, // MUX(true, false, true) = false
        .{ .a = false, .b = true, .c = false, .expected = false }, // MUX(false, true, false) = false
        .{ .a = false, .b = false, .c = true, .expected = true }, // MUX(false, false, true) = true
    };

    for (test_cases) |case| {
        const ct_a = try tlwe.TLWELv0.encrypt(case.a, &secret_key.key_lv0, allocator);
        const ct_b = try tlwe.TLWELv0.encrypt(case.b, &secret_key.key_lv0, allocator);
        const ct_c = try tlwe.TLWELv0.encrypt(case.c, &secret_key.key_lv0, allocator);

        const result = try gates_impl.mux(&ct_a, &ct_b, &ct_c, allocator);
        const decrypted = result.decrypt(&secret_key.key_lv0);

        try std.testing.expectEqual(case.expected, decrypted);
    }
}

test "gates truth table verification" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test comprehensive truth table for all gates
    const inputs = [_]bool{ true, false };

    for (inputs) |a| {
        for (inputs) |b| {
            const ct_a = try tlwe.TLWELv0.encrypt(a, &secret_key.key_lv0, allocator);
            const ct_b = try tlwe.TLWELv0.encrypt(b, &secret_key.key_lv0, allocator);

            // Test AND
            const and_result = try gates_impl.homAnd(&ct_a, &ct_b, allocator);
            const and_decrypted = and_result.decrypt(&secret_key.key_lv0);
            try std.testing.expectEqual(a and b, and_decrypted);

            // Test OR
            const or_result = try gates_impl.homOr(&ct_a, &ct_b, allocator);
            const or_decrypted = or_result.decrypt(&secret_key.key_lv0);
            try std.testing.expectEqual(a or b, or_decrypted);

            // Test XOR
            const xor_result = try gates_impl.homXor(&ct_a, &ct_b, allocator);
            const xor_decrypted = xor_result.decrypt(&secret_key.key_lv0);
            try std.testing.expectEqual(a != b, xor_decrypted);
        }
    }
}

test "gates noise management" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test that gates work correctly even with multiple operations
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    // Chain multiple operations to test noise management
    const result1 = try gates_impl.homAnd(&ct_true, &ct_false, allocator);
    const result2 = try gates_impl.homOr(&result1, &ct_true, allocator);
    const result3 = try gates_impl.homXor(&result2, &ct_false, allocator);

    const final_result = result3.decrypt(&secret_key.key_lv0);

    // Expected: ((true AND false) OR true) XOR false = (false OR true) XOR false = true XOR false = true
    try std.testing.expectEqual(true, final_result);
}

test "chained AND operations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test chained AND operations: true AND true AND false = false
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const result1 = try gates_impl.homAnd(&ct_true, &ct_true, allocator);
    const result2 = try gates_impl.homAnd(&result1, &ct_false, allocator);

    const final_result = result2.decrypt(&secret_key.key_lv0);

    // Expected: (true AND true) AND false = true AND false = false
    try std.testing.expectEqual(false, final_result);
}

test "chained OR operations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test chained OR operations: false OR false OR true = true
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const result1 = try gates_impl.homOr(&ct_false, &ct_false, allocator);
    const result2 = try gates_impl.homOr(&result1, &ct_true, allocator);

    const final_result = result2.decrypt(&secret_key.key_lv0);

    // Expected: (false OR false) OR true = false OR true = true
    try std.testing.expectEqual(true, final_result);
}

test "chained XOR operations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test chained XOR operations: true XOR false XOR true = false
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const result1 = try gates_impl.homXor(&ct_true, &ct_false, allocator);
    const result2 = try gates_impl.homXor(&result1, &ct_true, allocator);

    const final_result = result2.decrypt(&secret_key.key_lv0);

    // Expected: (true XOR false) XOR true = true XOR true = false
    try std.testing.expectEqual(false, final_result);
}

test "mixed chained operations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test mixed chained operations: (true AND false) OR (true XOR false) = false OR true = true
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const and_result = try gates_impl.homAnd(&ct_true, &ct_false, allocator);
    const xor_result = try gates_impl.homXor(&ct_true, &ct_false, allocator);
    const or_result = try gates_impl.homOr(&and_result, &xor_result, allocator);

    const final_result = or_result.decrypt(&secret_key.key_lv0);

    // Expected: (true AND false) OR (true XOR false) = false OR true = true
    try std.testing.expectEqual(true, final_result);
}
