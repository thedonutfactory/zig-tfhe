const std = @import("std");
const params = @import("params.zig");
const tlwe = @import("tlwe.zig");
const utils = @import("utils.zig");
const key = @import("key.zig");
const bootstrap = @import("bootstrap.zig");
const fft = @import("fft.zig");

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
    try std.testing.expect(true);
}

test "homomorphic AND gate - basic cases" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test AND gate: true AND true = true
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const result = try gates_impl.homAnd(&ct_true, &ct_true, allocator);
    const decrypted = result.decrypt(&secret_key.key_lv0);
    try std.testing.expectEqual(true, decrypted);
}

test "homomorphic AND gate - false cases" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test AND gate: true AND false = false
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const result = try gates_impl.homAnd(&ct_true, &ct_false, allocator);
    const decrypted = result.decrypt(&secret_key.key_lv0);
    try std.testing.expectEqual(false, decrypted);
}

test "homomorphic OR gate - basic cases" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test OR gate: true OR false = true
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    const result = try gates_impl.homOr(&ct_true, &ct_false, allocator);
    const decrypted = result.decrypt(&secret_key.key_lv0);
    try std.testing.expectEqual(true, decrypted);
}

test "homomorphic AND gate - all combinations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    // Test all AND combinations
    const result_tt = try gates_impl.homAnd(&ct_true, &ct_true, allocator);
    const result_tf = try gates_impl.homAnd(&ct_true, &ct_false, allocator);
    const result_ft = try gates_impl.homAnd(&ct_false, &ct_true, allocator);
    const result_ff = try gates_impl.homAnd(&ct_false, &ct_false, allocator);

    try std.testing.expectEqual(true, result_tt.decrypt(&secret_key.key_lv0)); // true AND true = true
    try std.testing.expectEqual(false, result_tf.decrypt(&secret_key.key_lv0)); // true AND false = false
    try std.testing.expectEqual(false, result_ft.decrypt(&secret_key.key_lv0)); // false AND true = false
    try std.testing.expectEqual(false, result_ff.decrypt(&secret_key.key_lv0)); // false AND false = false
}

test "homomorphic OR gate - all combinations" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    // Test all OR combinations
    const result_tt = try gates_impl.homOr(&ct_true, &ct_true, allocator);
    const result_tf = try gates_impl.homOr(&ct_true, &ct_false, allocator);
    const result_ft = try gates_impl.homOr(&ct_false, &ct_true, allocator);
    const result_ff = try gates_impl.homOr(&ct_false, &ct_false, allocator);

    try std.testing.expectEqual(true, result_tt.decrypt(&secret_key.key_lv0)); // true OR true = true
    try std.testing.expectEqual(true, result_tf.decrypt(&secret_key.key_lv0)); // true OR false = true
    try std.testing.expectEqual(true, result_ft.decrypt(&secret_key.key_lv0)); // false OR true = true
    try std.testing.expectEqual(false, result_ff.decrypt(&secret_key.key_lv0)); // false OR false = false
}

test "homomorphic XOR gate - basic cases" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tlwe.TLWELv0.encrypt(false, &secret_key.key_lv0, allocator);

    // Test XOR gate: true XOR false = true
    const result = try gates_impl.homXor(&ct_true, &ct_false, allocator);
    const decrypted = result.decrypt(&secret_key.key_lv0);
    try std.testing.expectEqual(true, decrypted);
}

test "homomorphic NOT gate" {
    const allocator = std.testing.allocator;
    var secret_key = try key.SecretKey.init(allocator);
    var cloud_key = try key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    var gates_impl = Gates.init(allocator, &cloud_key);

    // Test NOT gate: NOT true = false
    const ct_true = try tlwe.TLWELv0.encrypt(true, &secret_key.key_lv0, allocator);
    const result = try gates_impl.homNot(&ct_true, allocator);
    const decrypted = result.decrypt(&secret_key.key_lv0);
    try std.testing.expectEqual(false, decrypted);
}
