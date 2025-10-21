const std = @import("std");

// Import the modules we need directly
const params = @import("../src/params.zig");
const utils = @import("../src/utils.zig");
const key = @import("../src/key.zig");
const gates = @import("../src/gates.zig");
const tlwe = @import("../src/tlwe.zig");

/// Full adder implementation using homomorphic gates
fn fullAdder(
    server_key: *const key.CloudKey,
    ct_a: *const utils.Ciphertext,
    ct_b: *const utils.Ciphertext,
    ct_c: *const utils.Ciphertext,
) !struct { utils.Ciphertext, utils.Ciphertext } {
    const gates_impl = gates.Gates.new();

    // a_xor_b = a XOR b
    const a_xor_b = try gates_impl.xor(ct_a, ct_b, server_key);

    // a_and_b = a AND b
    const a_and_b = try gates_impl.andGate(ct_a, ct_b, server_key);

    // a_xor_b_and_c = (a XOR b) AND c
    const a_xor_b_and_c = try gates_impl.andGate(&a_xor_b, ct_c, server_key);

    // sum = (a XOR b) XOR c
    const ct_sum = try gates_impl.xor(&a_xor_b, ct_c, server_key);

    // carry = (a AND b) OR ((a XOR b) AND c)
    const ct_carry = try gates_impl.orGate(&a_and_b, &a_xor_b_and_c, server_key);

    return .{ ct_sum, ct_carry };
}

/// Add two encrypted numbers using ripple carry adder
pub fn add(
    server_key: *const key.CloudKey,
    a: []const utils.Ciphertext,
    b: []const utils.Ciphertext,
    cin: utils.Ciphertext,
    allocator: std.mem.Allocator,
) !struct { []utils.Ciphertext, utils.Ciphertext } {
    if (a.len != b.len) {
        return error.InvalidInput; // Cannot add two numbers with different number of bits!
    }

    var result = try allocator.alloc(utils.Ciphertext, a.len);
    var carry = cin;

    for (a, b, 0..) |ct_a, ct_b, i| {
        const full_adder_result = try fullAdder(server_key, &ct_a, &ct_b, &carry);
        result[i] = full_adder_result[0]; // sum
        carry = full_adder_result[1]; // carry
    }

    return .{ result, carry };
}

/// Encrypt a boolean value
fn encrypt(x: bool, secret_key: *const key.SecretKey) !utils.Ciphertext {
    return try utils.Ciphertext.encryptBool(x, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
}

/// Decrypt a ciphertext to a boolean value
fn decrypt(x: *const utils.Ciphertext, secret_key: *const key.SecretKey) bool {
    return x.decryptBool(&secret_key.key_lv0);
}

/// Convert a number to its bit representation
fn toBits(x: u16) [16]bool {
    var bits: [16]bool = undefined;
    for (0..16) |i| {
        bits[i] = (x & (@as(u16, 1) << @as(u4, @intCast(i)))) != 0;
    }
    return bits;
}

/// Convert bit representation back to a number
fn fromBits(bits: []const bool) u16 {
    var result: u16 = 0;
    for (bits, 0..) |bit, i| {
        if (bit) {
            result |= @as(u16, 1) << @as(u4, @intCast(i));
        }
    }
    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate keys
    const secret_key = key.SecretKey.new();
    const cloud_key = try key.CloudKey.new(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    // Input numbers
    const a: u16 = 402;
    const b: u16 = 304;

    const a_pt = toBits(a);
    const b_pt = toBits(b);

    // Encrypt the inputs
    var c1 = try allocator.alloc(utils.Ciphertext, 16);
    defer allocator.free(c1);

    var c2 = try allocator.alloc(utils.Ciphertext, 16);
    defer allocator.free(c2);

    for (a_pt, 0..) |bit, i| {
        c1[i] = try encrypt(bit, &secret_key);
    }

    for (b_pt, 0..) |bit, i| {
        c2[i] = try encrypt(bit, &secret_key);
    }

    const cin = try encrypt(false, &secret_key);

    const start = std.time.nanoTimestamp();

    // ----------------- SERVER SIDE -----------------
    // Use the server public key to add the a and b ciphertexts
    const add_result = try add(&cloud_key, c1, c2, cin, allocator);
    const c3 = add_result[0];
    const carry_out = add_result[1];
    defer allocator.free(c3);
    // -------------------------------------------------

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;

    // Calculate performance metrics
    const BITS: u16 = 16;
    const ADD_GATES_COUNT: u16 = 5; // Each full adder uses 5 gates
    const NUM_OPS: u16 = 1;
    const try_num = BITS * ADD_GATES_COUNT * NUM_OPS;
    const exec_ms_per_gate = elapsed_ms / @as(f64, @floatFromInt(try_num));

    std.debug.print("per gate: {d:.6} ms\n", .{exec_ms_per_gate});
    std.debug.print("total: {d:.6} ms\n", .{elapsed_ms});

    // Decrypt the results
    var r1: [16]bool = undefined;
    for (c3, 0..) |ct, i| {
        r1[i] = decrypt(&ct, &secret_key);
    }

    const carry_pt = decrypt(&carry_out, &secret_key);
    std.debug.print("Carry: {}\n", .{carry_pt});

    // Convert Boolean arrays to integers and check result
    const a_decrypted = fromBits(&a_pt);
    std.debug.print("A: {}\n", .{a_decrypted});

    const b_decrypted = fromBits(&b_pt);
    std.debug.print("B: {}\n", .{b_decrypted});

    const s = fromBits(&r1);
    std.debug.print("sum: {}\n", .{s});

    // Verify the result
    const expected = a + b;
    std.debug.print("Expected: {}\n", .{expected});
    std.debug.print("Result matches: {}\n", .{s == expected});
}
