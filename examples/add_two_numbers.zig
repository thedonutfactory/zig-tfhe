//! Add Two Numbers Example
//!
//! This example demonstrates how to perform addition on encrypted integers using
//! homomorphic encryption. It implements a full adder circuit that can add two
//! 16-bit numbers without decrypting them.
//!
//! The example shows:
//! - Encrypting two integers (402 + 304)
//! - Building a full adder circuit using homomorphic gates
//! - Performing addition on encrypted data
//! - Decrypting the result and verifying correctness

const std = @import("std");
const tfhe = @import("main");

const params = tfhe.params;
const utils = tfhe.utils;
const gates = tfhe.gates;
const key = tfhe.key;
const bit_utils = tfhe.bit_utils;

/// Full adder implementation using homomorphic gates.
/// Computes sum = (a XOR b) XOR c and carry = (a AND b) OR ((a XOR b) AND c).
fn fullAdder(
    gates_inst: *const gates.Gates,
    cloud_key: *const key.CloudKey,
    ct_a: *const utils.Ciphertext,
    ct_b: *const utils.Ciphertext,
    ct_c: *const utils.Ciphertext,
) !struct { sum: utils.Ciphertext, carry: utils.Ciphertext } {
    // a XOR b
    const a_xor_b = try gates_inst.xor(ct_a, ct_b, cloud_key);

    // a AND b
    const a_and_b = try gates_inst.andGate(ct_a, ct_b, cloud_key);

    // (a XOR b) AND c
    const a_xor_b_and_c = try gates_inst.andGate(&a_xor_b, ct_c, cloud_key);

    // sum = (a XOR b) XOR c
    const ct_sum = try gates_inst.xor(&a_xor_b, ct_c, cloud_key);

    // carry = (a AND b) OR ((a XOR b) AND c)
    const ct_carry = try gates_inst.orGate(&a_and_b, &a_xor_b_and_c, cloud_key);

    return .{ .sum = ct_sum, .carry = ct_carry };
}

/// Add two encrypted numbers represented as bit arrays.
/// Returns the sum and final carry bit.
fn add(
    allocator: std.mem.Allocator,
    gates_inst: *const gates.Gates,
    cloud_key: *const key.CloudKey,
    a: []const utils.Ciphertext,
    b: []const utils.Ciphertext,
    cin: utils.Ciphertext,
) !struct { sum: []utils.Ciphertext, carry: utils.Ciphertext } {
    if (a.len != b.len) {
        return error.MismatchedBitLength;
    }

    var result = try allocator.alloc(utils.Ciphertext, a.len);
    var carry = cin;

    for (0..a.len) |i| {
        const adder_result = try fullAdder(gates_inst, cloud_key, &a[i], &b[i], &carry);
        carry = adder_result.carry;
        result[i] = adder_result.sum;
    }

    return .{ .sum = result, .carry = carry };
}

/// Encrypt a boolean value.
fn encrypt(value: bool, secret_key: *const key.SecretKey) !utils.Ciphertext {
    return try utils.Ciphertext.encryptBool(value, params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
}

/// Decrypt a ciphertext to a boolean value.
fn decrypt(ct: *const utils.Ciphertext, secret_key: *const key.SecretKey) bool {
    return ct.decryptBool(&secret_key.key_lv0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== TFHE Add Two Numbers Example ===\n\n", .{});

    // Generate keys
    std.debug.print("Generating keys (this may take a moment)...\n", .{});
    const secret_key = key.SecretKey.new();
    var cloud_key = try key.CloudKey.new(allocator, &secret_key);
    defer cloud_key.deinit(allocator);
    std.debug.print("Keys generated successfully!\n\n", .{});

    // Create gates instance
    const gates_inst = gates.Gates.new();

    // Input values
    const a: u16 = 402;
    const b: u16 = 304;
    const expected_sum: u16 = a + b; // 706

    std.debug.print("Plaintext inputs:\n", .{});
    std.debug.print("  A = {}\n", .{a});
    std.debug.print("  B = {}\n", .{b});
    std.debug.print("  Expected sum = {}\n\n", .{expected_sum});

    // Convert to bits (little-endian)
    const a_bits = try bit_utils.U16AsBits.toBits(a, allocator);
    defer allocator.free(a_bits);
    const b_bits = try bit_utils.U16AsBits.toBits(b, allocator);
    defer allocator.free(b_bits);

    std.debug.print("Encrypting inputs...\n", .{});

    // Encrypt bit arrays
    var c1 = try allocator.alloc(utils.Ciphertext, a_bits.len);
    defer allocator.free(c1);
    for (a_bits, 0..) |bit, i| {
        c1[i] = try encrypt(bit, &secret_key);
    }

    var c2 = try allocator.alloc(utils.Ciphertext, b_bits.len);
    defer allocator.free(c2);
    for (b_bits, 0..) |bit, i| {
        c2[i] = try encrypt(bit, &secret_key);
    }

    // Carry in = 0
    const cin = try encrypt(false, &secret_key);

    std.debug.print("Inputs encrypted successfully!\n\n", .{});

    // Perform homomorphic addition
    std.debug.print("Computing encrypted addition (this will take a while)...\n", .{});
    const start_time = std.time.milliTimestamp();

    const add_result = try add(allocator, &gates_inst, &cloud_key, c1, c2, cin);
    defer allocator.free(add_result.sum);

    const end_time = std.time.milliTimestamp();
    const elapsed_ms = end_time - start_time;

    // Calculate gate statistics
    const bits: u16 = 16;
    const add_gates_count: u16 = 5; // Each full adder uses 5 gates
    const total_gates = bits * add_gates_count;
    const ms_per_gate = @as(f64, @floatFromInt(elapsed_ms)) / @as(f64, @floatFromInt(total_gates));

    std.debug.print("Computation complete!\n", .{});
    std.debug.print("  Total time: {} ms\n", .{elapsed_ms});
    std.debug.print("  Per gate: {d:.2} ms\n", .{ms_per_gate});
    std.debug.print("  Total gates: {}\n\n", .{total_gates});

    // Decrypt result
    std.debug.print("Decrypting result...\n", .{});

    var result_bits = try allocator.alloc(bool, add_result.sum.len);
    defer allocator.free(result_bits);
    for (add_result.sum, 0..) |ct, i| {
        result_bits[i] = decrypt(&ct, &secret_key);
    }

    // Decrypt carry
    const carry_bit = decrypt(&add_result.carry, &secret_key);

    // Convert bits back to integer
    const computed_sum = bit_utils.convert(u16, result_bits);

    std.debug.print("\nResults:\n", .{});
    std.debug.print("  Computed sum = {}\n", .{computed_sum});
    std.debug.print("  Carry out = {}\n", .{carry_bit});
    std.debug.print("  Expected sum = {}\n", .{expected_sum});

    // Verify correctness
    if (computed_sum == expected_sum) {
        std.debug.print("\n✓ Success! Homomorphic addition computed correctly.\n", .{});
    } else {
        std.debug.print("\n✗ Error! Result mismatch.\n", .{});
        return error.IncorrectResult;
    }
}
