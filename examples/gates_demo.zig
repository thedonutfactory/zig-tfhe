const std = @import("std");
const tfhe = @import("../src/main.zig");

/// Example: Demonstrate homomorphic boolean gates
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Homomorphic Gates Demo ===", .{});

    // Generate keys
    std.log.info("Generating keys...", .{});
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    const cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit();

    std.log.info("Keys generated successfully", .{});

    // Encrypt boolean values
    std.log.info("Encrypting boolean values...", .{});
    const ct_true = try tfhe.utils.Ciphertext.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tfhe.utils.Ciphertext.encrypt(false, &secret_key.key_lv0, allocator);

    std.log.info("Boolean values encrypted", .{});

    // Initialize gates
    var gates = tfhe.gates.Gates.init(allocator, &cloud_key);

    // Test homomorphic AND gate
    std.log.info("Testing AND gate...", .{});
    const and_result = try gates.homAnd(&ct_true, &ct_false, allocator);
    const and_decrypted = and_result.decrypt(&secret_key.key_lv0);
    std.log.info("true AND false = {}", .{and_decrypted});
    std.log.info("Expected: false", .{});

    // Test homomorphic OR gate
    std.log.info("Testing OR gate...", .{});
    const or_result = try gates.homOr(&ct_true, &ct_false, allocator);
    const or_decrypted = or_result.decrypt(&secret_key.key_lv0);
    std.log.info("true OR false = {}", .{or_decrypted});
    std.log.info("Expected: true", .{});

    // Test homomorphic XOR gate
    std.log.info("Testing XOR gate...", .{});
    const xor_result = try gates.homXor(&ct_true, &ct_false, allocator);
    const xor_decrypted = xor_result.decrypt(&secret_key.key_lv0);
    std.log.info("true XOR false = {}", .{xor_decrypted});
    std.log.info("Expected: true", .{});

    // Test homomorphic NOT gate
    std.log.info("Testing NOT gate...", .{});
    const not_result = try gates.homNot(&ct_true, allocator);
    const not_decrypted = not_result.decrypt(&secret_key.key_lv0);
    std.log.info("NOT true = {}", .{not_decrypted});
    std.log.info("Expected: false", .{});

    // Test homomorphic MUX gate
    std.log.info("Testing MUX gate...", .{});
    const mux_result = try gates.mux(&ct_true, &ct_true, &ct_false, allocator);
    const mux_decrypted = mux_result.decrypt(&secret_key.key_lv0);
    std.log.info("MUX(true, true, false) = {}", .{mux_decrypted});
    std.log.info("Expected: true", .{});

    std.log.info("=== Gates Demo Complete ===", .{});
}
