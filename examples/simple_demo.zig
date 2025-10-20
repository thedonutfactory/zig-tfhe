const std = @import("std");
const tfhe = @import("../src/main.zig");

/// Simple demo of TFHE operations
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Simple TFHE Demo ===", .{});

    // Generate keys
    std.log.info("Generating keys...", .{});
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    var cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    std.log.info("Keys generated successfully", .{});

    // Encrypt boolean values
    std.log.info("Encrypting boolean values...", .{});
    const ct_true = try tfhe.utils.Ciphertext.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tfhe.utils.Ciphertext.encrypt(false, &secret_key.key_lv0, allocator);

    std.log.info("Boolean values encrypted", .{});

    // Decrypt to verify
    const decrypted_true = ct_true.decrypt(&secret_key.key_lv0);
    const decrypted_false = ct_false.decrypt(&secret_key.key_lv0);

    std.log.info("Decrypted values: true={}, false={}", .{ decrypted_true, decrypted_false });

    // Test homomorphic AND gate
    std.log.info("Testing homomorphic AND gate...", .{});
    var gates_impl = tfhe.gates.Gates.init(allocator, &cloud_key);
    const result = try gates_impl.homAnd(&ct_true, &ct_false, allocator);
    const decrypted_result = result.decrypt(&secret_key.key_lv0);

    std.log.info("Homomorphic AND: true AND false = {}", .{decrypted_result});

    std.log.info("=== Demo Complete ===", .{});
}
