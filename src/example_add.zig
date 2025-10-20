const std = @import("std");
const tfhe = @import("main.zig");

/// Example: Add two numbers homomorphically
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Homomorphic Addition Example ===", .{});

    // Generate keys
    std.log.info("Generating keys...", .{});
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    var cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    std.log.info("Keys generated successfully", .{});

    // Define the numbers to add
    const a: usize = 5;
    const b: usize = 7;
    const modulus: usize = 16; // 4-bit arithmetic

    std.log.info("Adding {} + {} (mod {})", .{ a, b, modulus });

    // Encrypt the numbers
    std.log.info("Encrypting numbers...", .{});
    const ct_a = try tfhe.utils.Ciphertext.encryptLweMessage(a, modulus, 0.0001, &secret_key.key_lv0, allocator);
    const ct_b = try tfhe.utils.Ciphertext.encryptLweMessage(b, modulus, 0.0001, &secret_key.key_lv0, allocator);

    std.log.info("Numbers encrypted", .{});

    // Perform homomorphic addition
    std.log.info("Performing homomorphic addition...", .{});
    const ct_sum = ct_a.add(&ct_b);

    // Decrypt the result
    std.log.info("Decrypting result...", .{});
    const decrypted_sum = ct_sum.decryptLweMessage(modulus, &secret_key.key_lv0);

    std.log.info("Result: {} + {} = {} (mod {})", .{ a, b, decrypted_sum, modulus });
    std.log.info("Expected: {} (mod {})", .{ (a + b) % modulus, modulus });

    // Verify the result
    if (decrypted_sum == (a + b) % modulus) {
        std.log.info("✓ Addition successful!", .{});
    } else {
        std.log.err("✗ Addition failed!", .{});
    }
}
