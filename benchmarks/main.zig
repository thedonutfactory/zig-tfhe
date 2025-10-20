const std = @import("std");
const tfhe = @import("../src/main.zig");

/// Benchmark suite for zig-tfhe
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== zig-tfhe Benchmarks ===", .{});

    // Benchmark key generation
    benchmarkKeyGeneration(allocator) catch |err| {
        std.log.err("Key generation benchmark failed: {}", .{err});
    };

    // Benchmark encryption/decryption
    benchmarkEncryptionDecryption(allocator) catch |err| {
        std.log.err("Encryption/decryption benchmark failed: {}", .{err});
    };

    // Benchmark homomorphic operations
    benchmarkHomomorphicOperations(allocator) catch |err| {
        std.log.err("Homomorphic operations benchmark failed: {}", .{err});
    };

    std.log.info("=== Benchmarks Complete ===", .{});
}

/// Benchmark key generation performance
fn benchmarkKeyGeneration(allocator: std.mem.Allocator) !void {
    std.log.info("--- Key Generation Benchmark ---", .{});
    
    const iterations = 10;
    var total_time: u64 = 0;
    
    for (0..iterations) |_| {
        const start_time = std.time.nanoTimestamp();
        
        const secret_key = try tfhe.key.SecretKey.init(allocator);
        var cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
        defer cloud_key.deinit();
        
        const end_time = std.time.nanoTimestamp();
        total_time += end_time - start_time;
    }
    
    const avg_time_ms = (total_time / iterations) / 1_000_000;
    std.log.info("Average key generation time: {} ms", .{avg_time_ms});
}

/// Benchmark encryption and decryption performance
fn benchmarkEncryptionDecryption(allocator: std.mem.Allocator) !void {
    std.log.info("--- Encryption/Decryption Benchmark ---", .{});
    
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    const cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit();
    
    const iterations = 100;
    var total_encrypt_time: u64 = 0;
    var total_decrypt_time: u64 = 0;
    
    for (0..iterations) |i| {
        const plaintext = (i % 2) == 0;
        
        // Benchmark encryption
        const encrypt_start = std.time.nanoTimestamp();
        const ciphertext = try tfhe.utils.Ciphertext.encrypt(plaintext, &secret_key.key_lv0, allocator);
        const encrypt_end = std.time.nanoTimestamp();
        total_encrypt_time += encrypt_end - encrypt_start;
        
        // Benchmark decryption
        const decrypt_start = std.time.nanoTimestamp();
        const decrypted = ciphertext.decrypt(&secret_key.key_lv0);
        const decrypt_end = std.time.nanoTimestamp();
        total_decrypt_time += decrypt_end - decrypt_start;
        
        // Verify correctness
        if (decrypted != plaintext) {
            std.log.err("Encryption/decryption failed for iteration {}", .{i});
            return;
        }
    }
    
    const avg_encrypt_time_us = (total_encrypt_time / iterations) / 1_000;
    const avg_decrypt_time_us = (total_decrypt_time / iterations) / 1_000;
    
    std.log.info("Average encryption time: {} μs", .{avg_encrypt_time_us});
    std.log.info("Average decryption time: {} μs", .{avg_decrypt_time_us});
}

/// Benchmark homomorphic operations performance
fn benchmarkHomomorphicOperations(allocator: std.mem.Allocator) !void {
    std.log.info("--- Homomorphic Operations Benchmark ---", .{});
    
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    const cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    defer cloud_key.deinit();
    
    // Encrypt test values
    const ct_true = try tfhe.utils.Ciphertext.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tfhe.utils.Ciphertext.encrypt(false, &secret_key.key_lv0, allocator);
    
    var gates = tfhe.gates.Gates.init(allocator, &cloud_key);
    
    const iterations = 50;
    var total_and_time: u64 = 0;
    var total_or_time: u64 = 0;
    var total_xor_time: u64 = 0;
    var total_not_time: u64 = 0;
    
    for (0..iterations) |_| {
        // Benchmark AND gate
        const and_start = std.time.nanoTimestamp();
        const and_result = try gates.homAnd(&ct_true, &ct_false, allocator);
        const and_end = std.time.nanoTimestamp();
        total_and_time += and_end - and_start;
        
        // Benchmark OR gate
        const or_start = std.time.nanoTimestamp();
        const or_result = try gates.homOr(&ct_true, &ct_false, allocator);
        const or_end = std.time.nanoTimestamp();
        total_or_time += or_end - or_start;
        
        // Benchmark XOR gate
        const xor_start = std.time.nanoTimestamp();
        const xor_result = try gates.homXor(&ct_true, &ct_false, allocator);
        const xor_end = std.time.nanoTimestamp();
        total_xor_time += xor_end - xor_start;
        
        // Benchmark NOT gate
        const not_start = std.time.nanoTimestamp();
        const not_result = try gates.homNot(&ct_true, allocator);
        const not_end = std.time.nanoTimestamp();
        total_not_time += not_end - not_start;
        
        // Verify results
        const and_decrypted = and_result.decrypt(&secret_key.key_lv0);
        const or_decrypted = or_result.decrypt(&secret_key.key_lv0);
        const xor_decrypted = xor_result.decrypt(&secret_key.key_lv0);
        const not_decrypted = not_result.decrypt(&secret_key.key_lv0);
        
        if (and_decrypted != (true and false) or
            or_decrypted != (true or false) or
            xor_decrypted != (true != false) or
            not_decrypted != !true) {
            std.log.err("Homomorphic operation failed", .{});
            return;
        }
    }
    
    const avg_and_time_us = (total_and_time / iterations) / 1_000;
    const avg_or_time_us = (total_or_time / iterations) / 1_000;
    const avg_xor_time_us = (total_xor_time / iterations) / 1_000;
    const avg_not_time_us = (total_not_time / iterations) / 1_000;
    
    std.log.info("Average AND gate time: {} μs", .{avg_and_time_us});
    std.log.info("Average OR gate time: {} μs", .{avg_or_time_us});
    std.log.info("Average XOR gate time: {} μs", .{avg_xor_time_us});
    std.log.info("Average NOT gate time: {} μs", .{avg_not_time_us});
}
