//! Proxy Reencryption Example
//!
//! This example demonstrates how to use LWE proxy reencryption to securely
//! delegate access to encrypted data without decryption.
//!
//! Run with:
//! zig build proxy_reenc_demo

const std = @import("std");
const tfhe = @import("main");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== LWE Proxy Reencryption Demo ===\n\n", .{});

    // Scenario: Alice wants to share encrypted data with Bob
    // without decrypting it, using a semi-trusted proxy

    std.debug.print("1. Setting up keys for Alice and Bob...\n", .{});
    const alice_key = tfhe.key.SecretKey.new();
    const bob_key = tfhe.key.SecretKey.new();
    std.debug.print("   ✓ Alice's secret key generated\n", .{});

    // Bob publishes his public key
    var timer = try std.time.Timer.start();
    var bob_public_key = try tfhe.proxy_reenc.PublicKeyLv0.new(allocator, &bob_key.key_lv0);
    defer bob_public_key.deinit(allocator);
    const pubkey_time = timer.read();
    std.debug.print("   ✓ Bob's public key generated in {d:.2}ms\n", .{@as(f64, @floatFromInt(pubkey_time)) / 1_000_000.0});
    std.debug.print("   ✓ Bob shares his public key (safe to publish)\n\n", .{});

    // Alice encrypts some data
    std.debug.print("2. Alice encrypts her data...\n", .{});
    const messages = [_]bool{ true, false, true, true, false };
    var alice_ciphertexts = try std.ArrayList(tfhe.tlwe.TLWELv0).initCapacity(allocator, messages.len);
    defer alice_ciphertexts.deinit(allocator);

    for (messages) |msg| {
        const ct = try tfhe.tlwe.TLWELv0.encryptBool(msg, tfhe.params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);
        try alice_ciphertexts.append(allocator, ct);
    }

    std.debug.print("   Messages encrypted by Alice:\n", .{});
    for (messages, 0..) |msg, i| {
        std.debug.print("   - Message {}: {}\n", .{ i + 1, msg });
    }
    std.debug.print("\n", .{});

    // Alice generates a proxy reencryption key using Bob's PUBLIC key
    std.debug.print("3. Alice generates a proxy reencryption key (Alice -> Bob)...\n", .{});
    std.debug.print("   Using ASYMMETRIC mode - Bob's secret key is NOT needed!\n", .{});
    timer.reset();
    var reenc_key = try tfhe.proxy_reenc.ProxyReencryptionKey.newAsymmetric(allocator, &alice_key.key_lv0, &bob_public_key);
    defer reenc_key.deinit(allocator);
    const keygen_time = timer.read();
    std.debug.print("   ✓ Reencryption key generated in {d:.2}ms\n", .{@as(f64, @floatFromInt(keygen_time)) / 1_000_000.0});
    std.debug.print("   ✓ Alice shares this key with the proxy\n\n", .{});

    // Proxy reencrypts the data (without learning the plaintext)
    std.debug.print("4. Proxy converts Alice's ciphertexts to Bob's ciphertexts...\n", .{});
    timer.reset();
    var bob_ciphertexts = try std.ArrayList(tfhe.tlwe.TLWELv0).initCapacity(allocator, alice_ciphertexts.items.len);
    defer bob_ciphertexts.deinit(allocator);

    for (alice_ciphertexts.items) |ct| {
        const bob_ct = tfhe.proxy_reenc.reencryptTLWELv0(&ct, &reenc_key);
        try bob_ciphertexts.append(allocator, bob_ct);
    }
    const reenc_time = timer.read();
    std.debug.print("   ✓ {} ciphertexts reencrypted in {d:.2}ms\n", .{ bob_ciphertexts.items.len, @as(f64, @floatFromInt(reenc_time)) / 1_000_000.0 });
    std.debug.print("   ✓ Average time per reencryption: {d:.2}ms\n\n", .{@as(f64, @floatFromInt(reenc_time)) / (@as(f64, @floatFromInt(bob_ciphertexts.items.len)) * 1_000_000.0)});

    // Bob decrypts the reencrypted data
    std.debug.print("5. Bob decrypts the reencrypted data...\n", .{});
    var correct: usize = 0;
    var decrypted_messages = try std.ArrayList(bool).initCapacity(allocator, bob_ciphertexts.items.len);
    defer decrypted_messages.deinit(allocator);

    for (bob_ciphertexts.items) |ct| {
        try decrypted_messages.append(allocator, ct.decryptBool(&bob_key.key_lv0));
    }

    std.debug.print("   Decrypted messages:\n", .{});
    for (messages, 0..) |original, i| {
        const decrypted = decrypted_messages.items[i];
        const status = if (original == decrypted) blk: {
            correct += 1;
            break :blk "✓";
        } else "✗";
        std.debug.print("   {s} Message {}: {} (original: {})\n", .{ status, i + 1, decrypted, original });
    }
    std.debug.print("\n", .{});

    std.debug.print("=== Results ===\n", .{});
    const accuracy = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(messages.len)) * 100.0;
    std.debug.print("Accuracy: {}/{} ({d:.1}%)\n", .{ correct, messages.len, accuracy });
    std.debug.print("\n", .{});

    // Demonstrate multi-hop reencryption: Alice -> Bob -> Carol
    std.debug.print("\n=== Multi-Hop Reencryption Demo (Asymmetric) ===\n\n", .{});
    std.debug.print("Demonstrating a chain: Alice -> Bob -> Carol\n", .{});
    std.debug.print("Each party only needs the next party's PUBLIC key\n\n", .{});

    const carol_key = tfhe.key.SecretKey.new();
    var carol_public_key = try tfhe.proxy_reenc.PublicKeyLv0.new(allocator, &carol_key.key_lv0);
    defer carol_public_key.deinit(allocator);
    std.debug.print("1. Carol's keys generated and public key published\n", .{});

    var reenc_key_bc = try tfhe.proxy_reenc.ProxyReencryptionKey.newAsymmetric(allocator, &bob_key.key_lv0, &carol_public_key);
    defer reenc_key_bc.deinit(allocator);
    std.debug.print("2. Generated reencryption key (Bob -> Carol) using Carol's PUBLIC key\n", .{});

    const test_message = true;
    const alice_ct = try tfhe.tlwe.TLWELv0.encryptBool(test_message, tfhe.params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);
    std.debug.print("3. Alice encrypts message: {}\n", .{test_message});

    const bob_ct = tfhe.proxy_reenc.reencryptTLWELv0(&alice_ct, &reenc_key);
    std.debug.print("4. Proxy reencrypts Alice -> Bob\n", .{});
    const bob_decrypted = bob_ct.decryptBool(&bob_key.key_lv0);
    const bob_status = if (bob_decrypted == test_message) "✓" else "✗";
    std.debug.print("   Bob decrypts: {} {s}\n", .{ bob_decrypted, bob_status });

    const carol_ct = tfhe.proxy_reenc.reencryptTLWELv0(&bob_ct, &reenc_key_bc);
    std.debug.print("5. Proxy reencrypts Bob -> Carol\n", .{});
    const carol_decrypted = carol_ct.decryptBool(&carol_key.key_lv0);
    const carol_status = if (carol_decrypted == test_message) "✓" else "✗";
    std.debug.print("   Carol decrypts: {} {s}\n", .{ carol_decrypted, carol_status });

    std.debug.print("\n", .{});
    std.debug.print("=== Security Notes ===\n", .{});
    std.debug.print("• The proxy never learns the plaintext\n", .{});
    std.debug.print("• Bob's secret key is NEVER shared - only his public key is used\n", .{});
    std.debug.print("• The reencryption key only works in one direction\n", .{});
    std.debug.print("• Each reencryption adds a small amount of noise\n", .{});
    std.debug.print("• The scheme is unidirectional (Alice->Bob key ≠ Bob->Alice key)\n", .{});
    std.debug.print("• True asymmetric proxy reencryption with LWE-based public keys\n", .{});

    std.debug.print("\n=== Performance Summary ===\n", .{});
    std.debug.print("Bob's public key generation: {d:.2}ms\n", .{@as(f64, @floatFromInt(pubkey_time)) / 1_000_000.0});
    std.debug.print("Reencryption key generation: {d:.2}ms\n", .{@as(f64, @floatFromInt(keygen_time)) / 1_000_000.0});
    std.debug.print("Average reencryption time: {d:.2}ms\n", .{@as(f64, @floatFromInt(reenc_time)) / (@as(f64, @floatFromInt(bob_ciphertexts.items.len)) * 1_000_000.0)});
}
