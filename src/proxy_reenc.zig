//! LWE Proxy Reencryption Module
//!
//! This module implements proxy reencryption for LWE ciphertexts, allowing secure
//! transformation of ciphertexts from one secret key to another without decryption.
//!
//! # Overview
//!
//! Proxy reencryption enables a semi-trusted proxy to convert a ciphertext encrypted
//! under one key (delegator) to a ciphertext encrypted under another key (delegatee)
//! without learning the plaintext. This is useful for:
//!
//! - Secure data sharing and delegation
//! - Access control in encrypted systems
//! - Key rotation without decryption
//! - Multi-user homomorphic encryption scenarios
//!
//! # Two Modes of Operation
//!
//! ## 1. Asymmetric Mode (Recommended for delegation)
//!
//! Alice generates a reencryption key using her secret key and Bob's public key.
//! Bob never shares his secret key.
//!
//! ## 2. Symmetric Mode (For trusted scenarios)
//!
//! When both secret keys are available (e.g., single-party key rotation).

const std = @import("std");
const params = @import("params.zig");
const utils = @import("utils.zig");
const tlwe = @import("tlwe.zig");
const key = @import("key.zig");

/// LWE Public Key for asymmetric encryption
///
/// A public key consists of encryptions of zero under the secret key.
/// This allows anyone to encrypt messages without knowing the secret key.
pub const PublicKeyLv0 = struct {
    encryptions: std.ArrayListUnmanaged(tlwe.TLWELv0),

    const Self = @This();

    /// Generate a new public key from a secret key
    ///
    /// Creates encryptions of zero that can be used for encryption without
    /// revealing the secret key.
    pub fn new(allocator: std.mem.Allocator, secret_key: *const key.SecretKeyLv0) !PublicKeyLv0 {
        return Self.newWithParams(
            allocator,
            secret_key,
            params.implementation.tlwe_lv0.N * 2, // 2N for security
            params.implementation.tlwe_lv0.ALPHA,
        );
    }

    /// Generate a public key with custom parameters
    pub fn newWithParams(
        allocator: std.mem.Allocator,
        secret_key: *const key.SecretKeyLv0,
        size: usize,
        alpha: f64,
    ) !PublicKeyLv0 {
        var encryptions = std.ArrayListUnmanaged(tlwe.TLWELv0){};
        try encryptions.ensureTotalCapacity(allocator, size);

        // Generate encryptions of zero
        for (0..size) |_| {
            const enc = try tlwe.TLWELv0.encryptF64(0.0, alpha, secret_key);
            try encryptions.append(allocator, enc);
        }

        return PublicKeyLv0{
            .encryptions = encryptions,
        };
    }

    /// Free resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.encryptions.deinit(allocator);
    }

    /// Encrypt a value using the public key
    pub fn encryptF64(self: *const Self, plaintext: f64, alpha: f64) !tlwe.TLWELv0 {
        var rng = std.Random.DefaultPrng.init(utils.getUniqueSeed());
        var result = tlwe.TLWELv0.new();

        // Add the plaintext to b
        const plaintext_torus = utils.f64ToTorus(plaintext);
        result.bMut().* = plaintext_torus;

        // Randomly combine encryptions of zero
        for (self.encryptions.items) |enc| {
            if (rng.random().boolean()) {
                // Add or subtract randomly
                if (rng.random().boolean()) {
                    for (0..params.implementation.tlwe_lv0.N + 1) |i| {
                        result.p[i] = result.p[i] +% enc.p[i];
                    }
                } else {
                    for (0..params.implementation.tlwe_lv0.N + 1) |i| {
                        result.p[i] = result.p[i] -% enc.p[i];
                    }
                }
            }
        }

        // Add fresh noise
        var normal_distr = utils.NormalDist.init(0.0, alpha);
        const noise = utils.gaussianF64(0.0, &normal_distr, rng.random());
        result.bMut().* = result.bMut().* +% noise;

        return result;
    }

    /// Encrypt a boolean using the public key
    pub fn encryptBool(self: *const Self, plaintext: bool, alpha: f64) !tlwe.TLWELv0 {
        const p: f64 = if (plaintext) 0.125 else -0.125;
        return self.encryptF64(p, alpha);
    }
};

/// Proxy reencryption key for TLWELv0 ciphertexts
pub const ProxyReencryptionKey = struct {
    key_encryptions: std.ArrayListUnmanaged(tlwe.TLWELv0),
    base: usize,
    t: usize,

    const Self = @This();

    /// Generate a proxy reencryption key using asymmetric mode (RECOMMENDED)
    ///
    /// Alice generates a reencryption key using her secret key and Bob's public key.
    /// Bob never needs to share his secret key with Alice.
    pub fn newAsymmetric(
        allocator: std.mem.Allocator,
        key_from: *const key.SecretKeyLv0,
        public_key_to: *const PublicKeyLv0,
    ) !ProxyReencryptionKey {
        return Self.newAsymmetricWithParams(
            allocator,
            key_from,
            public_key_to,
            params.KSK_ALPHA,
            params.implementation.trgsw_lv1.BASEBIT,
            params.implementation.trgsw_lv1.IKS_T,
        );
    }

    /// Generate a proxy reencryption key with asymmetric mode and custom parameters
    pub fn newAsymmetricWithParams(
        allocator: std.mem.Allocator,
        key_from: *const key.SecretKeyLv0,
        public_key_to: *const PublicKeyLv0,
        alpha: f64,
        basebit: usize,
        t: usize,
    ) !ProxyReencryptionKey {
        const base = @as(usize, 1) << @intCast(basebit);
        const n = params.implementation.tlwe_lv0.N;

        var key_encryptions = std.ArrayListUnmanaged(tlwe.TLWELv0){};
        try key_encryptions.resize(allocator, base * t * n);

        // Initialize all to zero
        for (key_encryptions.items) |*item| {
            item.* = tlwe.TLWELv0.new();
        }

        // Generate decomposed encryptions using the PUBLIC key
        for (0..n) |i| {
            for (0..t) |j| {
                for (0..base) |k| {
                    if (k == 0) continue; // Skip k=0 as it contributes nothing

                    // Encrypt k * key_from[i] / 2^((j+1)*basebit) using Bob's PUBLIC key
                    const shift_amount = (j + 1) * basebit;
                    const p = (@as(f64, @floatFromInt(k)) * @as(f64, @floatFromInt(key_from[i]))) /
                        @as(f64, @floatFromInt(@as(u32, @intCast(1)) << @intCast(shift_amount)));
                    const idx = (base * t * i) + (base * j) + k;

                    // Use public key encryption instead of secret key
                    key_encryptions.items[idx] = try public_key_to.encryptF64(p, alpha);
                }
            }
        }

        return ProxyReencryptionKey{
            .key_encryptions = key_encryptions,
            .base = base,
            .t = t,
        };
    }

    /// Generate a proxy reencryption key using symmetric mode
    ///
    /// This requires both secret keys and should only be used in trusted scenarios
    /// like single-party key rotation or when both parties trust each other.
    pub fn newSymmetric(
        allocator: std.mem.Allocator,
        key_from: *const key.SecretKeyLv0,
        key_to: *const key.SecretKeyLv0,
    ) !ProxyReencryptionKey {
        return Self.newSymmetricWithParams(
            allocator,
            key_from,
            key_to,
            params.KSK_ALPHA,
            params.implementation.trgsw_lv1.BASEBIT,
            params.implementation.trgsw_lv1.IKS_T,
        );
    }

    /// Generate a proxy reencryption key in symmetric mode with custom parameters
    pub fn newSymmetricWithParams(
        allocator: std.mem.Allocator,
        key_from: *const key.SecretKeyLv0,
        key_to: *const key.SecretKeyLv0,
        alpha: f64,
        basebit: usize,
        t: usize,
    ) !ProxyReencryptionKey {
        const base = @as(usize, 1) << @intCast(basebit);
        const n = params.implementation.tlwe_lv0.N;

        var key_encryptions = std.ArrayListUnmanaged(tlwe.TLWELv0){};
        try key_encryptions.resize(allocator, base * t * n);

        // Initialize all to zero
        for (key_encryptions.items) |*item| {
            item.* = tlwe.TLWELv0.new();
        }

        // Generate decomposed encryptions similar to genKeySwitchingKey
        for (0..n) |i| {
            for (0..t) |j| {
                for (0..base) |k| {
                    if (k == 0) continue; // Skip k=0 as it contributes nothing

                    // Encrypt k * key_from[i] / 2^((j+1)*basebit)
                    const shift_amount = (j + 1) * basebit;
                    const p = (@as(f64, @floatFromInt(k)) * @as(f64, @floatFromInt(key_from[i]))) /
                        @as(f64, @floatFromInt(@as(u32, @intCast(1)) << @intCast(shift_amount)));
                    const idx = (base * t * i) + (base * j) + k;

                    key_encryptions.items[idx] = try tlwe.TLWELv0.encryptF64(p, alpha, key_to);
                }
            }
        }

        return ProxyReencryptionKey{
            .key_encryptions = key_encryptions,
            .base = base,
            .t = t,
        };
    }

    /// Free resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.key_encryptions.deinit(allocator);
    }
};

/// Reencrypt a TLWELv0 ciphertext from one key to another
///
/// Converts a ciphertext encrypted under the source key (embedded in the
/// reencryption key) to a ciphertext encrypted under the target key.
pub fn reencryptTLWELv0(ct_from: *const tlwe.TLWELv0, reenc_key: *const ProxyReencryptionKey) tlwe.TLWELv0 {
    const n = params.implementation.tlwe_lv0.N;
    const basebit = @ctz(reenc_key.base); // Count trailing zeros to get log2
    const base = reenc_key.base;
    const t = reenc_key.t;

    var result = tlwe.TLWELv0.new();

    // Start with the b value from the source ciphertext
    result.p[n] = ct_from.b();

    // Precision offset for rounding (similar to identity_key_switching)
    const prec_offset: params.Torus = @as(params.Torus, 1) << @intCast(32 - (1 + basebit * t));

    // Process each coefficient of the source ciphertext
    for (0..n) |i| {
        // Add precision offset for rounding
        const a_bar = ct_from.p[i] +% prec_offset;

        // Decompose into t levels
        for (0..t) |j| {
            // Extract the j-th digit in base `base`
            const shift = @as(u5, @intCast(32 - (j + 1) * basebit));
            const mask = (@as(params.Torus, 1) << @intCast(basebit)) - 1;
            const k = (a_bar >> shift) & mask;

            if (k != 0) {
                // Index into the reencryption key
                const idx = (base * t * i) + (base * j) + k;

                // Subtract the pre-computed encryption
                for (0..n + 1) |x| {
                    result.p[x] = result.p[x] -% reenc_key.key_encryptions.items[idx].p[x];
                }
            }
        }
    }

    return result;
}

// TESTS

test "public key encryption" {
    const allocator = std.testing.allocator;
    const secret_key = key.SecretKey.new();
    var public_key = try PublicKeyLv0.new(allocator, &secret_key.key_lv0);
    defer public_key.deinit(allocator);

    // Test encrypting with public key and decrypting with secret key
    const messages = [_]bool{ true, false };
    for (messages) |message| {
        const ct = try public_key.encryptBool(message, params.implementation.tlwe_lv0.ALPHA);
        const decrypted = ct.decryptBool(&secret_key.key_lv0);
        try std.testing.expectEqual(message, decrypted);
    }
}

test "public key encryption multiple" {
    const allocator = std.testing.allocator;
    const secret_key = key.SecretKey.new();
    var public_key = try PublicKeyLv0.new(allocator, &secret_key.key_lv0);
    defer public_key.deinit(allocator);

    var rng = std.Random.DefaultPrng.init(42);
    var correct: usize = 0;
    const iterations = 100;

    for (0..iterations) |_| {
        const message = rng.random().boolean();
        const ct = try public_key.encryptBool(message, params.implementation.tlwe_lv0.ALPHA);
        if (ct.decryptBool(&secret_key.key_lv0) == message) {
            correct += 1;
        }
    }

    const accuracy = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(iterations));
    try std.testing.expect(accuracy > 0.95);
}

test "proxy reencryption asymmetric" {
    const allocator = std.testing.allocator;
    const alice_key = key.SecretKey.new();
    const bob_key = key.SecretKey.new();

    // Bob publishes his public key
    var bob_public_key = try PublicKeyLv0.new(allocator, &bob_key.key_lv0);
    defer bob_public_key.deinit(allocator);

    // Alice generates reencryption key using Bob's PUBLIC key
    var reenc_key = try ProxyReencryptionKey.newAsymmetric(allocator, &alice_key.key_lv0, &bob_public_key);
    defer reenc_key.deinit(allocator);

    // Test both true and false
    const messages = [_]bool{ true, false };
    for (messages) |message| {
        const alice_ct = try tlwe.TLWELv0.encryptBool(message, params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);

        // Verify Alice can decrypt
        try std.testing.expectEqual(message, alice_ct.decryptBool(&alice_key.key_lv0));

        // Reencrypt to Bob's key
        const bob_ct = reencryptTLWELv0(&alice_ct, &reenc_key);

        // Verify Bob can decrypt
        try std.testing.expectEqual(message, bob_ct.decryptBool(&bob_key.key_lv0));
    }
}

test "proxy reencryption symmetric" {
    const allocator = std.testing.allocator;
    const alice_key = key.SecretKey.new();
    const bob_key = key.SecretKey.new();

    // Symmetric mode - requires both secret keys
    var reenc_key = try ProxyReencryptionKey.newSymmetric(allocator, &alice_key.key_lv0, &bob_key.key_lv0);
    defer reenc_key.deinit(allocator);

    // Test both true and false
    const messages = [_]bool{ true, false };
    for (messages) |message| {
        const alice_ct = try tlwe.TLWELv0.encryptBool(message, params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);

        // Verify Alice can decrypt
        try std.testing.expectEqual(message, alice_ct.decryptBool(&alice_key.key_lv0));

        // Reencrypt to Bob's key
        const bob_ct = reencryptTLWELv0(&alice_ct, &reenc_key);

        // Verify Bob can decrypt
        try std.testing.expectEqual(message, bob_ct.decryptBool(&bob_key.key_lv0));
    }
}

test "proxy reencryption asymmetric multiple" {
    const allocator = std.testing.allocator;
    const alice_key = key.SecretKey.new();
    const bob_key = key.SecretKey.new();
    var bob_public_key = try PublicKeyLv0.new(allocator, &bob_key.key_lv0);
    defer bob_public_key.deinit(allocator);

    var reenc_key = try ProxyReencryptionKey.newAsymmetric(allocator, &alice_key.key_lv0, &bob_public_key);
    defer reenc_key.deinit(allocator);

    var rng = std.Random.DefaultPrng.init(42);
    var correct: usize = 0;
    const iterations = 100;

    for (0..iterations) |_| {
        const message = rng.random().boolean();
        const alice_ct = try tlwe.TLWELv0.encryptBool(message, params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);
        const bob_ct = reencryptTLWELv0(&alice_ct, &reenc_key);

        if (bob_ct.decryptBool(&bob_key.key_lv0) == message) {
            correct += 1;
        }
    }

    const accuracy = @as(f64, @floatFromInt(correct)) / @as(f64, @floatFromInt(iterations));
    try std.testing.expect(accuracy > 0.90);
}

test "proxy reencryption chain asymmetric" {
    const allocator = std.testing.allocator;
    const alice_key = key.SecretKey.new();
    const bob_key = key.SecretKey.new();
    const carol_key = key.SecretKey.new();

    var bob_public = try PublicKeyLv0.new(allocator, &bob_key.key_lv0);
    defer bob_public.deinit(allocator);
    var carol_public = try PublicKeyLv0.new(allocator, &carol_key.key_lv0);
    defer carol_public.deinit(allocator);

    var reenc_key_ab = try ProxyReencryptionKey.newAsymmetric(allocator, &alice_key.key_lv0, &bob_public);
    defer reenc_key_ab.deinit(allocator);
    var reenc_key_bc = try ProxyReencryptionKey.newAsymmetric(allocator, &bob_key.key_lv0, &carol_public);
    defer reenc_key_bc.deinit(allocator);

    const message = true;
    const alice_ct = try tlwe.TLWELv0.encryptBool(message, params.implementation.tlwe_lv0.ALPHA, &alice_key.key_lv0);

    // Alice -> Bob
    const bob_ct = reencryptTLWELv0(&alice_ct, &reenc_key_ab);
    try std.testing.expectEqual(message, bob_ct.decryptBool(&bob_key.key_lv0));

    // Bob -> Carol
    const carol_ct = reencryptTLWELv0(&bob_ct, &reenc_key_bc);
    try std.testing.expectEqual(message, carol_ct.decryptBool(&carol_key.key_lv0));
}
