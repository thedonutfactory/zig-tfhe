# Proxy Reencryption for Zig-TFHE

## Overview

The Zig-TFHE library now includes LWE-based proxy reencryption, providing secure delegation of encrypted data access without requiring secret key sharing.

This is a direct port of the rs-tfhe proxy reencryption feature, maintaining API compatibility while leveraging Zig's performance characteristics.

## Quick Start

### Build and Run Example

```bash
zig build proxy_reenc_demo
```

### Basic Usage

```zig
const std = @import("std");
const tfhe = @import("main");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Alice and Bob generate keys
    const alice_key = tfhe.key.SecretKey.new();
    const bob_key = tfhe.key.SecretKey.new();

    // Bob publishes his public key (safe to share)
    var bob_public_key = try tfhe.proxy_reenc.PublicKeyLv0.new(allocator, &bob_key.key_lv0);
    defer bob_public_key.deinit(allocator);

    // Alice encrypts a message
    const message = true;
    const alice_ct = try tfhe.tlwe.TLWELv0.encryptBool(
        message, 
        tfhe.params.implementation.tlwe_lv0.ALPHA, 
        &alice_key.key_lv0
    );

    // Alice generates reencryption key using Bob's PUBLIC key
    var reenc_key = try tfhe.proxy_reenc.ProxyReencryptionKey.newAsymmetric(
        allocator,
        &alice_key.key_lv0,
        &bob_public_key
    );
    defer reenc_key.deinit(allocator);

    // Proxy converts (without learning plaintext)
    const bob_ct = tfhe.proxy_reenc.reencryptTLWELv0(&alice_ct, &reenc_key);

    // Bob decrypts with his secret key
    const decrypted = bob_ct.decryptBool(&bob_key.key_lv0);
    std.debug.print("Decrypted: {}\n", .{decrypted}); // true
}
```

## API Reference

### `PublicKeyLv0`

LWE public key for asymmetric encryption.

#### Methods

```zig
// Create new public key
pub fn new(allocator: std.mem.Allocator, secret_key: *const key.SecretKeyLv0) !PublicKeyLv0

// Create with custom parameters
pub fn newWithParams(
    allocator: std.mem.Allocator,
    secret_key: *const key.SecretKeyLv0,
    size: usize,
    alpha: f64
) !PublicKeyLv0

// Encrypt f64 value
pub fn encryptF64(self: *const Self, plaintext: f64, alpha: f64) !tlwe.TLWELv0

// Encrypt boolean
pub fn encryptBool(self: *const Self, plaintext: bool, alpha: f64) !tlwe.TLWELv0

// Free resources
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void
```

### `ProxyReencryptionKey`

Proxy reencryption key for transforming ciphertexts between keys.

#### Methods

```zig
// Asymmetric mode (recommended)
pub fn newAsymmetric(
    allocator: std.mem.Allocator,
    key_from: *const key.SecretKeyLv0,
    public_key_to: *const PublicKeyLv0
) !ProxyReencryptionKey

// Asymmetric with custom parameters
pub fn newAsymmetricWithParams(
    allocator: std.mem.Allocator,
    key_from: *const key.SecretKeyLv0,
    public_key_to: *const PublicKeyLv0,
    alpha: f64,
    basebit: usize,
    t: usize
) !ProxyReencryptionKey

// Symmetric mode (for trusted scenarios)
pub fn newSymmetric(
    allocator: std.mem.Allocator,
    key_from: *const key.SecretKeyLv0,
    key_to: *const key.SecretKeyLv0
) !ProxyReencryptionKey

// Symmetric with custom parameters
pub fn newSymmetricWithParams(
    allocator: std.mem.Allocator,
    key_from: *const key.SecretKeyLv0,
    key_to: *const key.SecretKeyLv0,
    alpha: f64,
    basebit: usize,
    t: usize
) !ProxyReencryptionKey

// Free resources
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void
```

### `reencryptTLWELv0`

Reencrypt a ciphertext from one key to another.

```zig
pub fn reencryptTLWELv0(
    ct_from: *const tlwe.TLWELv0, 
    reenc_key: *const ProxyReencryptionKey
) tlwe.TLWELv0
```

## Two Operating Modes

### Asymmetric Mode (Recommended)

Use when you want true proxy reencryption where Bob doesn't share his secret key:

```zig
// Bob publishes public key
var bob_public = try PublicKeyLv0.new(allocator, &bob_secret.key_lv0);
defer bob_public.deinit(allocator);

// Alice uses Bob's public key
var reenc_key = try ProxyReencryptionKey.newAsymmetric(
    allocator,
    &alice_secret.key_lv0,
    &bob_public
);
defer reenc_key.deinit(allocator);
```

**Performance**: ~1.7s key generation, ~1.1ms reencryption

### Symmetric Mode (Trusted Scenarios)

Use for single-party key rotation or when both parties trust each other:

```zig
// Requires both secret keys
var reenc_key = try ProxyReencryptionKey.newSymmetric(
    allocator,
    &old_key.key_lv0,
    &new_key.key_lv0
);
defer reenc_key.deinit(allocator);
```

**Performance**: ~20ms key generation, ~1.1ms reencryption

## Memory Management

All proxy reencryption types require explicit deinitialization:

```zig
var public_key = try PublicKeyLv0.new(allocator, &secret_key.key_lv0);
defer public_key.deinit(allocator);  // Always deinit!

var reenc_key = try ProxyReencryptionKey.newAsymmetric(allocator, &key_from, &public_key);
defer reenc_key.deinit(allocator);  // Always deinit!
```

## Testing

Run proxy reencryption tests:

```bash
zig test src/proxy_reenc.zig
```

Tests included:
- ✅ Public key encryption/decryption
- ✅ Public key with multiple plaintexts
- ✅ Asymmetric proxy reencryption
- ✅ Symmetric proxy reencryption
- ✅ Asymmetric with multiple iterations
- ✅ Multi-hop chains (Alice → Bob → Carol)

All tests passing: **6/6 proxy_reenc tests** (86/86 total with library tests)

## Performance

Measured on Apple Silicon (M-series):

| Operation | Asymmetric | Symmetric |
|-----------|-----------|-----------|
| Public key generation | ~1.6ms | N/A |
| Reencryption key gen | ~1.7s | ~20ms |
| Reencryption | ~1.1ms | ~1.1ms |
| Accuracy (3-hop chain) | 100% | 100% |

**Note**: Zig implementation is significantly faster than Rust for key generation due to Zig's compile-time optimizations and native code generation.

## Security

- **128-bit post-quantum security** (same as rs-tfhe)
- **Unidirectional**: Alice→Bob key ≠ Bob→Alice key
- **Proxy obliviousness**: Proxy learns nothing about plaintext
- **No secret key exposure** in asymmetric mode

## Multi-Hop Chains

For chains longer than 3-4 hops, use bootstrapping to refresh noise:

```zig
const bootstrap_strategy = tfhe.bootstrap.default_bootstrap();

// After reencryption
const ct_reencrypted = tfhe.proxy_reenc.reencryptTLWELv0(&ct, &reenc_key);

// Refresh noise with bootstrapping
const ct_refreshed = try bootstrap_strategy.bootstrap(&ct_reencrypted, &cloud_key);
// Safe for another hop
```

## Example Output

```
=== LWE Proxy Reencryption Demo ===

1. Setting up keys for Alice and Bob...
   ✓ Alice's secret key generated
   ✓ Bob's public key generated in 1.60ms
   ✓ Bob shares his public key (safe to publish)

2. Alice encrypts her data...
   Messages encrypted by Alice:
   - Message 1: true
   - Message 2: false
   - Message 3: true
   - Message 4: true
   - Message 5: false

3. Alice generates a proxy reencryption key (Alice -> Bob)...
   Using ASYMMETRIC mode - Bob's secret key is NOT needed!
   ✓ Reencryption key generated in 1705.81ms
   ✓ Alice shares this key with the proxy

4. Proxy converts Alice's ciphertexts to Bob's ciphertexts...
   ✓ 5 ciphertexts reencrypted in 5.68ms
   ✓ Average time per reencryption: 1.14ms

5. Bob decrypts the reencrypted data...
   Decrypted messages:
   ✓ Message 1: true (original: true)
   ✓ Message 2: false (original: false)
   ✓ Message 3: true (original: true)
   ✓ Message 4: true (original: true)
   ✓ Message 5: false (original: false)

=== Results ===
Accuracy: 5/5 (100.0%)
```

## Use Cases

Same as rs-tfhe:
- Secure data sharing in healthcare/finance
- Cloud storage with delegated access
- Key rotation without decryption
- Multi-party computation on encrypted data
- Access control for encrypted databases

## Comparison to Rust Implementation

| Feature | Zig | Rust |
|---------|-----|------|
| **API** | Very similar | Reference impl |
| **Memory** | Explicit allocators | Automatic |
| **Performance (keygen)** | ~1.7s | ~7.6s |
| **Performance (reenc)** | ~1.1ms | ~2.5ms |
| **Tests** | 6 tests passing | 8 tests passing |
| **Security** | 128-bit | 128-bit |

Zig implementation is **~4.5x faster** for asymmetric key generation and **~2.3x faster** for reencryption operations!

## Future Enhancements

- [ ] TLWELv1 support
- [ ] Batched operations
- [ ] Parallel key generation
- [ ] Integration with Zig's async/await for concurrent reencryptions

## Related Documentation

- See `../PROXY_REENCRYPTION.md` for comprehensive usage guide
- See `../ASYMMETRIC_PROXY_REENC.md` for security analysis
- See `../RELEASE_NOTES_PROXY_REENC.md` for release details

## License

Same as zig-tfhe library.

