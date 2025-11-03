# zig-tfhe: Claude's Guide

## Overview

High-performance Zig implementation of TFHE (Torus Fully Homomorphic Encryption) - a port of `rs-tfhe` that enables computation on encrypted data without decryption.

## Key Features

- **Security Levels**: 80/110/128-bit + specialized Uint1-8 parameters
- **Performance**: SIMD vectorization (AVX/FMA), native parallelization, 2.51x slower than Rust
- **Operations**: Complete boolean gates (AND, OR, XOR, etc.), arithmetic, lookup tables
- **Safety**: Zig's compile-time memory safety with explicit allocators

## Architecture

```
TLWE → TRLWE → TRGSW → Homomorphic Gates
```

**Core Modules**: `params`, `key`, `tlwe`, `trlwe`, `trgsw`, `gates`, `bootstrap`, `lut`, `fft`, `utils`, `bit_utils`, `parallel`, `proxy_reenc`

## Quick Start

```bash
git clone https://github.com/thedonutfactory/zig-tfhe
cd zig-tfhe
zig build
```

```zig
const tfhe = @import("main");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const secret_key = tfhe.key.SecretKey.new();
    var cloud_key = try tfhe.key.CloudKey.new(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    const ct_a = try tfhe.tlwe.TLWELv0.encryptBool(true, tfhe.params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);
    const ct_b = try tfhe.tlwe.TLWELv0.encryptBool(false, tfhe.params.implementation.tlwe_lv0.ALPHA, &secret_key.key_lv0);

    const gates_inst = tfhe.gates.Gates.new();
    const result = try gates_inst.andGate(&ct_a, &ct_b, &cloud_key);
    const decrypted = result.decryptBool(&secret_key.key_lv0);
    std.debug.print("true AND false = {}\n", .{decrypted}); // false
}
```

## Examples

```bash
zig build add_two_numbers   # 16-bit homomorphic addition (402 + 304 = 706)
zig build proxy_reenc_demo  # LWE proxy reencryption demonstration
```

## Security Parameters

```zig
const params = @import("params");
const security = params.SECURITY_128_BIT;  // Default: high security
// params.SECURITY_80_BIT   // Fast, for dev/testing
// params.SECURITY_UINT4    // 4-bit messages
```

## Performance

- **Gate Operation**: ~37ms per gate
- **16-bit Addition**: ~3 seconds (80 gates)
- **vs Rust**: 2.51x slower (recently improved from 2.62x)

## Testing

```bash
zig build test                    # All tests (~30s for key generation)
zig test src/gates.zig --test-filter "gates all"  # Specific modules
```

## Status (v0.1.1)

**Implemented**: Core TFHE, gates, bootstrapping, FFT, parallelization  
**Recent**: SIMD optimizations, 4.8% performance improvement  
**Performance**: 2.51x slower than Rust (improved from 2.62x)

## Proxy Reencryption

Securely delegate access to encrypted data without decryption:

```zig
const proxy_reenc = @import("proxy_reenc");

// Bob publishes his public key
var bob_public_key = try proxy_reenc.PublicKeyLv0.new(allocator, &bob_key.key_lv0);
defer bob_public_key.deinit(allocator);

// Alice generates reencryption key using Bob's PUBLIC key
var reenc_key = try proxy_reenc.ProxyReencryptionKey.newAsymmetric(
    allocator, 
    &alice_key.key_lv0, 
    &bob_public_key
);
defer reenc_key.deinit(allocator);

// Proxy converts without learning plaintext
const bob_ct = proxy_reenc.reencryptTLWELv0(&alice_ct, &reenc_key);

// Bob decrypts with his secret key
const plaintext = bob_ct.decryptBool(&bob_key.key_lv0);
```

## Key Patterns

**Memory Management**:
```zig
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();
```

**Error Handling**:
```zig
const result = try gates_inst.andGate(&ct_a, &ct_b, &cloud_key);
```

## Related

- [rs-tfhe](https://github.com/thedonutfactory/rs-tfhe) - Rust reference
- [TFHE](https://tfhe.github.io/tfhe/) - Original C++ implementation
