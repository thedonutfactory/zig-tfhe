# zig-tfhe: Zig TFHE Library

[![Zig](https://img.shields.io/badge/zig-0.12%2B-orange.svg)](https://ziglang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-128--bit-green.svg)](https://github.com/your-org/zig-tfhe)

A high-performance Zig implementation of TFHE (Torus Fully Homomorphic Encryption).

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/a7b395a8-46fb-4739-97d4-c6d65d21ba46" />

## Overview

zig-tfhe is a comprehensive homomorphic encryption library that enables computation on encrypted data without decryption, built in Zig for performance and safety.

### Key Features

![LUT Bootstrapping](https://img.shields.io/badge/LUT--Bootstrapping-Enabled-blue.svg)
![SIMD FFT](https://img.shields.io/badge/SIMD--FFT-AVX%2FFMA-red.svg)
![Parallel Processing](https://img.shields.io/badge/Parallel-Native-green.svg)
![Security Levels](https://img.shields.io/badge/Security-80%2C110%2C128--bit-purple.svg)

- **Multiple Security Levels**: 80-bit, 110-bit, and 128-bit security parameters
- **Specialized Uint Parameters**: Optimized parameter sets for different message moduli (1-8 bits)
- **Homomorphic Gates**: Complete set of boolean operations (AND, OR, NAND, NOR, XOR, XNOR, NOT, MUX)
- **Fast Arithmetic**: Efficient multi-bit arithmetic operations using nibble-based addition
- **Parallel Processing**: Native Zig parallelization for batch operations
- **Optimized FFT**: Multiple FFT implementations including SIMD optimizations
- **Feature Flags**: Modular compilation with optional features

## Installation

### Prerequisites

- Zig 0.12.0 or later
- A C compiler (for linking math libraries)

### Building

```bash
git clone <repository>
cd zig-tfhe
zig build
```

### Running Examples

```bash
# Basic examples
zig build run -- example add_two_numbers
zig build run -- example gates_demo

# LUT bootstrapping examples
zig build run -- example lut_bootstrapping
zig build run -- example lut_arithmetic
```

### Running Tests

```bash
zig build test
```

### Running Benchmarks

```bash
zig build bench
```

## Quick Start

### Basic Homomorphic Operations

```zig
const tfhe = @import("zig-tfhe");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate keys
    const secret_key = try tfhe.key.SecretKey.init(allocator);
    const cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);

    // Encrypt boolean values
    const ct_true = try tfhe.utils.Ciphertext.encrypt(true, &secret_key.key_lv0, allocator);
    const ct_false = try tfhe.utils.Ciphertext.encrypt(false, &secret_key.key_lv0, allocator);

    // Perform homomorphic operations
    var gates = tfhe.gates.Gates.init(allocator, &cloud_key);
    const result = try gates.hom_and(&ct_true, &ct_false, allocator);

    // Decrypt result
    const decrypted = result.decrypt(&secret_key.key_lv0);
    std.debug.assert(decrypted == false);
}
```

### Programmable Bootstrapping

```zig
const tfhe = @import("zig-tfhe");
const std = @import("std");

pub fn lut_bootstrap_example() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const secret_key = try tfhe.key.SecretKey.init(allocator);
    const cloud_key = try tfhe.key.CloudKey.init(allocator, &secret_key);
    var bootstrap = tfhe.bootstrap.lut.LutBootstrap.init(allocator);
    
    // Encrypt a value
    const encrypted = try tfhe.utils.Ciphertext.encrypt_lwe_message(5, 8, 0.0001, &secret_key.key_lv0, allocator);
    
    // Define a function to evaluate (square function)
    const square_func = struct {
        fn call(x: usize) usize {
            return (x * x) % 8;
        }
    }.call;
    
    // Apply function during bootstrapping
    const result = try bootstrap.bootstrap_func(&encrypted, square_func, 8, &cloud_key, allocator);
    
    // Decrypt result
    const decrypted = result.decrypt_lwe_message(8, &secret_key.key_lv0);
    std.debug.assert(decrypted == 1); // 5^2 mod 8 = 25 mod 8 = 1
}
```

## Architecture

### Core Components

#### Encryption Schemes
- **TLWE**: Torus Learning With Errors for level-0 ciphertexts
- **TRLWE**: Torus Ring Learning With Errors for level-1 ciphertexts
- **TRGSW**: Torus GSW for bootstrapping keys

#### Bootstrapping Strategies
- **Vanilla Bootstrap**: Traditional noise refreshing
- **LUT Bootstrap**: Programmable bootstrapping with lookup tables

#### FFT Implementations
- **Standard FFT**: Pure Zig implementation
- **SIMD FFT**: AVX/FMA optimized for x86_64
- **Real FFT**: Optimized for real-valued polynomials

### Parameter Sets

#### Standard Security Parameters
- `SECURITY_80_BIT`: 80-bit security level
- `SECURITY_110_BIT`: 110-bit security level  
- `SECURITY_128_BIT`: 128-bit security level (default)

#### Specialized Uint Parameters
- `SECURITY_UINT1`: Binary operations (messageModulus=2)
- `SECURITY_UINT2`: 2-bit arithmetic (messageModulus=4)
- `SECURITY_UINT3`: 3-bit arithmetic (messageModulus=8)
- `SECURITY_UINT4`: 4-bit arithmetic (messageModulus=16)
- `SECURITY_UINT5`: 5-bit arithmetic (messageModulus=32) - Recommended for complex operations
- `SECURITY_UINT6`: 6-bit arithmetic (messageModulus=64)
- `SECURITY_UINT7`: 7-bit arithmetic (messageModulus=128)
- `SECURITY_UINT8`: 8-bit arithmetic (messageModulus=256)

## Examples

The `examples/` directory contains comprehensive examples:

### Basic Examples
- `add_two_numbers.zig`: Simple homomorphic addition
- `gates_demo.zig`: Boolean gate operations
- `security_levels.zig`: Different security parameter comparisons

### LUT Bootstrapping Examples
- `lut_bootstrapping.zig`: Complete programmable bootstrapping demo
- `lut_bootstrapping_simple.zig`: Minimal LUT example
- `lut_add_two_numbers.zig`: Fast 8-bit addition using nibble operations
- `lut_arithmetic.zig`: Various arithmetic operations
- `lut_uint_parameters.zig`: Parameter set comparisons

### Performance Examples
- `batch_gates.zig`: Parallel gate processing
- `fft_diagnostics.zig`: FFT performance analysis

## Performance

![Benchmarks](https://img.shields.io/badge/Benchmarks-Native-orange.svg)
![Speedup](https://img.shields.io/badge/Speedup-2.7x--faster-brightgreen.svg)

### Benchmarks

Run benchmarks with:

```bash
zig build bench
```

### Performance Characteristics

| Operation | Time (ms) | Notes |
|-----------|-----------|-------|
| Key Generation | ~135 | One-time setup |
| Boolean Gate | ~15 | Per gate operation |
| Bootstrap | ~15-20 | Noise refreshing |
| LUT Bootstrap | ~15-20 | Function evaluation + noise refreshing |
| 8-bit Addition | ~50 | 3 bootstraps vs 8 for bit-by-bit |

### Optimization Features

- **Parallel Processing**: Native Zig parallelization
- **SIMD FFT**: AVX/FMA optimizations for x86_64
- **Specialized Parameters**: Optimized for specific message moduli
- **LUT Reuse**: Pre-computed lookup tables for repeated functions

## API Reference

### Core Types

#### `Ciphertext`
Main ciphertext type supporting homomorphic operations.

```zig
pub const Ciphertext = struct {
    pub fn encrypt(plaintext: bool, key: *const SecretKeyLv0, allocator: Allocator) !Self;
    pub fn decrypt(self: *const Self, key: *const SecretKeyLv0) bool;
    pub fn encrypt_lwe_message(msg: usize, modulus: usize, alpha: f64, key: *const SecretKeyLv0, allocator: Allocator) !Self;
    pub fn decrypt_lwe_message(self: *const Self, modulus: usize, key: *const SecretKeyLv0) usize;
};
```

#### `Gates`
Boolean gate operations.

```zig
pub const Gates = struct {
    pub fn hom_and(self: *Self, a: *const Ciphertext, b: *const Ciphertext, allocator: Allocator) !Ciphertext;
    pub fn hom_or(self: *Self, a: *const Ciphertext, b: *const Ciphertext, allocator: Allocator) !Ciphertext;
    pub fn hom_xor(self: *Self, a: *const Ciphertext, b: *const Ciphertext, allocator: Allocator) !Ciphertext;
    pub fn hom_not(self: *Self, a: *const Ciphertext, allocator: Allocator) !Ciphertext;
    pub fn mux(self: *Self, cond: *const Ciphertext, a: *const Ciphertext, b: *const Ciphertext, allocator: Allocator) !Ciphertext;
};
```

#### `LutBootstrap`
Programmable bootstrapping with lookup tables.

```zig
pub const LutBootstrap = struct {
    pub fn bootstrap_func(self: *Self, ct: *const Ciphertext, f: fn(usize) usize, modulus: usize, key: *const CloudKey, allocator: Allocator) !Ciphertext;
    pub fn bootstrap_lut(self: *Self, ct: *const Ciphertext, lut: *const LookupTable, key: *const CloudKey, allocator: Allocator) !Ciphertext;
};
```

## Contributing

Contributions are welcome! Please see the existing code style and add tests for new functionality.

### Development Setup

```bash
git clone <repository>
cd zig-tfhe
zig build test
zig build bench
```

### Running Examples

```bash
# Basic examples
zig build run -- example add_two_numbers
zig build run -- example gates_demo

# LUT bootstrapping examples
zig build run -- example lut_bootstrapping
zig build run -- example lut_add_two_numbers
```

## License

This project is licensed under the same terms as the original TFHE library. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Based on the TFHE library by Ilaria Chillotti, Nicolas Gama, Mariya Georgieva, and Malika Izabachène
- Ported from the rs-tfhe Rust implementation
- FFT optimizations from tfhe-go reference implementation
