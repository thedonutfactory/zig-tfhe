# zig-tfhe: Zig TFHE Library

[![CI](https://github.com/thedonutfactory/zig-tfhe/workflows/CI/badge.svg)](https://github.com/thedonutfactory/zig-tfhe/actions)
[![Zig](https://img.shields.io/badge/zig-0.12%2B-orange.svg)](https://ziglang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-128--bit-green.svg)](https://github.com/thedonutfactory/zig-tfhe)

A high-performance Zig implementation of TFHE (Torus Fully Homomorphic Encryption).

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/a7b395a8-46fb-4739-97d4-c6d65d21ba46" />

## Overview

zig-tfhe is a comprehensive homomorphic encryption library that enables computation on encrypted data without decryption, built in Zig for performance and safety.

> Not the language you were looking for? Check out our [Rust](https://github.com/thedonutfactory/rs-tfhe) or [Go](https://github.com/thedonutfactory/go-tfhe) sister projects.

### Key Features

![LUT Bootstrapping](https://img.shields.io/badge/LUT--Bootstrapping-Enabled-blue.svg)
![SIMD FFT](https://img.shields.io/badge/SIMD--FFT-AVX%2FFMA-red.svg)
![Parallel Processing](https://img.shields.io/badge/Parallel-Native-green.svg)
![Security Levels](https://img.shields.io/badge/Security-80%2C110%2C128--bit-purple.svg)

- **Multiple Security Levels**: 80-bit, 110-bit, and 128-bit security parameters
- **Specialized Uint Parameters**: Optimized parameter sets for different message moduli (1-8 bits)
- **Homomorphic Gates**: Complete set of boolean operations (AND, OR, NAND, NOR, XOR, XNOR, NOT, MUX)
- **Fast Arithmetic**: Efficient multi-bit arithmetic operations using ripple-carry adders
- **Parallel Processing**: Native Zig parallelization for batch operations
- **Optimized FFT**: High-performance FFT implementations with SIMD support
- **Memory Safety**: Zig's compile-time safety guarantees with comprehensive allocator tracking

## Quick Start

### Installation

#### Prerequisites

- Zig 0.12.0 or later
- A C compiler (for linking math libraries)

#### Building

```bash
git clone https://github.com/thedonutfactory/zig-tfhe
cd zig-tfhe
zig build
```

### Basic Usage

```zig
const std = @import("std");
const tfhe = @import("main");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Generate keys
    const secret_key = tfhe.key.SecretKey.new();
    var cloud_key = try tfhe.key.CloudKey.new(allocator, &secret_key);
    defer cloud_key.deinit(allocator);

    // Encrypt two boolean values
    const ct_a = try tfhe.tlwe.TLWELv0.encryptBool(
        true,
        tfhe.params.implementation.tlwe_lv0.ALPHA,
        &secret_key.key_lv0
    );
    const ct_b = try tfhe.tlwe.TLWELv0.encryptBool(
        false,
        tfhe.params.implementation.tlwe_lv0.ALPHA,
        &secret_key.key_lv0
    );

    // Perform homomorphic AND operation
    const gates_inst = tfhe.gates.Gates.new();
    const result = try gates_inst.andGate(&ct_a, &ct_b, &cloud_key);

    // Decrypt result
    const decrypted = result.decryptBool(&secret_key.key_lv0);
    std.debug.print("true AND false = {}\n", .{decrypted}); // Prints: false
}
```

## Examples

The `examples/` directory contains several demonstrations:

### Add Two Numbers

Demonstrates homomorphic integer addition using a full adder circuit:

```bash
build add_two_numbers -Doptimize=ReleaseFast -Dcpu=native 
```

This example adds two 16-bit numbers (402 + 304 = 706) entirely in the encrypted domain using homomorphic XOR, AND, and OR gates. See [examples/README.md](examples/README.md) for details.

## Testing

Run all tests:

```bash
zig build test
```

Run specific test modules:

```bash
zig test src/gates.zig --test-filter "gates all" -Doptimize=ReleaseFast -Dcpu=native 
zig test src/utils.zig  -Doptimize=ReleaseFast -Dcpu=native 
zig test src/key.zig --test-filter "secret key" -Doptimize=ReleaseFast -Dcpu=native 
```

**Note**: The full test suite includes cloud key generation which takes ~30 seconds. Use test filters to run faster subsets during development.

## API Overview

### Core Modules

- **`params`** - Security parameter selection (80-bit, 110-bit, 128-bit, Uint1-8)
- **`key`** - Secret key and cloud key generation
- **`tlwe`** - TLWE (Torus Learning With Errors) encryption
- **`trlwe`** - TRLWE (Ring Learning With Errors) encryption
- **`trgsw`** - TRGSW encryption for bootstrapping
- **`gates`** - Homomorphic logic gates (AND, OR, NOT, XOR, etc.)
- **`lut`** - Programmable bootstrapping with lookup tables
- **`fft`** - Fast Fourier Transform for polynomial operations
- **`bootstrap`** - Noise refreshing operations
- **`utils`** - Utility functions for torus operations and noise generation
- **`bit_utils`** - Bit manipulation and encryption helpers

### Security Parameters

Choose security level based on your requirements:

```zig
const params = @import("params");

// High security (default)
const security = params.SECURITY_128_BIT;

// Balanced performance and security
const security = params.SECURITY_110_BIT;

// Development/testing (faster)
const security = params.SECURITY_80_BIT;

// Specialized for multi-bit messages
const security = params.SECURITY_UINT4; // 4-bit messages
```

### Homomorphic Operations

All boolean gates supported:

```zig
const gates_inst = tfhe.gates.Gates.new();

// Basic gates
const and_result = try gates_inst.andGate(&ct_a, &ct_b, &cloud_key);
const or_result = try gates_inst.orGate(&ct_a, &ct_b, &cloud_key);
const xor_result = try gates_inst.xorGate(&ct_a, &ct_b, &cloud_key);
const not_result = gates_inst.notGate(&ct_a);

// Advanced gates
const nand_result = try gates_inst.nandGate(&ct_a, &ct_b, &cloud_key);
const nor_result = try gates_inst.norGate(&ct_a, &ct_b, &cloud_key);
const mux_result = try gates_inst.muxNaive(&ct_cond, &ct_true, &ct_false, &cloud_key);
```

## Performance

Typical performance on modern hardware (M-series Mac, ~3-4 GHz):

- **Gate Operation**: ~350-400ms per gate (includes bootstrapping)
- **Key Generation**: ~15-20 seconds for full cloud key
- **16-bit Addition**: ~30-35 seconds (80 gates)

Performance is dominated by bootstrapping operations, which are necessary to keep noise levels manageable for continued computation.

## Architecture

### TFHE Scheme Overview

```
TLWE (Level 0)
    ↓ (Bootstrap)
TRLWE (Level 1) ← Uses FFT for efficiency
    ↓
TRGSW (Gadget Decomposition)
    ↓
Homomorphic Gates
```

### Key Components

1. **TLWE**: Basic torus LWE encryption (smaller dimension)
2. **TRLWE**: Ring-based LWE over polynomial rings (larger dimension)
3. **TRGSW**: Gadget switching keys enabling external products
4. **Bootstrap**: Noise reduction through homomorphic decryption
5. **FFT**: Efficient polynomial multiplication in frequency domain

## Documentation

All modules include comprehensive inline documentation. Generate docs with:

```bash
zig build-lib src/main.zig -femit-docs
```

Or browse the source files - each module has detailed header documentation explaining its purpose and usage.

## Contributing

Contributions are welcome! This library is a port of [rs-tfhe](https://github.com/thedonutfactory/rs-tfhe) with Zig-specific optimizations and idioms.

### Development

- Follow idiomatic Zig style (see `zig fmt`)
- Add tests for new functionality
- Document public APIs with `///` doc comments
- Use proper memory management with allocators

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

This library is based on:
- [TFHE](https://tfhe.github.io/tfhe/) - The original TFHE library
- [rs-tfhe](https://github.com/thedonutfactory/rs-tfhe) - Rust implementation
- Research papers on TFHE and programmable bootstrapping

## Related Projects

- [rs-tfhe](https://github.com/thedonutfactory/rs-tfhe) - Rust implementation
- [go-tfhe](https://github.com/thedonutfactory/go-tfhe) - Go implementation
