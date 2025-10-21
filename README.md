# zig-tfhe: Zig TFHE Library

[![Zig](https://img.shields.io/badge/zig-0.12%2B-orange.svg)](https://ziglang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-128--bit-green.svg)](https://github.com/your-org/zig-tfhe)

A high-performance Zig implementation of TFHE (Torus Fully Homomorphic Encryption).

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/a7b395a8-46fb-4739-97d4-c6d65d21ba46" />

## Overview

zig-tfhe is a comprehensive homomorphic encryption library that enables computation on encrypted data without decryption, built in Zig for performance and safety.

(Not the language you were looking for? Check out our [rust](https://github.com/thedonutfactory/rs-tfhe) or [go](https://github.com/thedonutfactory/go-tfhe) sister projects) 

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
git clone https://github.com/thedonutfactory/zig-tfhe
cd zig-tfhe
zig build
```
