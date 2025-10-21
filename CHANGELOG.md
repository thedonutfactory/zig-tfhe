# Changelog

All notable changes to zig-tfhe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-21

### Added

#### Core Cryptographic Primitives
- TLWE (Torus Learning With Errors) encryption at Level 0
- TRLWE (Ring Learning With Errors) encryption at Level 1
- TRGSW (Ring GSW) encryption with gadget decomposition
- Vanilla bootstrapping for noise refreshing
- Programmable bootstrapping with lookup table (LUT) support
- Fast Fourier Transform (FFT) implementation for polynomial operations

#### Homomorphic Operations
- Complete set of homomorphic boolean gates:
  - `AND` gate with bootstrapping
  - `OR` gate with bootstrapping
  - `NOT` gate (no bootstrapping needed)
  - `XOR` gate with bootstrapping
  - `NAND` gate with bootstrapping
  - `NOR` gate with bootstrapping
  - `XNOR` gate with bootstrapping
  - `MUX` (multiplexer) gate with bootstrapping

#### Security Parameters
- 80-bit security parameters (performance-optimized)
- 110-bit security parameters (balanced, original TFHE)
- 128-bit security parameters (high security, default)
- Specialized Uint1 through Uint8 parameters for multi-bit messages

#### Key Management
- Secret key generation with proper noise distributions
- Cloud key generation with bootstrapping keys
- Key serialization support

#### Utilities
- Torus arithmetic operations
- Gaussian noise generation for encryption
- Bit manipulation utilities for multi-bit encryption
- Modular switch operations between encryption levels

#### Examples
- `add_two_numbers`: Complete 16-bit homomorphic addition example
  - Implements full adder circuit with carry propagation
  - Demonstrates XOR, AND, and OR gate composition
  - Benchmarks performance (80 gates, ~30-35 seconds)

#### Documentation
- Comprehensive README with quick start guide
- Inline API documentation for all public modules
- Example documentation with expected outputs
- Performance benchmarking data
- Architecture overview

#### Build System
- `build.zig` with module support for Zig 0.12+
- Test suite covering all core modules
- Example build targets
- Proper dependency management (libc, libm)

#### Testing
- Unit tests for all cryptographic primitives
- Integration tests for homomorphic gates
- Key generation and encryption/decryption tests
- FFT correctness tests
- Bootstrap operation tests

### Infrastructure
- MIT License
- Module-based architecture
- Allocator-based memory management
- Parallel processing framework (foundation)
- CI-ready project structure

### Performance
- Gate operations: ~350-400ms (with bootstrapping)
- Cloud key generation: ~15-20 seconds
- 16-bit addition: ~30-35 seconds (80 gates)

### Known Limitations
- FFT implementation uses baseline algorithm (optimization opportunities exist)
- Batch operations infrastructure present but not yet fully optimized
- No SIMD optimizations yet (AVX, NEON planned for future releases)
- Sequential gate processing (parallelization planned)

[0.1.0]: https://github.com/thedonutfactory/zig-tfhe/releases/tag/v0.1.0

