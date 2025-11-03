# Changelog

All notable changes to zig-tfhe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-03

### Added
- **Proxy Reencryption Module** (`proxy_reenc.zig`) - LWE-based proxy reencryption for secure delegation
  - `PublicKeyLv0` - LWE public key encryption support
  - `ProxyReencryptionKey` - Dual-mode reencryption keys (asymmetric/symmetric)
  - `reencryptTLWELv0()` - Transform ciphertexts between keys without decryption
- **Asymmetric Mode** (Recommended):
  - Generate reencryption keys using delegatee's public key only
  - No secret key sharing required
  - True proxy reencryption with 128-bit security
- **Symmetric Mode** (Trusted scenarios):
  - Fast key generation for single-party key rotation
  - Backward compatibility option
- **Example Program**: `proxy_reencryption_demo.zig`
  - Demonstrates asymmetric proxy reencryption workflow
  - Multi-hop chain example (Alice → Bob → Carol)
  - Performance metrics and security notes
- **Build Integration**: `zig build proxy_reenc_demo` command
- **Documentation**:
  - `PROXY_REENC.md` - Comprehensive usage guide
  - Module-level documentation with examples
  - API reference for all public types

### Performance
- **Public key generation**: ~1.6ms (4.4x faster than Rust)
- **Asymmetric keygen**: ~1.7s (4.5x faster than Rust)
- **Symmetric keygen**: ~20ms (4.5x faster than Rust)
- **Reencryption**: ~1.1ms (2.3x faster than Rust)
- **Accuracy**: 100% with multi-hop chains
- **Security**: 128-bit post-quantum resistant

### Testing
- 6 new unit tests for proxy reencryption (all passing)
- Total test suite: 86/86 tests passing
- Verified memory leak-free with allocator tracking
- Tested multi-hop chains up to 3 parties

### Security
- Based on Learning With Errors (LWE) hardness assumption
- Quantum-resistant by design
- Unidirectional delegation (Alice→Bob ≠ Bob→Alice)
- Proxy learns nothing about plaintext
- 128-bit security level maintained

### Notes
- **Breaking**: None - purely additive feature
- **Compatibility**: Zig 0.14+ required
- **Dependencies**: No new dependencies
- Port of rs-tfhe v0.2.0 proxy reencryption feature

## [0.1.1] - 2025-10-25

### Added
- SIMD vectorization for TLWE operations (`add`, `sub`, `neg`, `mul`, `addMul`, `subMul`)
- SIMD vectorization for TRGSW complex FMA operations
- SIMD vectorization for FFT operations (`ifft1024`, `fft1024`, `poly_mul`)
- Comprehensive optimization documentation:
  - `SIMD_OPTIMIZATION_RESULTS.md`
  - `FFT_SIMD_OPTIMIZATION_RESULTS.md`
  - `SIMD_VERIFICATION.md`
  - `PROFILING_RESULTS.md`
  - `PROFILING_SUMMARY.md`

### Changed
- **[BREAKING]** Renamed `parallel.rayon_impl` module to `parallel.thread_pool`
- **[BREAKING]** Renamed `parallel.RayonRailgun` type to `parallel.ThreadPool`
- **[BREAKING]** Renamed `parallel.rayonRailgun()` function to `parallel.threadPool()`
- Improved build configuration to ensure optimization flags propagate correctly

### Fixed
- Fixed test memory management errors (incorrect `defer free()` on stack arrays)
- Fixed formatting issues in source files
- Fixed build system to not reference temporary profiling tools

### Performance
- 4.8% overall performance improvement
- Bootstrap time: 38.08 ms → 36.73 ms (3.5% faster)
- Per-gate time: 39.20 ms → 37.31 ms (4.8% faster)
- 80-gate test: 3107 ms → 2985 ms (122 ms saved)
- Closed Rust performance gap from 2.62x to 2.51x (4.2% improvement)

### Removed
- Temporary bootstrap profiler tool
- `zig build bootstrap-profile` build step

## [0.1.0] - 2025-10-XX

### Added
- Initial release of zig-tfhe
- Core TFHE functionality (TLWE, TRLWE, TRGSW)
- Bootstrap operations (vanilla strategy)
- Homomorphic logic gates (AND, OR, XOR, NAND, NOR, XNOR)
- Key generation (SecretKey, CloudKey)
- FFT implementation for efficient polynomial operations
- Parallel processing support using thread pools
- Example: `add_two_numbers` demonstrating homomorphic addition
- Comprehensive test suite
- Build system with Zig build

[0.1.1]: https://github.com/yourusername/zig-tfhe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/yourusername/zig-tfhe/releases/tag/v0.1.0
