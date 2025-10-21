# Zig-TFHE Examples

This directory contains examples demonstrating how to use the Zig-TFHE library.

## Available Examples

### `add_two_numbers.zig`

A basic example that demonstrates homomorphic addition of two 16-bit numbers using fully homomorphic encryption.

**What it does:**
- Encrypts two numbers (402 and 304) bit-by-bit
- Performs homomorphic addition using a ripple-carry adder circuit
- Each bit addition uses a full adder implemented with homomorphic gates (AND, OR, XOR)
- Decrypts the result

**How to run:**
```bash
zig build example
```

**Expected output:**
```
per gate: ~400-500 ms
total: ~30-40 seconds
Carry: [true/false]
A: 402
B: 304
sum: [result]
Expected: 706
Result matches: [true/false]
```

**Note:** Due to the probabilistic nature of TFHE and noise accumulation, the result may not always be exactly correct. This is expected behavior for homomorphic encryption systems, especially with complex circuits like multi-bit addition.

## Implementation Details

The `add_two_numbers` example mirrors the functionality of the Rust version (`rs-tfhe/examples/add_two_numbers.rs`) and demonstrates:

1. **Key Generation**: Creating secret and cloud keys
2. **Encryption**: Converting plaintext bits to TLWE ciphertexts
3. **Homomorphic Operations**: 
   - Full adder circuit (XOR, AND, OR gates)
   - Ripple-carry adder for multi-bit addition
4. **Decryption**: Converting ciphertexts back to plaintext
5. **Performance Measurement**: Timing per-gate and total execution

## Performance Characteristics

- **Per-gate latency**: ~400-500ms per homomorphic gate operation
- **Total for 16-bit addition**: ~30-40 seconds (80 gate operations: 16 bits × 5 gates per full adder)
- These timings are for the vanilla bootstrap strategy on a typical CPU

## Building Custom Examples

To create your own example:

1. Create a new `.zig` file in the `examples/` directory
2. Import the TFHE library: `const tfhe = @import("tfhe");`
3. Add your example to `build.zig` following the pattern for `add_two_numbers`
4. Run with `zig build your_example_name`

## Module Structure

The TFHE library exports the following modules:
- `tfhe.params` - Security parameters and constants
- `tfhe.utils` - Utility functions (conversions, noise generation)
- `tfhe.key` - Key generation and management
- `tfhe.tlwe` - TLWE ciphertext operations
- `tfhe.trlwe` - TRLWE ciphertext operations
- `tfhe.trgsw` - TRGSW ciphertext operations
- `tfhe.gates` - Homomorphic logic gates
- `tfhe.bootstrap` - Bootstrapping strategies
- `tfhe.lut` - Lookup table operations
- `tfhe.parallel` - Parallel processing utilities

