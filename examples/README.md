# Zig-TFHE Examples

This directory contains examples demonstrating how to use the Zig-TFHE library for fully homomorphic encryption.

## Examples

### add_two_numbers

Demonstrates homomorphic integer addition by implementing a full adder circuit that adds two 16-bit numbers (402 + 304 = 706) without decrypting them.

**Run the example:**
```bash
zig build add_two_numbers -Doptimize=ReleaseFast -Dcpu=native
```

**What it demonstrates:**
- Key generation (SecretKey and CloudKey)
- Encrypting integer values as bit arrays
- Building a full adder circuit using homomorphic XOR, AND, and OR gates
- Performing computation on encrypted data
- Decrypting the result and verifying correctness

**Expected output:**
```
=== TFHE Add Two Numbers Example ===

Generating keys (this may take a moment)...
Keys generated successfully!

Plaintext inputs:
  A = 402
  B = 304
  Expected sum = 706

Encrypting inputs...
Inputs encrypted successfully!

Computing encrypted addition (this will take a while)...
Computation complete!
  Total time: ~30000 ms
  Per gate: ~377 ms
  Total gates: 80

Decrypting result...

Results:
  Computed sum = 706
  Carry out = false
  Expected sum = 706

✓ Success! Homomorphic addition computed correctly.
```

**Performance notes:**
- Each full adder uses 5 homomorphic gates (2 XOR, 2 AND, 1 OR)
- For 16-bit addition: 16 full adders × 5 gates = 80 total gates
- Each gate requires bootstrapping, which takes ~350-400ms
- Total computation time: ~30-35 seconds for 16-bit addition

## Building All Examples

To build all examples at once:
```bash
zig build
```

To list all available build targets:
```bash
zig build --help
```

