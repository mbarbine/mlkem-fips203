# mlkem-fips203

![example workflow](https://github.com/lattice-based-cryptography/ml-kem/actions/workflows/basic.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/mlkem-fips203.svg)](https://crates.io/crates/mlkem-fips203)

### Description

Rust implementation of module-lattice key encapsulation mechanism (ML-KEM) as specified in FIPS 203. Includes all parameters sets (MLKEM512, MLKEM768, MLKEM1024).

### FIPS 203

NIST post-quantum cryptography standard finalized on Aug. 13th, 2022(?): https://csrc.nist.gov/pubs/fips/203/final

### Disclaimer

This is not secure. It is not written in constant-time nor resistant to other side-channel attacks. This is intended for educational use and not for real-world applications.

### Usage

 In the `src` directory,

`cargo build`

To build the binary.

`cargo test`

- Performs `keygen`, `encrypt`, `decrypt` for a test message.
- Performs `keygen`, `encaps`, `decaps` to encapsulate and decapsulate keys.
- Sets the DRBG seed and generates random bytes using DRBG.
- Runs doctests for every public function.

`cargo bench`

Runs the three benchmarks for `keygen`, `encaps`, `decaps`.

`cargo run`

Runs the main file which performs a basic PKE `keygen`, `encrypt`, `decrypt` for a random message, and `keygen`, `encaps`, `decaps`.

### Parameters

A global parameter `q=3329`, the Kyber prime, is set. The polynomial size is set to `n=256`. We work over the ring `R_q = Z_q[x]/(x^n+1)`.

### MLKEM Parameter Comparison  

| params     | k  | eta_1 | eta_2 | d_u | d_v |  
|------------|----|-------|-------|-----|-----|  
| **MLKEM512**  | 2  | 3     | 2     | 10  | 4   |  
| **MLKEM768**  | 3  | 2     | 2     | 10  | 4   |  
| **MLKEM1024** | 4  | 2     | 2     | 11  | 5   |  

#### Parameter Descriptions:

- **k**: Module rank  
- **eta_1, eta_2**: Control the `cbd` width (centered binomial distribution) for randomness  
- **d_u, d_v**: Compression & encoding parameters

### NTT

We briefly note that this implementation uses a specialized NTT which does not require a `512`th root of unity (which does not exist in `Z_q` since 512 does not divide `3328`). 

On pg. 24 of the FIPS 203 standard paper, they describe that one may use the Chinese remainder theorem to write the ring R_q as a sum of `128` quadratic factors. This ring `T_q` is isomorphic to `R_q`, but we can perform the NTT with only a `256`th root of unity by pairing coefficients.

### Passing by reference

On pg. 6 of the FIPS 203 paper, they note that there is no "passing by reference". We only use cloning when we need to copy values to pass as parameters.

### Polynomials

We use the `Polynomial<i64>` type. This is not ideal (pun intended), and could be replaced by a custom type which implements the many polynomial methods we use in `utils.rs`.

### Example

```
use mlkem_fips203::ml_kem::MLKEM;
use mlkem_fips203::parameters::Parameters;

// run the basic keygen/encaps/decaps
let (ek, dk) = mlkem.keygen(); // Generate public and private keys for KEM
let (shared_k,c) = match mlkem.encaps(ek) { // encapsulate the shared key, handling potential errors
    Ok(ciphertext) => ciphertext,
    Err(e) => panic!("Encryption failed: {}", e),
};
let shared_k_decaps = match mlkem.decaps(dk,c) { // decapsulate the shared key, handling potential errors
    Ok(decapsulated_shared_key) => decapsulated_shared_key,
    Err(e) => panic!("Decryption failed: {}", e),
 };
 assert_eq!(shared_k, shared_k_decaps); // check if the decapsulated shared key matches the original shared key
```

### Error handling

As specified in FIPS 203, we handle errors for both `encaps` and `decaps`. We use a `Result<T,E>` return type.

### Benchmarks

All benchmarks were averaged over at least 100 runs using the `criterion` benchmarking crate.

 MLKEM | keygen    | encaps    | decaps    |
-------|-----------|-----------|-----------|
 512   | 239.00 µs | 362.94 µs | 513.25 µs |
 768   | 394.09 µs | 528.75 µs | 745.37 µs |
 1024  | 526.46 µs | 711.49 ms | 987.81 µs |
