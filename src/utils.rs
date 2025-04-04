use polynomial_ring::Polynomial;
use std::hash::Hasher;
use rs_sha3_256::{Sha3_256Hasher, HasherContext};
use rs_sha3_512::Sha3_512Hasher;
use rs_shake128::Shake128Hasher;
use rs_shake256::Shake256Hasher;
use num_bigint::BigUint;
use num_traits::Zero;

/// Selects between the bytes in `a` or `b` based on `cond`.
///
/// If `cond` is `false`, returns `a`. If `cond` is `true`, returns `b`.
///
/// # Examples
/// ```
/// use ml_kem::utils::select_bytes;
/// let a = vec![10, 20, 30];
/// let b = vec![100, 110, 120];
///
/// assert_eq!(select_bytes(a.clone(), b.clone(), false), a);
/// assert_eq!(select_bytes(a.clone(), b.clone(), true), b);
/// ```
pub fn select_bytes(a: Vec<u8>, b: Vec<u8>, cond: bool) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Input slices must have the same length");

    let cw = if cond { 0xFF } else { 0x00 };

    a.iter()
        .zip(b.iter())
        .map(|(&a_byte, &b_byte)| a_byte ^ (cw & (a_byte ^ b_byte)))
        .collect()
}

/// function to ensure coefficients are in [0,q-1] after taking remainders
/// # Arguments
/// * `poly` - polynomial to mod
/// * `q` - modulus
/// # Returns
/// `Polynomial<i64>` - polynomial with coefficients in [0,q-1]
pub fn mod_coeffs(poly: Polynomial<i64>, q: i64) -> Polynomial<i64> {
	let coeffs = poly.coeffs();
	let mut new_coeffs = vec![];
	if coeffs.len() == 0 {
		return poly // return original input for the zero polynomial
	} else {
		for i in 0..coeffs.len() {
			new_coeffs.push(coeffs[i].rem_euclid(q));
		}
	}
	Polynomial::new(new_coeffs)
}

/// Add two polynomials
/// # Arguments:
///	* `x` - polynomial to be added
/// * `y` - polynomial to be added.
/// * `q` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns:
///	polynomial in Z_modulus[X]/(f)
pub fn polyadd(x : &Polynomial<i64>, y : &Polynomial<i64>, q : i64, f : &Polynomial<i64>) -> Polynomial<i64> {
	let mut r = x+y;
    r = polyrem(r,f);
    mod_coeffs(r, q)
}

/// Subtract two polynomials
/// # Arguments
///	* `x` - polynomial to be subtracted
/// * `y` - polynomial to be subtracted.
/// * `q` - coefficient modulus.
///	* `f` - polynomial modulus.
/// # Returns
///	polynomial in Z_modulus[X]/(f)
pub fn polysub(x : &Polynomial<i64>, y : &Polynomial<i64>, q: i64, f : &Polynomial<i64>) -> Polynomial<i64> {
	polyadd(x, &polyinv(y, q), q, f)
}

/// Additive inverse of a polynomial
/// # Arguments
///	* `x` - polynomial to be inverted
/// * `q` - coefficient modulus.
/// # Returns
///	polynomial in Z_modulus[X]
pub fn polyinv(x : &Polynomial<i64>, q: i64) -> Polynomial<i64> {
    mod_coeffs(-x, q)
  }

/// Polynomial remainder of x modulo f assuming f=x^n+1
/// # Arguments
/// * `g` - polynomial in Z[X]
///	* `f` - polynomial modulus
/// # Returns
/// polynomial in Z[X]/(f)
pub fn polyrem(g: Polynomial<i64>, f: &Polynomial<i64>) -> Polynomial<i64> {
	let n = f.coeffs().len()-1;
	let mut coeffs = g.coeffs().to_vec();
	if coeffs.len() < n+1 {
		return Polynomial::new(coeffs)
	} else{
		for i in n..coeffs.len() {
			coeffs[i % n] = coeffs[i % n]+(-1 as i64).pow((i/n).try_into().unwrap())*coeffs[i];
		}
		coeffs.resize(n,0);
		Polynomial::new(coeffs)
	}
}

/// Computes the bit-reversal of an unsigned `k`-bit integer `i`.
///
/// The function reverses the order of the `k` least significant bits of `i`.
///
/// # Examples
///
/// ```
/// use ml_kem::utils::bit_reverse;
/// let result = bit_reverse(13, 4); // 13 in 4-bit binary is 1101, reversed -> 1011 (11)
/// assert_eq!(result, 11);
/// ```
pub fn bit_reverse(i: i64, k: usize) -> i64 {
    let mut reversed = 0;
    let mut n = i;
    
    for _ in 0..k {
        reversed = (reversed << 1) | (n & 1);
        n >>= 1;
    }

    reversed
}

/// Sample coefficients of a polynomial (assummed the NTT transformed version) from input bytes
///
/// Algorithm 1 (Parse)
/// https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
/// Algorithm 6 (Sample NTT)
/// Parse: B^* -> R
///
/// # Arguments
///
/// * `input_bytes` - A byte slice containing the input data
/// * `n` - The number of coefficients to sample
///
/// # Returns
///
/// * Vec<u16> - A vector of sampled coefficients
///
/// # Example
/// ```
/// use ml_kem::utils::ntt_sample;
/// let input_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
/// let n = 10;
/// let result = ntt_sample(&input_bytes, n);
/// assert_eq!(result.len(), n); // Ensure the result has the expected length
/// ```
/// # Note
/// The function samples coefficients from the input bytes, ensuring that they are less than 3329, the Kyber prime.
pub fn ntt_sample(input_bytes: &[u8], n: usize) -> Vec<i64> {
    let mut coefficients = vec![0i64; n];
    let mut i = 0;
    let mut j = 0;

    while j < n {
        if i + 2 >= input_bytes.len() {
            break; // Prevent out-of-bounds access
        }

        let d1 = input_bytes[i] as i64 + 256 * (input_bytes[i + 1] as i64 % 16);
        let d2 = (input_bytes[i + 1] as i64 / 16) + 16 * input_bytes[i + 2] as i64;

        if d1 < 3329 {
            coefficients[j] = d1;
            j += 1;
        }

        if d2 < 3329 && j < n {
            coefficients[j] = d2;
            j += 1;
        }

        i += 3;
    }

    coefficients
}


/// Hash function described in 4.4 of FIPS 203 (page 18)
///
/// # Arguments
///
/// * `m` - A variable length vector of bytes
///
/// # Returns
///
/// * Vec<u8> - 32 byte output, the result of applying the sha3_256 hash
///
/// # Example
/// ```
/// use ml_kem::utils::hash_h;
/// let input = vec![0xFF; 8];
/// let result = hash_h(input);
/// assert_eq!(result.len(), 32); // Ensure the result is 32 bytes long
/// ```
pub fn hash_h(m: Vec<u8>) -> Vec<u8> {

    // Apply sha3_256 hash
    let mut sha3_256hasher = Sha3_256Hasher::default();
    sha3_256hasher.write(&m);
    let bytes_result = HasherContext::finish(&mut sha3_256hasher);
    
    bytes_result.as_ref().to_vec() // Return the hashed output
}

/// Hash function described in 4.5 of FIPS 203 (page 18)
///
/// # Arguments
///
/// * `m` - A vector of bytes
///
/// # Returns
///
/// * Vec<u8> - 32 byte output, the result of applying the shake_256 hash
///
/// # Example
/// ```
/// use ml_kem::utils::hash_j;
/// let input = vec![0x01, 0x02, 0x03, 0x04];
/// let result = hash_j(input);
/// assert_eq!(result.len(), 32); // Ensure the result is 32 bytes long
/// ```
pub fn hash_j(m: Vec<u8>) -> Vec<u8> {
	// Apply shake_256 hash
	let mut shake_256hasher = Shake256Hasher::<32>::default();
	shake_256hasher.write(&m);
	let bytes_result = HasherContext::finish(&mut shake_256hasher);
	bytes_result[0..].to_vec()
}

/// Hash function described in 4.4 of FIPS 203 (page 18)
///
/// # Arguments
///
/// * `m` - A vector of bytes
///
/// # Returns
///
/// * (Vec<u8>, Vec<u8>) - 32 byte outputs, the result of applying the sha3_512 hash
///
/// # Example
/// ```
/// use ml_kem::utils::hash_g;
/// let input = vec![0x01, 0x02, 0x03, 0x04];
/// let (output1, output2) = hash_g(input);
/// assert_eq!(output1.len(), 32); // Ensure the first part is 32 bytes long
/// assert_eq!(output2.len(), 32); // Ensure the second part is 32 bytes long
/// ```
pub fn hash_g(m: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
	// Apply sha3_512 hash
	let mut sha3_512hasher = Sha3_512Hasher::default();
	sha3_512hasher.write(&m);
	let bytes_result = HasherContext::finish(&mut sha3_512hasher);
	// Group results
	(bytes_result[..32].to_vec(), bytes_result[32..].to_vec())
}

/// Pseudorandom function described in 4.3 of FIPS 203 (page 18)
/// Uses 128 bytes for the Shake256 hash
///
/// # Arguments
///
/// * `s` - 32 bytes
/// * `b` - A single byte
///
/// # Returns
///
/// * Vec<u8> - 128 byte output, the result of applying the shake_256 hash
///
/// # Example
/// ```
/// use ml_kem::utils::prf_2;
/// let s = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22];
/// let b = 0xFF;
/// let result = prf_2(s, b);
/// assert_eq!(result.len(), 128); // Ensure the result is 128 bytes long
/// ```
pub fn prf_2(s: Vec<u8>, b: u8) -> Vec<u8> {
	// Concatenate s and b
	let mut m = s;
	m.push(b);
	// Apply shake_256 hash
	let mut shake_256hasher = Shake256Hasher::<128>::default();
	shake_256hasher.write(&m);
	let bytes_result = HasherContext::finish(&mut shake_256hasher);
	bytes_result[0..].to_vec()
}

/// Pseudorandom function described in 4.3 of FIPS 203 (page 18)
/// Uses 192 bytes for the Shake256 hash
///
/// # Arguments
///
/// * `s` - 32 bytes
/// * `b` - A single byte
///
/// # Returns
///
/// * Vec<u8> - 192 byte output, the result of applying the shake_256 hash
///
/// # Example
/// ```
/// use ml_kem::utils::prf_3;
/// let s = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22];
/// let b = 0xFF;
/// let result = prf_3(s, b);
/// assert_eq!(result.len(), 192); // Ensure the result is 192 bytes long
/// ```
pub fn prf_3(s: Vec<u8>, b: u8) -> Vec<u8> {
	// Concatenate s and b
	let mut m = s;
	m.push(b);
	// Apply shake_256 hash
	let mut shake_256hasher = Shake256Hasher::<192>::default();
	shake_256hasher.write(&m);
	let bytes_result = HasherContext::finish(&mut shake_256hasher);
	bytes_result[0..].to_vec()
}

/// eXtendable-Output Function (XOF) described in 4.9 of FIPS 203 (page 19)
/// 
/// # Arguments
///
/// * `bytes32` - A 32-byte input
/// * `i` - An 8-bit integer, domain separation parameter
/// * `j` - An 8-bit integer, domain separation parameter
///
/// # Returns
///
/// * Vec<u8> - 840 byte output, the result of applying the shake_128 hash
///
/// # Example
/// ```
/// use ml_kem::utils::xof;
/// let bytes32 = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
/// let i = 0x01;
/// let j = 0x02;
/// let result = xof(bytes32, i, j);
/// assert_eq!(result.len(), 840); // Ensure the result is 840 bytes long
/// ```
pub fn xof(bytes32: Vec<u8>, i: u8, j: u8) -> Vec<u8> {
	// Concatenate bytes32, i, and j
	let mut m = bytes32;
	m.push(i);
	m.push(j);
	// Apply shake_128 hash
	let mut shake_128hasher = Shake128Hasher::<840>::default();
	shake_128hasher.write(&m);
	let bytes_result = HasherContext::finish(&mut shake_128hasher);
	bytes_result[0..].to_vec()
}

/// Generate a random matrix from a seed using xof bytes
/// 
/// # Arguments
/// 
/// * `rho` - seed as vector of bytes
/// * `rank` - the rank of the matrix `k`
/// * `n` - the degree of the polynomial
/// * `transpose` - return tranpose matrix
/// 
/// # Returns 
///
/// * Vec<Vec<Polynomial<i64>>> - a k x k matrix of polynomials in R_q
///
/// # Example
/// ```
/// use ml_kem::utils::generate_matrix_from_seed;
/// let rho = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
/// let rank = 2;
/// let n = 8;
/// let a_hat = generate_matrix_from_seed(rho,rank,n,false);
/// let poly_deg = a_hat[0][0].deg().unwrap_or(0);
/// assert_eq!(poly_deg,n-1)
/// ```
///
/// # Note
/// The sampled polynomials are assumed to be the NTT transformed versions though they are random.
pub fn generate_matrix_from_seed(
    rho: Vec<u8>,
    rank: usize,
	n: usize,
    transpose: bool,
) -> Vec<Vec<Polynomial<i64>>> {
    let mut a_data = vec![vec![Polynomial::new(vec![]); rank]; rank];

    for i in 0..rank {
        for j in 0..rank {
            let xof_bytes = xof(rho.clone(), j as u8, i as u8);
            a_data[i][j] = Polynomial::new(ntt_sample(&xof_bytes, n));
        }
    }

    if transpose {
        module_lwe::utils::transpose(&a_data)
    } else {
        a_data
    }
}

/// Generates a polynomial from bytes via the centered binomial distribution
/// following Algorithm 6 of FIPS 203.
/// 
/// # Arguments
/// 
/// * `input_bytes` - a vector of bytes
/// * `eta` - 2 or 3
/// * `n` - the degree of the polynomial
/// 
/// # Returns 
///
/// * Polynomial<i64> - a polynomial
///
/// # Example
/// ```
/// use ml_kem::utils::cbd;
/// let n = 8;
/// let eta = 3;
/// let input_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
/// let poly = cbd(input_bytes, eta, n);
/// let poly_deg = poly.deg().unwrap_or(0);
/// assert_eq!(poly_deg, n-1); // Ensure the polynomial has the correct degree
/// ```
pub fn cbd(input_bytes: Vec<u8>, eta: usize, n:usize) -> Polynomial<i64> {
	assert_eq!(eta*n/4, input_bytes.len(), "input length must be eta*n/4");
	let mut coefficients = vec![0;n];
	let mut t = BigUint::from_bytes_le(&input_bytes);
	let mask = BigUint::from((1 << eta)-1 as u64);
	let mask2 = BigUint::from((1 << 2*eta)-1 as u64);
	for i in 0..n {
		let x = t.clone() & mask2.clone();
		let a = (x.clone() & mask.clone()).count_ones() as i64;
		let b = ((x.clone() >> eta) & mask.clone()).count_ones() as i64;
		t >>= 2*eta;
		coefficients[i] = a-b;
	}
	Polynomial::new(coefficients)
}

/// Generate a random error vector, an element of a rank k module over R_q
///
/// # Arguments
/// 
/// * `sigma` - the std. deviation for the prf function
/// * `eta` - the upper/lower bound for the centered binomial distribution
/// * `n` - a byte
/// * `poly_size` - the degree of the polynomials
///
/// # Returns
/// 
/// * (Vec<Polynomial<i64>>, u8) - the vector of polynomials and the current byte value `n`
///
/// # Example
/// ```
/// use ml_kem::utils::generate_error_vector;
/// let sigma = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22];
/// let eta = 3;
/// let b = 0x01;
/// let k = 3;
/// let poly_size = 256;
/// let (v,n) = generate_error_vector(sigma,eta,b,k,poly_size);
/// assert_eq!(v.len(),3);
/// ```
pub fn generate_error_vector(
    sigma: Vec<u8>,
    eta: usize,
    b: u8,
    k: usize,
    poly_size: usize,
) -> (Vec<Polynomial<i64>>, u8) {
    let mut elements = vec![Polynomial::new(vec![]); k];
    let mut current_b = b;

    for i in 0..k {
        let prf_output: Vec<u8>;
        if eta == 2 {
            prf_output = prf_2(sigma.clone(), current_b);
        } else if eta == 3 {
            prf_output = prf_3(sigma.clone(), current_b);
        } else {
            panic!("eta must be 2 or 3"); // Handle invalid eta values
        }
		assert_eq!(eta*poly_size/4, prf_output.len(), "eta*poly_size/4 must be 128 or 192 (prf output length)");
        elements[i] = cbd(prf_output, eta, poly_size);
        current_b += 1;
    }

    (elements, current_b)
}

/// Generates a polynomial sampled from the Centered Binomial Distribution (CBD).
///
/// This function derives a pseudo-random byte stream using `prf_3` with the given
/// `sigma` and `n` as input, then maps the output to a polynomial using the CBD function.
///
/// # Arguments
/// 
/// * `sigma` - A vector of bytes serving as a seed for pseudo-random generation.
/// * `eta` - The parameter controlling the shape of the binomial distribution.
/// * `n` - A unique identifier (byte) for domain separation in the PRF.
/// * `poly_size` - The degree of the polynomial.
///
/// # Returns
/// 
/// * A tuple containing:
///   - A `Polynomial<i64>` sampled from the centered binomial distribution.
///   - The updated `n + 1`, ensuring unique PRF inputs across calls.
///
/// # Example
/// ```
/// use ml_kem::utils::generate_polynomial;
///
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
///
/// let (poly, new_n) = generate_polynomial(sigma, eta, n, poly_size, None);
///
/// assert_eq!(new_n, 1);
/// assert_eq!(poly.coeffs().len(), poly_size);
/// ```
///
/// # Notes
/// - `prf_3` produces 192 bytes, and for cbd we require eta*poly_size/4 = 192, the `prf` output length.
/// - The value of `n` should be unique per call to ensure distinct polynomials.
///
/// # Panics
/// - This function panics if `cbd` asserts that the input byte length is incorrect.
pub fn generate_polynomial(
    sigma: Vec<u8>,
    eta: usize,
    b: u8,
    poly_size: usize,
    q: Option<i64>,
) -> (Polynomial<i64>, u8) {
    // get the prf_output depending on eta = 2, or eta = 3
    let prf_output: Vec<u8>;
    if eta == 2 {
        prf_output = prf_2(sigma, b);
    } else if eta == 3 {
        prf_output = prf_3(sigma, b);
    } else {
        panic!("eta must be 2 or 3"); // Handle invalid eta values
    }
    let poly = cbd(prf_output, eta, poly_size); // form the polynomial array from a centered binomial dist.
    //if a modulus is set, place coeffs in [0,q-1]
    if let Some(q) = q {
        return (mod_coeffs(poly,q), b + 1);
    }
    (poly, b + 1)
}

/// Encodes a polynomial into a byte vector based on the FIPS 203 standard (Algorithm 3, inverse).
/// This function shifts and ORs the polynomial coefficients into an integer, then serializes the integer
/// into a byte array.
///
/// # Arguments
/// * `poly` - A reference to the `Polynomial<i64>` that needs to be encoded.
/// * `d` - The bit-width parameter for the encoding process. Typically 12 for some cryptographic algorithms.
///
/// # Returns
/// * `Vec<u8>` - The resulting encoded byte vector representing the polynomial.
///
/// # Example
/// ```
/// use polynomial_ring::Polynomial;
/// use ml_kem::utils::{generate_polynomial,encode_poly};
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (poly, new_n) = generate_polynomial(sigma, eta, n, poly_size, None);
/// let encoded = encode_poly(&poly, 12);
/// assert_eq!(encoded.len(), 384); // 32 * d (d = 12)
/// ```
pub fn encode_poly(poly: &Polynomial<i64>, d: usize) -> Vec<u8> {
    let poly_mod = mod_coeffs(poly.clone(), 3329);
	let mut t = BigUint::zero(); // Start with a BigUint initialized to zero
    let mut coeffs = poly_mod.coeffs().to_vec(); // get the coefficients of the polynomial
    coeffs.resize(256, 0); // ensure they're the right size

    for i in 0..255 {
        // OR the current coefficient then left shift by d bits
        t |= BigUint::from(coeffs[256 - i - 1] as u64); // Use BigUint for coefficients
        t <<= d; // Equivalent to t = t * 2^d
    }

    // Add the last coefficient
    t |= BigUint::from(coeffs[0] as u64);

    // Convert BigUint to a byte vector
    let byte_len = 32 * d;
    let mut result = t.to_bytes_le(); // Convert to little-endian bytes
    result.resize(byte_len, 0); // Ensure the result is exactly `32 * d` bytes

    result
}

/// Decodes a byte vector into a polynomial based on the FIPS 203 standard (Algorithm 3).
///
/// # Arguments
/// * `input_bytes` - The bytes to be decoded.
/// * `d` - The bit-width parameter for the encoding process. Typically 12 for some cryptographic algorithms.
///
/// # Returns
/// * `Polynomial<i64>` - The resulting polynomial.
///
/// # Example
/// ```
/// use polynomial_ring::Polynomial;
/// use ml_kem::utils::{generate_polynomial,encode_poly,decode_poly};
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (poly, new_n) = generate_polynomial(sigma, eta, n, poly_size, Some(3329));
/// let encoded = encode_poly(&poly, 12);
/// let decoded = decode_poly(encoded, 12);
/// assert_eq!(poly, decoded);
/// ```
pub fn decode_poly(input_bytes: Vec<u8>, d: usize) -> Polynomial<i64> {
	assert_eq!(256*d, input_bytes.len()*8, "256*d must be length of input bytes times 8");
	// Set the modulus
	let mut m = 3329;
	if d < 12 {
		m = 1 << d;
	}
	
	let mut coeffs = vec![0; 256];
	let mut b_int = BigUint::from_bytes_le(&input_bytes);
	let mask = BigUint::from((1 << d) - 1 as u64);
	// Form bits from big unsigned integer into integer coefficients
	for i in 0..256 {
		let bits_vec = (b_int.clone() & mask.clone()).to_u64_digits();
		if bits_vec.len() > 0 {
			coeffs[i] = bits_vec[0] as i64 % m;
		}
		b_int >>= d; // Right shift d bits
	}
	Polynomial::new(coeffs)
}

/// Encodes a vector of polynomials into a single vector of bytes.
/// This function uses `encode_polynomial` on each polynomial and concatenates
/// the resulting byte arrays into one `Vec<u8>`.
///
/// # Arguments
/// * `polys` - A reference to a `Vec<Polynomial<i64>>` that contains the polynomials to be encoded.
/// * `d` - The bit-width parameter for the encoding process. Typically 12 for some cryptographic algorithms.
///
/// # Returns
/// * `Vec<u8>` - A single vector containing all the encoded polynomials.
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,encode_vector};
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (p0, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, None);
/// let (p1, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, None);
/// let polys = vec![p0, p1];
/// let encoded_bytes = encode_vector(&polys, 12);
/// assert_eq!(encoded_bytes.len(), 768);  // Total length after encoding two polynomials
/// ```
pub fn encode_vector(v: &Vec<Polynomial<i64>>, d: usize) -> Vec<u8> {
    let mut encoded_bytes = Vec::new();
    for poly in v {
        let encoded_poly = encode_poly(poly, d);
        encoded_bytes.extend(encoded_poly);  // Append each encoded polynomial's bytes
    }
    encoded_bytes
}

/// Decodes a byte vector into a vector of polynomials.
///
/// # Arguments
/// * `input_bytes` - The bytes to be decoded.
/// * `d` - The bit-width parameter for the encoding process. Typically 12 for some cryptographic algorithms.
///
/// # Returns
/// * `Vec<Polynomial<i64>>` - The resulting vector of polynomials.
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,encode_vector,decode_vector};
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (p0, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let (p1, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let polys = vec![p0, p1];
/// let encoded_bytes = encode_vector(&polys, 12);
/// let decoded = decode_vector(&encoded_bytes, 2, 12);
/// assert_eq!(polys, decoded);
/// ```
pub fn decode_vector(input_bytes: &Vec<u8>, k: usize, d: usize) -> Vec<Polynomial<i64>> {
	assert_eq!(256*d*k, input_bytes.len()*8, "256*d*k must be length of input bytes times 8");	
	let mut v = vec![Polynomial::new(vec![]); k];
	for i in 0..k {
		v[i] = decode_poly(input_bytes[i*32*d..i*32*d+32*d].to_vec(), d);
	}
	v
}


/// Compute round((2^d / q) * x) % 2^d
///
/// # Arguments
/// * `x` - int to be compressed
/// * `d` - int specifying compression type
///
/// # Returns
/// * `i64` - compressed integer
fn compress_ele(x: i64, d: usize) -> i64 {
    let t = 1 << d;
    let y = (t * x.rem_euclid(3329) + 1664) / 3329; // n.b. 1664 = 3329 / 2
    y % t
}


/// Compute round((q / 2^d) * x)
///
/// # Arguments
/// * `x` - int to be compressed
/// * `d` - int specifying compression type
///
/// # Returns
/// * `i64` - compressed integer
fn decompress_ele(x: i64, d: usize) -> i64 {
    let t = 1 << (d - 1);
    (3329 * x + t) >> d
}

/// Compress the polynomial by compressing each coefficient
///
/// # Arguments
/// * `poly` - polynomial to compress
/// * `d` - integer to specify compression type
///
/// # Returns
/// * `Polynomial<i64>` - a decompressed polynomial
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,compress_poly};
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (poly, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let compressed_poly = compress_poly(&poly,12);
/// assert_eq!(compressed_poly.coeffs().len(), poly.coeffs().len());
/// ```
///
/// # Notes
/// - This is lossy compression
pub fn compress_poly(poly: &Polynomial<i64>, d: usize) -> Polynomial<i64> {
    let compressed_coeffs: Vec<i64> = poly.coeffs().iter().map(|&c| compress_ele(c, d)).collect();
    Polynomial::new(compressed_coeffs)
}

/// compress each polynomial in a vector of polynomials
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,compress_vec};
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (p0, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let (p1, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let v = vec![p0, p1];
/// compress_vec(&v, 12);
/// ```
pub fn compress_vec(v: &Vec<Polynomial<i64>>, d: usize) -> Vec<Polynomial<i64>> {
    v.iter().map(|poly| compress_poly(poly, d)).collect()
}

/// compress each polynomial in a vector of polynomials
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,compress_vec,decompress_vec};
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (p0, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let (p1, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let v = vec![p0, p1];
/// let compress_v = compress_vec(&v, 12);
/// let recovered_v = decompress_vec(&compress_v,12);
/// assert_eq!(v,recovered_v);
/// ```
pub fn decompress_vec(v: &Vec<Polynomial<i64>>, d: usize) -> Vec<Polynomial<i64>> {
    v.iter().map(|poly| decompress_poly(poly, d)).collect()
}


/// Decompress the polynomial by decompressing each coefficient
/// 
/// # Arguments
/// * `poly` - polynomial to compress
/// * `d` - integer to specify compression type
///
/// # Returns
/// * `Polynomial<i64>` - a decompressed polynomial
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial,compress_poly,decompress_poly};
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (poly, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, Some(3329));
/// let compressed_poly = compress_poly(&poly,12);
/// assert_eq!(compressed_poly.coeffs().len(), poly.coeffs().len());
/// let poly_recovered = decompress_poly(&compressed_poly,12);
/// assert_eq!(poly,poly_recovered);
/// ```
///
/// # Notes 
/// - This as compression is lossy, we have
/// x' = decompress(compress(x)), which x' != x, but is
/// close in magnitude.
pub fn decompress_poly(poly: &Polynomial<i64>, d: usize) -> Polynomial<i64> {
    let decompressed_coeffs: Vec<i64> = poly.coeffs().iter().map(|&c| decompress_ele(c, d)).collect();
    Polynomial::new(decompressed_coeffs)
}

/// Applies the Number Theoretic Transform (NTT) to each polynomial in a vector.
///
/// This function takes a vector of polynomials, converts their coefficient slices 
/// into owned `Vec<i64>` values, ensures they have a uniform length of `n` by 
/// padding with zeros if necessary, and then applies the NTT to each polynomial.
///
/// # Arguments
///
/// * `v` - A reference to a vector of `Polynomial<i64>`, representing the input polynomials.
/// * `zetas` - The powers of roots of unity used for the NTT.
///
/// # Returns
///
/// A vector of `Polynomial<i64>` where each polynomial has been transformed using NTT.
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial, vec_ntt};
/// use ml_kem::parameters::Parameters;
/// let params = Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let b = 0;
/// let n = 256;
/// let q = 3329;
/// let (p0, _b) = generate_polynomial(sigma.clone(), eta, b, n, Some(q));
/// let (p1, _b) = generate_polynomial(sigma.clone(), eta, b, n, Some(q));
/// let v = vec![p0, p1];
/// vec_ntt(&v, params.zetas);
/// ```
pub fn vec_ntt(v: &Vec<Polynomial<i64>>, zetas: Vec<i64>) -> Vec<Polynomial<i64>> {
    v.iter()
        .map(|poly| poly_ntt(poly, zetas.clone())) // Clone `zetas` for each polynomial
        .collect()
}

/// Applies the inverse Number Theoretic Transform (iNTT) to each polynomial in a vector.
///
/// This function takes a vector of polynomials, converts their coefficient slices 
/// into owned `Vec<i64>` values, ensures they have a uniform length of `n` by 
/// padding with zeros if necessary, and then applies the NTT to each polynomial.
///
/// # Arguments
///
/// * `v` - A reference to a vector of `Polynomial<i64>`, representing the input polynomials.
/// * `zetas` - The powers of roots of unity used for the NTT.
///
/// # Returns
///
/// A vector of `Polynomial<i64>` where each polynomial has been transformed using NTT.
///
/// # Example
/// ```
/// use ml_kem::utils::{generate_polynomial, vec_ntt, vec_intt};
/// use ml_kem::parameters::Parameters;
/// let params = Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let eta = 3;
/// let b = 0;
/// let n = 256;
/// let q = 3329;
/// let (p0, _b) = generate_polynomial(sigma.clone(), eta, b, n, Some(q));
/// let (p1, _b) = generate_polynomial(sigma.clone(), eta, b, n, Some(q));
/// let v = vec![p0, p1];
/// let v_ntt = vec_ntt(&v, params.zetas.clone());
/// let v_recovered = vec_intt(&v_ntt, params.zetas.clone());
/// assert_eq!(v, v_recovered);
/// ```
pub fn vec_intt(v: &Vec<Polynomial<i64>>, zetas: Vec<i64>) -> Vec<Polynomial<i64>> {
    v.iter()
        .map(|poly| poly_intt(poly, zetas.clone())) // Clone `zetas` for each polynomial
        .collect()
}

/// Computes the Number Theoretic Transform (NTT) of a polynomial in Z_q[x]/(x^n+1).
///
/// The NTT is a specialized version of the Discrete Fourier Transform (DFT) 
/// that operates in a finite field. It is used to accelerate polynomial 
/// multiplication in cryptographic schemes.
///
/// # Arguments
/// * `poly` - A reference to the input polynomial.
/// * `zetas` - Precomputed root of unity powers.
///
/// # Returns
/// * A new `Polynomial<i64>` representing the NTT-transformed coefficients.
///
/// # Examples
/// ```
/// use ml_kem::utils::{generate_polynomial,poly_ntt};
/// use ml_kem::parameters::Parameters;
/// let params = Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let b = 0;
/// let (poly, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// poly_ntt(&poly, params.zetas);
/// ```
pub fn poly_ntt(poly: &Polynomial<i64>, zetas: Vec<i64>) -> Polynomial<i64> {
    let mut coeffs = poly.coeffs().to_vec(); // Convert slice to Vec<i64>
	coeffs.resize(256, 0); // Ensure uniform length
    let mut k = 1;
	let mut l = 128;
	while l >= 2 {
		let mut start = 0;
		while start < 256 {
			let zeta = zetas[k];
			k += 1;
			for j in start..start+l {
				let t = zeta*coeffs[j+l];
				coeffs[j+l] = (coeffs[j]-t).rem_euclid(3329);
				coeffs[j] = (coeffs[j]+t).rem_euclid(3329);
			}
			start += 2*l;
		}
		l >>= 1;
	}
	Polynomial::new(coeffs)
}

/// Computes the inverse Number Theoretic Transform (INTT) of a polynomial in Z_q[x]/(x^n+1).
///
/// The INTT reverses the NTT operation, recovering the original polynomial 
/// coefficients after an NTT transformation and pointwise multiplication. 
/// This is crucial for polynomial multiplication in NTT-based cryptographic protocols.
///
/// # Arguments
/// * `poly` - A reference to the input polynomial in the NTT domain.
/// * `zetas` - Precomputed root of unity powers.
///
/// # Returns
/// * A new `Polynomial<i64>` representing the inverse-transformed coefficients.
///
/// # Examples
/// ```
/// use ml_kem::utils::{generate_polynomial,poly_ntt,poly_intt};
/// let params = ml_kem::parameters::Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let b = 0;
/// let (poly, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let poly_ntt_forward = poly_ntt(&poly, params.zetas.clone());
/// let poly_recovered = poly_intt(&poly_ntt_forward, params.zetas.clone());
/// assert_eq!(poly,poly_recovered);
/// ```
pub fn poly_intt(poly: &Polynomial<i64>, zetas: Vec<i64>) -> Polynomial<i64> {
    let mut coeffs = poly.coeffs().to_vec(); // Convert slice to Vec<i64>
    coeffs.resize(256, 0); // Ensure uniform length
    let mut l = 2;
	let mut k = 127;
	while l <= 128 {
		let mut start = 0;
		while start < 256 {
			let zeta = zetas[k];
			k = k-1;
			for j in start..start+l {
				let t = coeffs[j];
				coeffs[j] = (t+coeffs[j+l]).rem_euclid(3329);
				coeffs[j+l] = (zeta*(coeffs[j+l]-t)).rem_euclid(3329);
			}
			start += 2*l;
		}
		l <<= 1;
	}
	for j in 0..256 {
		coeffs[j] = (coeffs[j]*3303).rem_euclid(3329); //3303 is 128^-1 mod 3329
	
	}
	Polynomial::new(coeffs)
}

/// Multiplies two elements in Z_q[x]/(x^2-zeta).
/// The NTT space is a direct product of 128 such rings.
///
/// # Arguments
/// * `a0` - a0+a1*x is one factor.
/// * `a1`
/// * `b0` - b0+b1*x is the other factor.
/// * `b1`
/// * `zeta` - x^2-zeta is the modulus of the ring.
///
/// # Returns
/// * (r0: i64, r1: i64) - r0+r1*x is the product in Z_q[x]/(x^2-zeta).
pub fn ntt_base_multiplication(a0:i64 , a1:i64, b0:i64, b1:i64, zeta:i64) -> (i64, i64) {
	let r0 = (a0*b0+zeta*a1*b1).rem_euclid(3329);
	let r1 = (a1*b0+a0*b1).rem_euclid(3329);
	(r0, r1)
}

/// Multiplies two elements of the NTT space to produce another element of the NTT space.
///
/// # Arguments
/// * `f` - One NTT polynomial to be multiplied.
/// * `g` - The other NTT polynomial to be multiplied.
/// * `zetas` - Precomputed root of unity powers.
///
/// # Returns
/// * Polynomial<i64> - The product in the NTT space.
pub fn ntt_coefficient_multiplication(f_coeffs: Vec<i64>, g_coeffs: Vec<i64>, zetas: Vec<i64>) -> Vec<i64> {
	let mut new_coeffs = vec![];
	// Multiply in each of the 128 Z_q[x]/(x^2-zeta) factors
	for i in 0..64 {
		let (r0,r1) = ntt_base_multiplication(
			f_coeffs[4*i+0],
			f_coeffs[4*i+1],
			g_coeffs[4*i+0],
			g_coeffs[4*i+1],
			zetas[64+i]);
		let (r2,r3) = ntt_base_multiplication(
			f_coeffs[4*i+2],
			f_coeffs[4*i+3],
			g_coeffs[4*i+2],
			g_coeffs[4*i+3],
			-zetas[64+i]);
		new_coeffs.append(&mut vec![r0,r1,r2,r3]);
	}
	new_coeffs
}

/// perform the multiplication of two polynomials which are in the NTT domain
/// 
/// # Arguments
/// * `f` - first polynomial
/// * `g` - second polynomial
/// * `zetas` - powers of roots of unity for NTT
///
/// # Returns
/// * `Polynomial<i64> - the product f x g in the NTT domain
///
/// # Examples
/// ```
/// use ml_kem::utils::{mod_coeffs,generate_polynomial,poly_ntt, poly_intt, ntt_multiplication};
/// use ring_lwe::utils::polymul;
/// let params = ml_kem::parameters::Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let b = 0;
/// let (p0, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let (p1, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let p0_p1 = mod_coeffs(polymul(&p0, &p1, 3329, &params.f), 3329);
/// let p0_ntt = poly_ntt(&p0, params.zetas.clone());
/// let p1_ntt = poly_ntt(&p1, params.zetas.clone());
/// let p0_ntt_p1_ntt = ntt_multiplication(p0_ntt, p1_ntt, params.zetas.clone());
/// let p0_p1_recovered = poly_intt(&p0_ntt_p1_ntt, params.zetas.clone());
/// assert_eq!(p0_p1, p0_p1_recovered);
/// ```
pub fn ntt_multiplication(f: Polynomial<i64>, g: Polynomial<i64>, zetas: Vec<i64>) -> Polynomial<i64> {
	
	let mut f_coeffs = f.coeffs().to_vec();
	let mut g_coeffs = g.coeffs().to_vec();
	f_coeffs.resize(256,0);
	g_coeffs.resize(256,0); 
	let new_coeffs = ntt_coefficient_multiplication(f_coeffs, g_coeffs, zetas);
	Polynomial::new(new_coeffs)
}

/// add two vectors of polynomials
/// # Arguments
/// * `v0` - vector of polynomials
/// * `v1` - vector of polynomials
/// * `q` - modulus
/// * `f` - polynomial modulus
/// # Returns
/// * `result` - vector of polynomials
pub fn add_vec(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, q: i64, f: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
	assert!(v0.len() == v1.len());
	let mut result = vec![];
	for i in 0..v0.len() {
		result.push(polyadd(&v0[i], &v1[i], q, &f));
	}
	result
}

/// take the dot product of two vectors of polynomials
/// # Arguments
/// * `v0` - vector of polynomials
/// * `v1` - vector of polynomials
/// * `modulus` - modulus
/// * `poly_mod` - polynomial modulus
/// * `zetas` - powers of roots of unity for NTT
/// # Returns
/// * `result` - polynomial
/// 
/// # Examples
/// ```
/// use ml_kem::utils::{generate_polynomial,mul_vec_simple};
/// let params = ml_kem::parameters::Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let b = 0;
/// let (p0, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let (p1, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let (p2, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let (p3, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let v0 = vec![p0, p1];
/// let v1 = vec![p2, p3];
/// let v0_dot_v1 = mul_vec_simple(&v0,&v1,params.q, &params.f, params.zetas.clone());
/// assert_eq!(v0_dot_v1.coeffs().len(), params.n);
/// ```
pub fn mul_vec_simple(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, q: i64, f: &Polynomial<i64>, zetas: Vec<i64>) -> Polynomial<i64> {
	assert!(v0.len() == v1.len());
	let mut result = Polynomial::new(vec![]);
	for i in 0..v0.len() {
		result = polyadd(&result, &ntt_multiplication(v0[i].clone(), v1[i].clone(), zetas.clone()), q, &f);
	}
	mod_coeffs(result, q)
}

/// multiply a matrix by a vector of polynomials
/// # Arguments
/// * `m` - matrix of polynomials
/// * `v` - vector of polynomials
/// * `modulus` - modulus
/// * `poly_mod` - polynomial modulus
/// * `zetas` - powers of roots of unity for NTT
/// # Returns
/// * `result` - vector of polynomials
/// # Examples
/// ```
/// use ml_kem::utils::{generate_polynomial,mul_vec_simple,generate_matrix_from_seed,mul_mat_vec_simple};
/// let params = ml_kem::parameters::Parameters::mlkem512();
/// let sigma = vec![0u8; 32];
/// let b = 0;
/// let (p0, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let (p1, _b) = generate_polynomial(sigma.clone(), params.eta_1, b, params.n, Some(3329));
/// let v0 = vec![p0, p1];
/// let rho = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
/// let rank = 2;
/// let a_hat = generate_matrix_from_seed(rho,rank,params.n,false);
/// let v = mul_mat_vec_simple(&a_hat, &v0, params.q, &params.f, params.zetas.clone());
/// ```
pub fn mul_mat_vec_simple(m: &Vec<Vec<Polynomial<i64>>>, v: &Vec<Polynomial<i64>>, q: i64, f: &Polynomial<i64>, zetas: Vec<i64>) -> Vec<Polynomial<i64>> {
	
	let mut result = vec![];
	for i in 0..m.len() {
		result.push(mul_vec_simple(&m[i], &v, q, &f, zetas.clone()));
	}
	result
}