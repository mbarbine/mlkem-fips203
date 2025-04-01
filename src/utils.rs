use polynomial_ring::Polynomial;
use std::hash::Hasher;
use rs_sha3_256::{Sha3_256Hasher, HasherContext};
use rs_sha3_512::Sha3_512Hasher;
use rs_shake128::Shake128Hasher;
use rs_shake256::Shake256Hasher;
use getrandom::getrandom;
use aes_ctr_drbg::DrbgCtx;
use ntt::ntt;
use num_bigint::BigUint;
use num_traits::Zero;


/// default parameters for module-LWE
pub struct Parameters {
	/// degree of the polynomials
    pub n: usize,
	/// Ciphertext modulus
    pub q: i64,
	/// Module rank	
    pub k: usize,
	/// centered binomial distribution width
	pub eta_1: usize,
	/// centered binomial distribution width
	pub eta_2: usize,
	/// du
	pub du: usize,
	/// dv
	pub dv: usize,
    /// Standard deviation of the error
    pub sigma: f64,
	/// 2n-th root of unity	
    pub omega: i64,
	/// Polynomial modulus
    pub f: Polynomial<i64>,
	/// generate random bytes
	pub random_bytes: fn(usize, Option<&mut DrbgCtx>) -> Vec<u8>,
}

/// default parameters for module-LWE
impl Default for Parameters {
    fn default() -> Self {
        let n = 256;
        let q = 12289;
        let k = 4;
        let sigma = 3.19;
		let omega = ntt::omega(q, 2*n);
		let eta_1 = 3;
		let eta_2 = 2;
		let du = 10;
		let dv = 4;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, k, sigma, omega, eta_1, eta_2, du, dv, f, random_bytes: gen_random_bytes }
    }
}

/// generate random bytes using `getrandom` crate
/// or using the DRBG if a mutable reference is provided
fn gen_random_bytes(size: usize, drbg: Option<&mut DrbgCtx>) -> Vec<u8> {
	let mut out = vec![0; size];
	if let Some(drbg) = drbg {
		drbg.get_random(&mut out);
	}
	else {
		getrandom(&mut out).expect("Failed to get random bytes");
	}
	out
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
/// * `m` - A vector of 64-bit integers
///
/// # Returns
///
/// * Vec<u8> - 32 byte output, the result of applying the sha3_256 hash
///
/// # Example
/// ```
/// use ml_kem::utils::hash_h;
/// let input = vec![1i64, 2, 3, 4, 5, 6, 7, 8];
/// let result = hash_h(input);
/// assert_eq!(result.len(), 32); // Ensure the result is 32 bytes long
/// ```
pub fn hash_h(m: Vec<i64>) -> Vec<u8> {
    // Convert i64 vector directly into a byte slice
    let bytes: Vec<u8> = m.iter()
        .flat_map(|num| num.to_le_bytes()) // Convert each i64 to 8 bytes (little-endian)
        .collect();

    // Apply sha3_256 hash
    let mut sha3_256hasher = Sha3_256Hasher::default();
    sha3_256hasher.write(&bytes);
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

/// Convert a vector of bytes into a vector of bits
/// 
/// # Arguments
/// 
/// * `bytes` - a vector of bytes
/// 
/// # Returns 
///
/// * Vec<u8> - a vector of bits
///
/// # Example
/// ```
/// use ml_kem::utils::bytes_to_bits;
/// let bytes = vec![15, 200];
/// let bits = bytes_to_bits(bytes);
/// assert_eq!(bits, vec![1,1,1,1,0,0,0,0,0,0,0,1,0,0,1,1]);
/// ```
pub fn bytes_to_bits(bytes: Vec<u8>) -> Vec<u8> {
	let mut bits = vec![0; bytes.len()*8];
	let mut c = bytes;
	for i in 0..c.len() {
		for j in 0..8 {
			bits[8*i+j] = c[i] % 2;
			c[i] = c[i]/2;
		}
	}
	bits
}

/// Generates a polynomial from bytes via the centered binomial distribution
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
	let bits = bytes_to_bits(input_bytes);
	for i in 0..n {
		let mut a = 0i64;
		let mut b = 0i64;
		for j in 0..eta {
			a += bits[2*i*eta+j] as i64;
			b += bits[2*i*eta+eta+j] as i64;
		}
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
/// let eta = 24;
/// let n = 0x01;
/// let k = 3;
/// let poly_size = 32;
/// let (v,n) = generate_error_vector(sigma,eta,n,k,poly_size);
/// assert_eq!(v.len(),3);
/// ```
pub fn generate_error_vector(
    sigma: Vec<u8>,
    eta: usize,
    n: u8,
    k: usize,
    poly_size: usize
) -> (Vec<Polynomial<i64>>, u8) {
    let mut elements = vec![Polynomial::new(vec![]); k];
    let mut current_n = n;

    for i in 0..k {
        let prf_output = prf_3(sigma.clone(), current_n);
		assert_eq!(eta*poly_size/4, prf_output.len(), "eta*poly_size/4 must be 192 (prf output length)");
        elements[i] = cbd(prf_output, eta, poly_size);
        current_n += 1;
    }

    (elements, current_n)
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
    n: u8,
    poly_size: usize,
    q: Option<i64>,
) -> (Polynomial<i64>, u8) {
    let prf_output = prf_3(sigma, n); // get the prf bytes
    let poly = cbd(prf_output, eta, poly_size); // form the polynomial array from a centered binomial dist.
    if let Some(q) = q {
        let coeffs = poly.coeffs();
        let mut mod_coeffs = vec![];
        for i in 0..coeffs.len() {
            mod_coeffs.push(coeffs[i].rem_euclid(q));
        }
        return (Polynomial::new(mod_coeffs), n + 1);
    }
    (poly, n + 1)
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
    let mut t = BigUint::zero(); // Start with a BigUint initialized to zero

    for i in 0..255 {
        // Left shift by d bits and then OR the current coefficient
        t <<= d; // Equivalent to t = t * 2^d
        t |= BigUint::from(poly.coeffs()[256 - i - 1] as u64); // Use BigUint for coefficients
    }

    // Add the last coefficient
    t |= BigUint::from(poly.coeffs()[0] as u64);

    // Convert BigUint to a byte vector
    let byte_len = 32 * d;
    let mut result = t.to_bytes_le(); // Convert to little-endian bytes
    result.resize(byte_len, 0); // Ensure the result is exactly `32 * d` bytes

    result
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
/// use ml_kem::utils::{generate_polynomial,encode_vec};
/// let sigma = vec![0u8; 32]; // Example seed
/// let eta = 3;
/// let n = 0;
/// let poly_size = 256;
/// let (p0, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, None);
/// let (p1, _n) = generate_polynomial(sigma.clone(), eta, n, poly_size, None);
/// let polys = vec![p0, p1];
/// let encoded_bytes = encode_vec(&polys, 12);
/// assert_eq!(encoded_bytes.len(), 768);  // Total length after encoding two polynomials
/// ```
pub fn encode_vec(v: &Vec<Polynomial<i64>>, d: usize) -> Vec<u8> {
    let mut encoded_bytes = Vec::new();
    for poly in v {
        let encoded_poly = encode_poly(poly, d);
        encoded_bytes.extend(encoded_poly);  // Append each encoded polynomial's bytes
    }
    encoded_bytes
}

/// placeholder decode vec function
pub fn decode_vec(_encoded: &Vec<u8>, _k: usize, _d: usize, _from_ntt: bool) -> Vec<Polynomial<i64>> {
    // Placeholder implementation
    // Decode the vector and return a Vec of Polynomials.
    // This function should return a Vec<Polynomial<i64>> after decoding the input `encoded` data.
    
    Vec::new()  // Placeholder for now
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
/// * `omega` - The primitive root of unity used for the NTT.
/// * `n` - The expected number of coefficients in each polynomial.
/// * `q` - The modulus used for NTT computations.
///
/// # Returns
///
/// A vector of `Polynomial<i64>` where each polynomial has been transformed using NTT.
pub fn vec_ntt(v: &Vec<Polynomial<i64>>, omega: i64, n: usize, q: i64) -> Vec<Polynomial<i64>> {
    v.iter()
        .map(|poly| {
            let mut coeffs = poly.coeffs().to_vec(); // Convert slice to Vec<i64>
            coeffs.resize(n, 0); // Ensure uniform length
            Polynomial::new(ntt(&coeffs, omega, n, q))
        })
        .collect()
}
