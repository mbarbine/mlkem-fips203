use polynomial_ring::Polynomial;
use std::hash::Hasher;
use rs_sha3_256::{Sha3_256Hasher, HasherContext};
use rs_sha3_512::Sha3_512Hasher;
use rs_shake128::Shake128Hasher;
use rs_shake256::Shake256Hasher;

#[derive(Debug)]
/// default parameters for module-LWE
pub struct Parameters {
	/// degree of the polynomials
    pub n: usize,
	/// Ciphertext modulus
    pub q: i64,
	/// Module rank	
    pub k: usize,
    /// Standard deviation of the error
    pub sigma: f64,
	/// 2n-th root of unity	
    pub omega: i64,
	/// Polynomial modulus
    pub f: Polynomial<i64>,
}

/// default parameters for module-LWE
impl Default for Parameters {
    fn default() -> Self {
        let n = 512;
        let q = 12289;
        let k = 8;
        let sigma = 3.19;
		let omega = ntt::omega(q, 2*n);
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, k, sigma, omega, f }
    }
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