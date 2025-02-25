use polynomial_ring::Polynomial;
use sha256::digest;

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

pub fn hash(m: Vec<i64>) -> String {
	// Group the bits into bytes (8 bits each)
	let byte_chunks: Vec<String> = m.chunks(8)
		.map(|chunk| chunk.iter().map(|bit| bit.to_string()).collect())
		.collect();
	// Convert each binary string into character
	let message_string: String = byte_chunks.iter()
		.map(|byte| char::from_u32(i64::from_str_radix(byte, 2).unwrap() as u32).unwrap())
		.collect();
	//Apply sha256 hash
	digest(message_string)
}