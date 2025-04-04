use crate::utils::bit_reverse;
use getrandom::getrandom;
use polynomial_ring::Polynomial;
use ntt::mod_exp;
use aes_ctr_drbg::DrbgCtx;

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
	/// Polynomial modulus
    pub f: Polynomial<i64>,
	/// generate random bytes
	pub random_bytes: fn(usize, Option<&mut DrbgCtx>) -> Vec<u8>,
	/// ntt zeta values
	pub zetas: Vec<i64>,
}

/// default parameters for module-LWE
impl Parameters {
    // Provides about 128 bit level of security.
    fn mlkem512() -> Self {
        let n = 256;
        let q = 3329;
        let k = 2;
		let eta_1 = 3;
		let eta_2 = 2;
		let du = 10;
		let dv = 4;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let zetas: Vec<i64> = (0..128)
        	.map(|i| mod_exp(17, bit_reverse(i, 7), 3329))
        	.collect();
        Parameters { n, q, k, eta_1, eta_2, du, dv, f, zetas, random_bytes: gen_random_bytes }
    }

    // Provides about 192 bit level of security.
    pub fn mlkem768() -> Self {
        let n = 256;
        let q = 3329;
        let k = 3;
		let eta_1 = 2;
		let eta_2 = 2;
		let du = 10;
		let dv = 4;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let zetas: Vec<i64> = (0..128)
        	.map(|i| mod_exp(17, bit_reverse(i, 7), 3329))
        	.collect();
        Parameters { n, q, k, eta_1, eta_2, du, dv, f, zetas, random_bytes: gen_random_bytes }
    }

    // Provides about 256 bit level of security.
    pub fn mlkem1024() -> Self {
        let n = 256;
        let q = 3329;
        let k = 4;
		let eta_1 = 2;
		let eta_2 = 2;
		let du = 11;
		let dv = 5;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        let zetas: Vec<i64> = (0..128)
        	.map(|i| mod_exp(17, bit_reverse(i, 7), 3329))
        	.collect();
        Parameters { n, q, k, eta_1, eta_2, du, dv, f, zetas, random_bytes: gen_random_bytes }
    }
}

/// generate random bytes using `getrandom` crate or using the DRBG if a mutable reference is provided
/// # Arguments
/// * `size` - size of the random bytes to generate
/// * `drbg` - optional mutable reference to a `DrbgCtx` instance
/// # Returns
/// * `Vec<u8>` - vector of random bytes
/// # Panics
/// * Panics if `getrandom` fails to generate random bytes
/// # Note
/// * If `drbg` is `None`, the function uses the `getrandom` crate to generate random bytes.
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