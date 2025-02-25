use module_lwe::utils::{gen_uniform_matrix,mul_mat_vec_simple,gen_small_vector,add_vec};
use module_lwe::encrypt::encrypt;
use module_lwe::decrypt::decrypt;
use ring_lwe::utils::gen_binary_poly;
use crate::utils::{Parameters, hash};
use polynomial_ring::Polynomial;

pub struct KEM {
    // Define necessary fields if needed
}

impl KEM {
    pub fn keygen(params: &Parameters) -> ((Vec<Vec<Polynomial<i64>>>,Vec<Polynomial<i64>>), Vec<Polynomial<i64>>) {

        // Generate a key pair (public key, secret key)
        let a = gen_uniform_matrix(params.n, params.k, params.q, None); 
        
        //generate secret key s and ephermeral error polynomial e
        let s = gen_small_vector(params.n, params.k, None);
        let e = gen_small_vector(params.n, params.k, None);
        
        // Step 3: Public key = (A, b), where b = A * s + e
        let b = add_vec(&mul_mat_vec_simple(&a, &s, params.q, &params.f, params.omega), &e, params.q, &params.f);
        
        return ((a,b), s)
    }

    pub fn encapsulate(pk: (Vec<Vec<Polynomial<i64>>>,Vec<Polynomial<i64>>), params: &Parameters) -> (String, (Vec<Polynomial<i64>>, Polynomial<i64>)) {
        // Generate a shared secret and encapsulation
        
		// Get Module LWE parameters
		let params_mod = module_lwe::utils::Parameters{ n: params.n, q: params.q, k: params.k, omega: params.omega, f: params.f.clone() };
		
		// Generate a random binary message m
		let mut m = gen_binary_poly(params.n, None).coeffs().to_vec();
		m.resize(params.n,0);
		// MLWE encrypt m using pk to obtain encapsulation ct
		let ct = encrypt(&pk.0, &pk.1, &m, &params_mod, None);
		// Hash m to obtain the shared secret k
		let k = hash(m);
		(k, ct)
    }

    pub fn decapsulate(sk: Vec<Polynomial<i64>>, ct: (Vec<Polynomial<i64>>, Polynomial<i64>), params: &Parameters) -> String {
        // Recover the shared secret from ciphertext and secret key
        
		// Get Module LWE parameters
		let params_mod = module_lwe::utils::Parameters{ n: params.n, q: params.q, k: params.k, omega: params.omega, f: params.f.clone() };
		
		// Decrypt encapsulation to obtain binary message m
		let mut m = decrypt(&sk, &ct.0, &ct.1, &params_mod);
		m.resize(params.n,0);
		// Hash m to obtain the shared secret k
		hash(m)
		
    }
}