use module_lwe::utils::{gen_uniform_matrix,mul_mat_vec_simple,gen_small_vector,add_vec};
use crate::utils::Parameters;
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

    pub fn encapsulate(public_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Generate a shared secret and encapsulation
        unimplemented!()
    }

    pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        // Recover the shared secret from ciphertext and secret key
        unimplemented!()
    }
}