use module_lwe::utils::{gen_uniform_matrix,mul_mat_vec_simple,gen_small_vector,add_vec};
use module_lwe::encrypt::encrypt;
use module_lwe::decrypt::decrypt;
use ring_lwe::utils::gen_binary_poly;
use crate::utils::{Parameters, hash_h};
use polynomial_ring::Polynomial;
use aes_ctr_drbg::DrbgCtx;

pub struct MLKEM {
    pub params: Parameters,
    pub drbg: Option<DrbgCtx>,
}

impl MLKEM {
    // Constructor to initialize MLKEM with parameters
    pub fn new(params: Parameters) -> Self {
        MLKEM { params, drbg: None}
    }

    /// Set the DRBG to be used for random bytes
    pub fn set_drbg_seed(&mut self, seed: Vec<u8>) {
        let p = vec![48, 0]; // personalization string must be min. 48 bytes long
        let mut drbg = DrbgCtx::new(); // instantiate the DRBG
	    drbg.init(&seed, p); // initialize the DRBG with the seed
        self.drbg = Some(drbg); // Store the DRBG in the struct
    }

    pub fn keygen(&self) -> ((Vec<Vec<Polynomial<i64>>>, Vec<Polynomial<i64>>), Vec<Polynomial<i64>>) {
        let a = gen_uniform_matrix(self.params.n, self.params.k, self.params.q, None); 
        
        let s = gen_small_vector(self.params.n, self.params.k, None);
        let e = gen_small_vector(self.params.n, self.params.k, None);
        
        let b = add_vec(
            &mul_mat_vec_simple(&a, &s, self.params.q, &self.params.f, self.params.omega), 
            &e, 
            self.params.q, 
            &self.params.f
        );
        
        ((a, b), s)
    }

    pub fn encapsulate(&self, pk: (Vec<Vec<Polynomial<i64>>>, Vec<Polynomial<i64>>)) -> (Vec<u8>, (Vec<Polynomial<i64>>, Polynomial<i64>)) {
        let params_mlwe = module_lwe::utils::Parameters { 
            n: self.params.n, 
            q: self.params.q, 
            k: self.params.k, 
            omega: self.params.omega, 
            f: self.params.f.clone() 
        };

        let mut m = gen_binary_poly(self.params.n, None).coeffs().to_vec();
        m.resize(self.params.n, 0);

        let ct = encrypt(&pk.0, &pk.1, &m, &params_mlwe, None);
        let k = hash_h(m);
        (k, ct)
    }

    pub fn decapsulate(&self, sk: Vec<Polynomial<i64>>, ct: (Vec<Polynomial<i64>>, Polynomial<i64>)) -> Vec<u8> {
        let params_mlwe = module_lwe::utils::Parameters { 
            n: self.params.n, 
            q: self.params.q, 
            k: self.params.k, 
            omega: self.params.omega, 
            f: self.params.f.clone() 
        };

        let mut m = decrypt(&sk, &ct.0, &ct.1, &params_mlwe);
        m.resize(self.params.n, 0);

        hash_h(m)
    }

}
