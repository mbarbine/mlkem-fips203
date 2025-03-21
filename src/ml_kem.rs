use module_lwe::utils::{gen_uniform_matrix,mul_mat_vec_simple,gen_small_vector,add_vec};
use module_lwe::encrypt::encrypt;
use module_lwe::decrypt::decrypt;
use ring_lwe::utils::gen_binary_poly;
use crate::utils::{Parameters, hash_h};
use polynomial_ring::Polynomial;

pub struct MLKEM {
    params: Parameters,
}

impl MLKEM {
    // Constructor to initialize MLKEM with parameters
    pub fn new(params: Parameters) -> Self {
        MLKEM { params } // Corrected: properly initializes and returns the struct
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

    /*

    to be translate to Rust

    def set_drbg_seed(self, seed):
    """
    Change entropy source to a DRBG and seed it with provided value.

    Setting the seed switches the entropy source from :func:`os.urandom()`
    to an AES256 CTR DRBG.

    Used for both deterministic versions of ML-KEM as well as testing
    alignment with the KAT vectors

    NOTE:
      currently requires pycryptodome for AES impl.

    :param bytes seed: random bytes to seed the DRBG with
    """
    try:
        from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

        self._drbg = AES256_CTR_DRBG(seed)
        self.random_bytes = self._drbg.random_bytes
    except ImportError as e:  # pragma: no cover
        print(f"Error importing AES from pycryptodome: {e = }")
        raise Warning(
            "Cannot set DRBG seed due to missing dependencies, try installing requirements: pip -r install requirements"
        )
    */
}
