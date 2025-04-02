use crate::utils::{Parameters, hash_g, generate_matrix_from_seed, generate_error_vector, generate_polynomial, encode_vector, vec_ntt, vec_intt, poly_intt, decode_vector, encode_poly, decode_poly, decompress_poly, compress_poly, compress_vec,mul_mat_vec_simple,mul_vec_simple, decompress_vec};
use module_lwe::utils::add_vec;
use ring_lwe::utils::{polyadd,polysub};
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

    /// Generates an encryption key and a corresponding decryption key based on the
    /// specified parameter `d` and following Algorithm 13 (FIPS 203).
    ///
    /// This function generates two 32-byte seeds using the `hash_g` function,
    /// computes the matrix `A_hat`, generates error vectors `s` and `e` from
    /// the Centered Binomial Distribution, applies NTT transformations to `s`
    /// and `e`, and computes the public key (`ek_pke`) and the private key (`dk_pke`).
    ///
    /// # Arguments
    /// * `d` - The input parameter (likely a domain or identifier) to seed the key generation.
    ///
    /// # Returns
    /// * A tuple containing:
    ///   - `ek_pke`: The encryption key, which is the public value `t_hat` encoded with `rho`.
    ///   - `dk_pke`: The decryption key, which is the encoded `s_hat`.
    /// 
    /// # Example
    /// ```
    /// use ml_kem::utils::Parameters;
    /// use ml_kem::ml_kem::MLKEM;
    /// let params = Parameters::default();
    /// let mlkem = MLKEM::new(params);
    /// let d = vec![0x01, 0x02, 0x03, 0x04];
    /// let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
    /// ```
    pub fn _k_pke_keygen(
        &self,
        d: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>) {
        // Expand 32 + 1 bytes to two 32-byte seeds.
        // Note: rho, sigma are generated using hash_g
        let (rho, sigma) = hash_g([d.clone(), vec![self.params.k as u8]].concat());

        // Generate A_hat from seed rho
        let a_hat = generate_matrix_from_seed(rho.clone(), self.params.k, self.params.n, false);

        // Set counter for PRF
        let prf_count = 0;

        // Generate the error vectors s and e
        let (s, _prf_count) = generate_error_vector(sigma.clone(), self.params.eta_1, prf_count, self.params.k, self.params.n);
        let (e, _prf_count) = generate_error_vector(sigma.clone(), self.params.eta_1, prf_count, self.params.k, self.params.n);

        // the NTT of s as an element of a rank k module over the polynomial ring
        let s_hat = vec_ntt(&s, self.params.zetas.clone());
        // the NTT of e as an element of a rank k module over the polynomial ring
        let e_hat = vec_ntt(&e, self.params.zetas.clone());
        // A_hat @ s_hat + e_hat
        let a_hat_s_hat = mul_mat_vec_simple(&a_hat, &s_hat, self.params.q, &self.params.f, self.params.zetas.clone());
        let t_hat = add_vec(&a_hat_s_hat, &e_hat, self.params.q, &self.params.f);

        // Encode the keys
        let mut ek_pke = encode_vector(&t_hat, 12); // Encoding vec of polynomials to bytes
        ek_pke.extend_from_slice(&rho); // append rho, output of hash function
        let dk_pke = encode_vector(&s_hat, 12); // Encoding s_hat for dk_pke

        (ek_pke, dk_pke)
    }

    /// Encrypts a plaintext message using the encryption key and randomness `r`
    /// following Algorithm 14 (FIPS 203).
    ///
    /// In addition to performing standard public key encryption (PKE),
    /// this function includes two additional checks required by the FIPS document:
    ///
    /// 1. **Type Check**: Ensures that `ek_pke` has the expected length.
    /// 2. **Modulus Check**: Verifies that `t_hat` has been canonically encoded.
    ///
    /// If either check fails, the function will panic with an error message.
    ///
    /// # Arguments
    ///
    /// * `ek_pke` - A vector of bytes representing the encryption key.
    /// * `m` - A vector of bytes representing the plaintext message.
    /// * `r` - Randomness used in the encryption process.
    ///
    /// # Returns
    ///
    /// A vector of bytes representing the encrypted ciphertext.
    /// 
    /// # Example
    /// ```
    /// use ml_kem::ml_kem::MLKEM;
    /// use ml_kem::utils::{Parameters,encode_poly,compress_poly, generate_polynomial};
    /// let mlkem = MLKEM::new(params);
    /// use ring_lwe::utils::gen_uniform_poly;
    /// let d = vec![0x01, 0x02, 0x03, 0x04];
    /// let (ek_pke, _dk_pke) = mlkem._k_pke_keygen(d);
    /// let m_poly = gen_uniform_poly(mlkem.params.n, mlkem.params.q, None);
    /// let m = encode_poly(&compress_poly(&m_poly,1),1);
    /// let r = vec![0x01, 0x02, 0x03, 0x04];
    /// let c = mlkem._k_pke_encrypt(ek_pke, m, r);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if `ek_pke` has an incorrect length.
    pub fn _k_pke_encrypt(
        &self,
        ek_pke: Vec<u8>,
        m: Vec<u8>,
        r: Vec<u8>,
    ) -> Vec<u8> {

        let expected_len = ek_pke.len();
        let received_len = 384 * self.params.k + 32;

        if expected_len != received_len {
            panic!(
                "Type check failed, ek_pke has the wrong length, expected {} bytes and received {}",
                received_len,
                expected_len
            );
        }

        // Unpack ek
        let (t_hat_bytes_slice, rho_slice) = ek_pke.split_at(ek_pke.len() - 32);
        let t_hat_bytes = t_hat_bytes_slice.to_vec();
        let rho = rho_slice.to_vec();

        // decode the vector of polynomials from bytes
        let t_hat = decode_vector(&t_hat_bytes, self.params.k, 12);

        // check that t_hat has been canonically encoded
        if encode_vector(&t_hat,12) != t_hat_bytes {
            panic!(
                "Modulus check failed, t_hat does not encode correctly"
            );
        }

        // Generate A_hat^T from seed rho
        let a_hat_t = generate_matrix_from_seed(rho.clone(), self.params.k, self.params.n, true);

        // generate error vectors y, e1 and error polynomial e2
        let prf_count = 0;
        let (y, _prf_count) = generate_error_vector(r.clone(), self.params.eta_1, prf_count, self.params.k, self.params.n);
        let (e1, _prf_count) = generate_error_vector(r.clone(), self.params.eta_2, prf_count, self.params.k, self.params.n);
        let (e2, _prf_count) = generate_polynomial(r.clone(), self.params.eta_2, prf_count, self.params.n, None);

        // compute the NTT of the error vector y
        let y_hat = vec_ntt(&y, self.params.zetas.clone());

        // compute u = intt(a_hat.T * y_hat) + e1
        let a_hat_t_y_hat = mul_mat_vec_simple(&a_hat_t, &y_hat, self.params.q, &self.params.f, self.params.zetas.clone());
        let a_hat_t_y_hat_intt = vec_intt(&a_hat_t_y_hat, self.params.zetas.clone());
        let u = add_vec(&a_hat_t_y_hat_intt, &e1, self.params.q, &self.params.f);

        //decode the polynomial mu from the bytes m
        let mu = decompress_poly(&decode_poly(m, 1),1);

        //compute v = intt(t_hat.y_hat) + e2 + mu
        let t_hat_dot_y_hat = mul_vec_simple(&t_hat, &y_hat, self.params.q, &self.params.f, self.params.zetas.clone());
        let t_hat_dot_y_hat_intt = poly_intt(&t_hat_dot_y_hat, self.params.zetas.clone());
        let v = polyadd(&polyadd(&t_hat_dot_y_hat_intt, &e2, self.params.q, &self.params.f), &mu, self.params.q, &self.params.f);

        // compress vec u, poly v by compressing coeffs, then encode to bytes using params du, dv
        let c1 = encode_vector(&compress_vec(&u,self.params.du),self.params.du);
        let c2 = encode_poly(&compress_poly(&v,self.params.dv),self.params.dv);

        //return c1 + c2, the concatenation of two encoded polynomials
        [c1, c2].concat()

    }

    /// Decrypts a message given the encoded secret key and ciphertext pair 
    /// following Algorithm 15 (FIPS 203).
    /// 
    /// # Arguments
    /// * `dk_pke` - byte encoded secret key, output of `_k_pke_encrypt`
    /// * `c` - ciphertext as encoded vector, encoded polynomial
    ///
    /// # Returns
    /// * `m` - message as compressed and encoded polynomial
    ///
    /// # Examples
    /// ```
    /// use ml_kem::ml_kem::MLKEM;
    /// use ml_kem::utils::{Parameters,encode_poly,generate_polynomial};
    /// use ring_lwe::utils::gen_uniform_poly;
    /// let params = Parameters::default();
    /// let mlkem = MLKEM::new(params);
    /// let d = vec![0x01, 0x02, 0x03, 0x04];
    /// let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
    /// let m_poly = gen_uniform_poly(mlkem.params.n, mlkem.params.q, None);
    /// let m = encode_poly(&compress_poly(&m_poly,1),1);
    /// let r = vec![0x01, 0x02, 0x03, 0x04];
    /// let c = mlkem._k_pke_encrypt(ek_pke, m.clone(), r);
    /// let m_dec = mlkem._k_pke_decrypt(dk_pke, c);
    /// assert_eq!(m, m_dec);
    /// ```
    pub fn _k_pke_decrypt(&self, dk_pke: Vec<u8>, c: Vec<u8> ) -> Vec<u8> {

        // encoded size
        let n = self.params.k * self.params.du * 32;
        
        // break ciphertext into two encoded parts
        let (c1, c2) = c.split_at(n);
        let c1 = c1.to_vec();
        let c2 = c2.to_vec();

        // decode and decompress c1, c2, dk_pke into vector u, polynomial v, secret key
        let u = decompress_vec(&decode_vector(&c1, self.params.k, self.params.du), self.params.du);
        let v = decompress_poly(&decode_poly(c2, self.params.dv), self.params.dv);
        let s_hat = decode_vector(&dk_pke, self.params.k, 12);

        // compute u_hat, the NTT of u
        let u_hat = vec_ntt(&u, self.params.zetas.clone());

        // compute w = v - (s_hat.u_hat).from_ntt()
        let s_hat_dot_u_hat = mul_vec_simple(&s_hat, &u_hat, self.params.q, &self.params.f, self.params.zetas.clone());
        let s_hat_dot_u_hat_intt = poly_intt(&s_hat_dot_u_hat, self.params.zetas.clone());
        let w = polysub(&v, &s_hat_dot_u_hat_intt, self.params.q, &self.params.f);

        // compress and encode w to get message m
        let m = encode_poly(&compress_poly(&w,1),1);

        m

    }

}
