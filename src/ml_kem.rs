use crate::utils::{hash_g, hash_h, hash_j, generate_matrix_from_seed, generate_error_vector, generate_polynomial, encode_vector, vec_ntt, vec_intt, poly_intt, decode_vector, encode_poly, decode_poly, decompress_poly, compress_poly, compress_vec,mul_mat_vec_simple,mul_vec_simple, decompress_vec, polyadd, polysub, add_vec, select_bytes};
use crate::parameters::Parameters;
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
    /// * `d` - The input parameter to seed the key generation.
    ///
    /// # Returns
    /// * A tuple containing:
    ///   - `ek_pke`: The encryption key, which is the public value `t_hat` encoded with `rho`.
    ///   - `dk_pke`: The decryption key, which is the encoded `s_hat`.
    /// 
    /// # Example
    /// ```
    /// use ml_kem::parameters::Parameters;
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
    /// `Vec<u8>` - A vector of bytes `c` representing the encrypted ciphertext.
    /// 
    /// # Example
    /// ```
    /// use ml_kem::ml_kem::MLKEM;
    /// use ml_kem::parameters::Parameters;
    /// use ml_kem::utils::{encode_poly,compress_poly, generate_polynomial};
    /// let params = Parameters::default();
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
    ) -> Result<Vec<u8>, String> {

        let expected_len = ek_pke.len();
        let received_len = 384 * self.params.k + 32;

        if expected_len != received_len {
            return Err(format!(
                "Type check failed: ek_pke length mismatch (expected {}, got {})",
                received_len, expected_len
            ));
        }

        // Unpack ek
        let (t_hat_bytes_slice, rho_slice) = ek_pke.split_at(ek_pke.len() - 32);
        let t_hat_bytes = t_hat_bytes_slice.to_vec();
        let rho = rho_slice.to_vec();

        // decode the vector of polynomials from bytes
        let t_hat = decode_vector(&t_hat_bytes, self.params.k, 12);

        // check that t_hat has been canonically encoded
        if encode_vector(&t_hat,12) != t_hat_bytes {
            return Err("Modulus check failed: t_hat does not encode correctly".to_string());
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
        Ok([c1, c2].concat())

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
    /// use ml_kem::parameters::Parameters;
    /// use ml_kem::utils::{encode_poly,generate_polynomial,compress_poly};
    /// use ring_lwe::utils::gen_uniform_poly;
    /// let params = Parameters::default();
    /// let mlkem = MLKEM::new(params);
    /// let d = vec![0x01, 0x02, 0x03, 0x04];
    /// let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
    /// let m_poly = gen_uniform_poly(mlkem.params.n, mlkem.params.q, None);
    /// let m = encode_poly(&compress_poly(&m_poly,1),1);
    /// let r = vec![0x01, 0x02, 0x03, 0x04];
    /// let c = match mlkem._k_pke_encrypt(ek_pke, m.clone(), r) {
    ///    Ok(ciphertext) => ciphertext,
    ///    Err(e) => panic!("Encryption failed: {}", e), // Make the test fail if encryption fails
    /// };
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

    /// Use randomness to generate an encapsulation key and a corresponding
    /// decapsulation key following Algorithm 16 (FIPS 203)
    ///
    /// # Arguments
    /// * `d` - 32 bytes of randomness to seed the key generation
    /// * `z` - 32 bytes of randomness to seed the key generation
    /// # Returns
    /// `(Vec<u8>, Vec<u8>)` - encapsulation key and decapsulation key (ek, dk)
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let d = vec![0x00; 32];
    /// let z = vec![0x01; 32];
    /// let (ek, dk) = mlkem._keygen_internal(d,z);
    /// ```
    pub fn _keygen_internal(&self, d: Vec<u8>, z: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        
        let (ek_pke, dk_pke) = self._k_pke_keygen(d);

        let ek = ek_pke;
        let dk = [dk_pke, ek.clone(), hash_h(ek.clone()), z].concat();

        (ek, dk)
    }

    /// Uses the encapsulation key and randomness to generate a key and an
    /// associated ciphertext following Algorithm 17 (FIPS 203)
    /// 
    /// # Arguments
    /// * `ek` - (384*k+32)-byte encoded encapsulation key
    /// * `m` - 32 bytes of randomness
    /// # Returns
    /// `(Vec<u8>, Vec<u8>)` - (32 byte shared key `K`, 32*(d_u*k+d_v)-byte ciphertext `c`)
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let d = vec![0x00; 32];
    /// let z = vec![0x01; 32];
    /// let m = vec![0x02; 32];
    /// let (ek, _dk) = mlkem._keygen_internal(d,z);
    /// let (shared_k,c) = match mlkem._encaps_internal(ek,m) {
    ///    Ok(ciphertext) => ciphertext,
    ///    Err(e) => panic!("Encryption failed: {}", e), // Make the test fail if encryption fails
    /// };
    /// ```
    pub fn _encaps_internal(&self, ek: Vec<u8>, m: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (shared_k, r) = hash_g([m.clone(), hash_h(ek.clone())].concat());
    
        let c = self._k_pke_encrypt(ek, m, r)?; // Propagate error with `?`
    
        Ok((shared_k, c))
    }

    /// Uses the decapsulation key to produce a shared secret key from a
    /// ciphertext following Algorithm 18 (FIPS 203)
    /// 
    /// # Arguments
    /// `dk` - (768*k+96)-byte decapsulation key
    /// `c` - 32*(d_u*k+d_v)-byte ciphertext 
    /// # Returns
    /// `Vec<u8>` - 32 byte decapulated shared key
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let d = vec![0x00; 32];
    /// let z = vec![0x01; 32];
    /// let m = vec![0x02; 32];
    /// let (ek, dk) = mlkem._keygen_internal(d,z);
    /// let (shared_k,c) = match mlkem._encaps_internal(ek,m) {
    ///    Ok(ciphertext) => ciphertext,
    ///    Err(e) => panic!("Encryption failed: {}", e),
    /// };
    /// let shared_k_decaps = match mlkem._decaps_internal(dk,c) {
    ///    Ok(decapsulated_shared_key) => decapsulated_shared_key,
    ///    Err(e) => panic!("Encryption failed: {}", e),
    /// };
    /// assert_eq!(shared_k, shared_k_decaps);
    /// ```
    pub fn _decaps_internal(&self, dk: Vec<u8>, c: Vec<u8>) -> Result<Vec<u8>, String>{

        // NOTE: ML-KEM requires input validation before returning the result of
        // decapsulation. These are performed by the following three checks:
        //
        // 1) Ciphertext type check: the byte length of c must be correct
        // 2) Decapsulation type check: the byte length of dk must be correct
        // 3) Hash check: a hash of the internals of the dk must match
        //
        // Unlike encaps, these are easily performed in the kem decaps

        if c.len() != 32 * (self.params.du * self.params.k + self.params.dv) {
            return Err(format!(
                "ciphertext type check failed. Expected {} bytes and obtained {}",
                32 * (self.params.du * self.params.k + self.params.dv),
                c.len()
            ));
        }

        if dk.len() != 768 * self.params.k + 96{
            return Err(format!(
                "decapsulation type check failed. Expected {} bytes and obtained {}",
                768 * self.params.k + 96,
                dk.len()
            ));
        }

        // Parse out data from dk as Vec<u8>
        let dk_pke = dk[0..384 * self.params.k].to_vec();
        let ek_pke = dk[384 * self.params.k..768 * self.params.k + 32].to_vec();
        let h = dk[768 * self.params.k + 32..768 * self.params.k + 64].to_vec();
        let z = dk[768 * self.params.k + 64..].to_vec();

        // Ensure the hash-check passes
        if hash_h(ek_pke.clone()) != h{
            return Err("hash check failed".to_string());
        }

        // Decrypt the ciphertext
        let m_prime = self._k_pke_decrypt(dk_pke, c.clone());

        // Re-encrypt the recovered message
        let (k_prime, r_prime) = hash_g([m_prime.clone(),h].concat());
        let k_bar = hash_j([z,c.clone()].concat());

        // Here the public encapsulation key is read from the private
        // key and so we never expect this to fail the TypeCheck or ModulusCheck
        let c_prime = match self._k_pke_encrypt(ek_pke.clone(), m_prime.clone(), r_prime.clone()) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };

        // If c != c_prime, return K_bar as garbage
        // WARNING: for proper implementations, it is absolutely
        // vital that the selection between the key and garbage is
        // performed in constant time
        let shared_k = select_bytes(&k_bar, &k_prime, c == c_prime);

        Ok(shared_k)
    }
	
    /// Generate an encapsulation key and corresponding decapsulation key
    /// following Algorithm 19 (FIPS 203)
    ///
    /// # Arguments
    /// # Returns
    /// `(Vec<u8>, Vec<u8>)` - encapsulation key and decapsulation key (ek, dk)
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mut mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let (ek, dk) = mlkem.keygen();
    /// ```
    pub fn keygen(&mut self) -> (Vec<u8>, Vec<u8>) {
		let d = (self.params.random_bytes)(32, self.drbg.as_mut());
		let z = (self.params.random_bytes)(32, self.drbg.as_mut());
		let (ek, dk) = self._keygen_internal(d,z);
		return (ek, dk)
	}
	
    /// Derive an encapsulation key and corresponding decapsulation key
    /// following the approach from Section 7.1 (FIPS 203)
    /// with storage of the ``seed`` value for later expansion.
    ///
    /// # Arguments
    /// * `seed` - 64 byte concatenation of the `d` and `z` values
    /// # Returns
    /// `(Vec<u8>, Vec<u8>)` - encapsulation key and decapsulation key (ek, dk)
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mut mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let seed = vec![0x00; 64];
    /// let (ek, dk) = match mlkem.key_derive(seed) {
    ///    Ok(keys) => (keys),
    ///    Err(e) => panic!("Key derive failed: {}", e),
    /// };
    /// ```
    pub fn key_derive(&self, seed: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
        if seed.len() != 64 {
            return Err("The seed must be 64 bytes long".to_string());
        }
		let d = seed[..32].to_vec();
		let z = seed[32..].to_vec();
		let (ek, dk) = self._keygen_internal(d, z);
		Ok((ek, dk))
	}
	
    /// Uses the encapsulation key to generate a shared secret key and an
    /// associated ciphertext following Algorithm 20 (FIPS 203)
    /// 
    /// # Arguments
    /// * `ek` - (384*k+32)-byte encoded encapsulation key
    /// # Returns
    /// `(Vec<u8>, Vec<u8>)` - (32 byte shared key `K`, 32*(d_u*k+d_v)-byte ciphertext `c`)
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mut mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let (ek, _dk) = mlkem.keygen();
    /// let (shared_k,c) = match mlkem.encaps(ek) {
    ///    Ok(ciphertext) => ciphertext,
    ///    Err(e) => panic!("Encryption failed: {}", e), // Make the test fail if encryption fails
    /// };
    /// ```
	pub fn encaps(&mut self, ek: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), String> {
		let m = (self.params.random_bytes)(32, self.drbg.as_mut());
		let (shared_k, c) = self._encaps_internal(ek, m)?; // Propagate error with `?`
		Ok((shared_k, c))
	}
	
    /// Uses the decapsulation key to produce a shared secret key from a
    /// ciphertext following Algorithm 21 (FIPS 203)
    /// 
    /// # Arguments
    /// * `dk` - (768*k+96)-byte decapsulation key
    /// * `c` - 32*(d_u*k+d_v)-byte ciphertext 
    /// # Returns
    /// `Vec<u8>` - 32 byte decapulated shared key
    /// # Examples
    /// ```
    /// let params = ml_kem::parameters::Parameters::default();
    /// let mut mlkem = ml_kem::ml_kem::MLKEM::new(params);
    /// let (ek, dk) = mlkem.keygen();
    /// let (shared_k,c) = match mlkem.encaps(ek) {
    ///    Ok(ciphertext) => ciphertext,
    ///    Err(e) => panic!("Encryption failed: {}", e),
    /// };
    /// let shared_k_decaps = match mlkem.decaps(dk,c) {
    ///    Ok(decapsulated_shared_key) => decapsulated_shared_key,
    ///    Err(e) => panic!("Decryption failed: {}", e),
    /// };
    /// assert_eq!(shared_k, shared_k_decaps);
    /// ```
	pub fn decaps(&self, dk: Vec<u8>, c: Vec<u8>) -> Result<Vec<u8>, String> {
		let shared_k_prime = self._decaps_internal(dk, c)?; // Propagate error with `?`
		Ok(shared_k_prime)
	}
}