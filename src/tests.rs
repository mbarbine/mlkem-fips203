#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use ml_kem::parameters::Parameters;
    use ml_kem::utils::{encode_poly,compress_poly};
	use ml_kem::ml_kem::MLKEM;
    use polynomial_ring::Polynomial;

    // test for setting the DRBG seed
    #[test]
    pub fn test_set_drbg_seed() {
        let params = Parameters::mlkem512();
        let mut mlkem = MLKEM::new(params);

        // Generate random bytes before setting DRBG seed (should use system randomness)
        let rand_bytes_os = (mlkem.params.random_bytes)(16, None);
        assert_eq!(rand_bytes_os.len(), 16);

        // Set DRBG seed
        let seed = vec![0x42; 48]; // Example 48-byte seed
        mlkem.set_drbg_seed(seed);

        // Generate random bytes using DRBG
        let rand_bytes_drbg = (mlkem.params.random_bytes)(16, mlkem.drbg.as_mut());
        assert_eq!(rand_bytes_drbg.len(), 16);

        // Ensure DRBG output is deterministic
        let rand_bytes_init: [u8; 16] = [21, 115, 212, 133, 136, 19, 186, 226, 132, 198, 0, 183, 126, 71, 212, 214];
        assert_eq!(rand_bytes_drbg, rand_bytes_init);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    pub fn test_pke_512() {
        let params = Parameters::mlkem512();
        let mlkem = MLKEM::new(params);
        let d = vec![0x01, 0x02, 0x03, 0x04];
        let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
        let rand_bytes_os = (mlkem.params.random_bytes)(mlkem.params.n, None);
        let rand_coeffs: Vec<i64> = rand_bytes_os.into_iter().map(|byte| byte as i64).collect();
        let m_poly = Polynomial::new(rand_coeffs);
        let m = encode_poly(compress_poly(m_poly,1),1);
        let r = vec![0x01, 0x02, 0x03, 0x04];
        let c = match mlkem._k_pke_encrypt(ek_pke, m.clone(), r) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let m_dec = mlkem._k_pke_decrypt(dk_pke, c);
        assert_eq!(m, m_dec);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    pub fn test_pke_768() {
        let params = Parameters::mlkem768();
        let mlkem = MLKEM::new(params);
        let d = vec![0x01, 0x02, 0x03, 0x04];
        let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
        let rand_bytes_os = (mlkem.params.random_bytes)(mlkem.params.n, None);
        let rand_coeffs: Vec<i64> = rand_bytes_os.into_iter().map(|byte| byte as i64).collect();
        let m_poly = Polynomial::new(rand_coeffs);
        let m = encode_poly(compress_poly(m_poly,1),1);
        let r = vec![0x01, 0x02, 0x03, 0x04];
        let c = match mlkem._k_pke_encrypt(ek_pke, m.clone(), r) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let m_dec = mlkem._k_pke_decrypt(dk_pke, c);
        assert_eq!(m, m_dec);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    pub fn test_pke_1024() {
        let params = Parameters::mlkem1024();
        let mlkem = MLKEM::new(params);
        let d = vec![0x01, 0x02, 0x03, 0x04];
        let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d);
        let rand_bytes_os = (mlkem.params.random_bytes)(mlkem.params.n, None);
        let rand_coeffs: Vec<i64> = rand_bytes_os.into_iter().map(|byte| byte as i64).collect();
        let m_poly = Polynomial::new(rand_coeffs);
        let m = encode_poly(compress_poly(m_poly,1),1);
        let r = vec![0x01, 0x02, 0x03, 0x04];
        let c = match mlkem._k_pke_encrypt(ek_pke, m.clone(), r) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let m_dec = mlkem._k_pke_decrypt(dk_pke, c);
        assert_eq!(m, m_dec);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    fn test_keygen_encaps_decaps_512() {
        let params = Parameters::mlkem512();
        let mut mlkem = MLKEM::new(params);
        let (ek, dk) = mlkem.keygen();
        let (shared_k,c) = match mlkem.encaps(ek) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let shared_k_decaps = match mlkem.decaps(dk,c) {
            Ok(decapsulated_shared_key) => decapsulated_shared_key,
            Err(e) => panic!("Decryption failed: {}", e),
         };
         assert_eq!(shared_k, shared_k_decaps);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    fn test_keygen_encaps_decaps_768() {
        let params = Parameters::mlkem768();
        let mut mlkem = MLKEM::new(params);
        let (ek, dk) = mlkem.keygen();
        let (shared_k,c) = match mlkem.encaps(ek) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let shared_k_decaps = match mlkem.decaps(dk,c) {
            Ok(decapsulated_shared_key) => decapsulated_shared_key,
            Err(e) => panic!("Decryption failed: {}", e),
            };
            assert_eq!(shared_k, shared_k_decaps);
    }

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    fn test_keygen_encaps_decaps_1024() {
        let params = Parameters::mlkem1024();
        let mut mlkem = MLKEM::new(params);
        let (ek, dk) = mlkem.keygen();
        let (shared_k,c) = match mlkem.encaps(ek) {
            Ok(ciphertext) => ciphertext,
            Err(e) => panic!("Encryption failed: {}", e),
        };
        let shared_k_decaps = match mlkem.decaps(dk,c) {
            Ok(decapsulated_shared_key) => decapsulated_shared_key,
            Err(e) => panic!("Decryption failed: {}", e),
            };
            assert_eq!(shared_k, shared_k_decaps);
    }
}