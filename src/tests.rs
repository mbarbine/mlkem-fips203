#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use ml_kem::utils::Parameters;
	use ml_kem::ml_kem::MLKEM;

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    pub fn test_basic() {
        let params = Parameters::default();  // Adjust this if needed
        let mlkem = MLKEM::new(params); 
        let (pk, sk) = mlkem.keygen();
        let (k, ct) = mlkem.encapsulate(pk);
		let k_recovered = mlkem.decapsulate(sk, ct);
        assert_eq!(k, k_recovered, "test failed: {:?} != {:?}", k, k_recovered);
    }

    #[test]
    fn test_set_drbg_seed() {
        let params = Parameters::default();
        let mut kem = MLKEM::new(params);

        // Generate random bytes before setting DRBG seed (should use system randomness)
        let rand_bytes_os = (kem.params.random_bytes)(16, None);
        assert_eq!(rand_bytes_os.len(), 16);

        // Set DRBG seed
        let seed = vec![0x42; 48]; // Example 48-byte seed
        kem.set_drbg_seed(seed);

        // Generate random bytes using DRBG
        let rand_bytes_drbg = (kem.params.random_bytes)(16, kem.drbg.as_mut());
        assert_eq!(rand_bytes_drbg.len(), 16);

        // Ensure DRBG output is deterministic
        let rand_bytes_init: [u8; 16] = [21, 115, 212, 133, 136, 19, 186, 226, 132, 198, 0, 183, 126, 71, 212, 214];
        assert_eq!(rand_bytes_drbg, rand_bytes_init);
    }
}