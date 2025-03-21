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
        assert_eq!(k, k_recovered, "test failed: {} != {}", k, k_recovered);
    }
}