#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use ml_kem::utils::Parameters;
	use ml_kem::kem::KEM;

    // Test for basic keygen/encapsulate/decapsulate
    #[test]
    pub fn test_basic() {
        let params = Parameters::default();  // Adjust this if needed
        let (pk, sk) = KEM::keygen(&params);
        let (k, ct) = KEM::encapsulate(pk, &params);
		let k_recovered = KEM::decapsulate(sk, ct, &params);
        assert_eq!(k, k_recovered, "test failed: {} != {}", k, k_recovered);
    }
}