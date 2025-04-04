use ml_kem::ml_kem::MLKEM;
use ml_kem::parameters::Parameters;
use ml_kem::utils::{encode_poly,compress_poly};
use ring_lwe::utils::gen_uniform_poly;
mod tests;

fn main() {

    // run the basic PKE with a uniformly random message polynomial
    let params = Parameters::mlkem512(); // initialize default parameters
    let mut mlkem = MLKEM::new(params); 
    mlkem.set_drbg_seed(vec![0x42; 48]); // Example 48-byte seed
    let d = (mlkem.params.random_bytes)(32, mlkem.drbg.as_mut());
    let (ek_pke, dk_pke) = mlkem._k_pke_keygen(d); // Generate public and private keys for PKE
    let m_poly = gen_uniform_poly(mlkem.params.n, mlkem.params.q, None); //random message polynomial
    let m = encode_poly(compress_poly(m_poly,1),1); // compress and encode the message polynomial
    let r = vec![0x01, 0x02, 0x03, 0x04]; // Example random bytes for encryption
    let c = match mlkem._k_pke_encrypt(ek_pke, m.clone(), r) { //perform encryption, handling potential errors
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("Encryption failed: {}", e),
    };
    let m_dec = mlkem._k_pke_decrypt(dk_pke, c); // perform the decryption
    assert_eq!(m, m_dec); // check if the decrypted message matches the original message

    // run the basic keygen/encaps/decaps
    let (ek, dk) = mlkem.keygen(); // Generate public and private keys for KEM
    let (shared_k,c) = match mlkem.encaps(ek) { // encapsulate the shared key, handling potential errors
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("Encryption failed: {}", e),
    };
    let shared_k_decaps = match mlkem.decaps(dk,c) { // decapsulate the shared key, handling potential errors
        Ok(decapsulated_shared_key) => decapsulated_shared_key,
        Err(e) => panic!("Decryption failed: {}", e),
     };
     assert_eq!(shared_k, shared_k_decaps); // check if the decapsulated shared key matches the original shared key

}
