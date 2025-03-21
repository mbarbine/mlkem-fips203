use ml_kem::ml_kem::MLKEM;
use ml_kem::utils::Parameters;
mod tests;

fn main() {
    let params = Parameters::default();

    // Generate key pair
    let mlkem = MLKEM::new(params); 
    let (public_key, secret_key) = mlkem.keygen();

    // Print keys for verification
    println!("Public Key: {:?}", public_key);
    println!("Secret Key: {:?}", secret_key);
}
