use ml_kem::kem::KEM;
use ml_kem::utils::Parameters;
mod tests;

fn main() {
    let params = Parameters::default();

    // Generate key pair
    let (public_key, secret_key) = KEM::keygen(&params);

    // Print keys for verification
    println!("Public Key: {:?}", public_key);
    println!("Secret Key: {:?}", secret_key);
}
