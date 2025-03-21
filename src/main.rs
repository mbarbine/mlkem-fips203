use ml_kem::ml_kem::MLKEM;
use ml_kem::utils::Parameters;
use aes_ctr_drbg::DrbgCtx;
mod tests;

fn main() {
    let params = Parameters::default();

    // Generate key pair
    let mlkem = MLKEM::new(params); 
    let (public_key, secret_key) = mlkem.keygen();

    // Print keys for verification
    println!("Public Key: {:?}", public_key);
    println!("Secret Key: {:?}", secret_key);

    // personalization string must be min. 48 bytes long
	let p = vec![48, 0];

	// get entropy from somewhere, f.e. /dev/random
	let entropy: [u8; 48] = [0x04; 48]; // don't use that!

	let mut drbg = DrbgCtx::new();
	drbg.init(&entropy, p);

	// get 10 bytes
	let mut out = Vec::new();
	out.resize(10, 0);
	drbg.get_random(&mut out);

    println!("{:?}", out);

}
