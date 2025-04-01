use ml_kem::ml_kem::MLKEM;
use ml_kem::utils::Parameters;
use ml_kem::utils::{generate_polynomial,encode_poly};
mod tests;

fn main() {

    let params = Parameters::default();
    let mlkem = MLKEM::new(params);

    let d = vec![0x01, 0x02, 0x03, 0x04];
    let (_ek_pke, _dk_pke) = mlkem._k_pke_keygen(d);
    
    let sigma = vec![0u8; 32]; // Example seed
    let eta = 3;
    let n = 0;
    let poly_size = 256;
    let (poly, _n) = generate_polynomial(sigma, eta, n, poly_size, None);
    println!("{:?}", poly);

    let encoded = encode_poly(&poly, 12);
    println!("encoded_poly = {:?}", encoded);
    assert_eq!(encoded.len(), 384); // 32 * d (d = 12)
    let (ek_pke, _dk_pke) = mlkem._k_pke_keygen(d);

    // let m = vec![0x01, 0x02, 0x03, 0x04];
    // let r = 3.0;
    // mlkem._k_pke_encrypt(ek_pke, m, r);

}
