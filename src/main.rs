use ml_kem::ml_kem::MLKEM;
use ml_kem::utils::{Parameters,encode_poly,generate_polynomial};
mod tests;

fn main() {

    let params = Parameters::default();
    let mlkem = MLKEM::new(params);

    let d = vec![0x01, 0x02, 0x03, 0x04];
    let (ek_pke, _dk_pke) = mlkem._k_pke_keygen(d);

    let sigma = vec![0u8; 32]; // Example seed
    let eta = 3;
    let n = 0;
    let poly_size = 256;
    let (m_poly, _n) = generate_polynomial(sigma, eta, n, poly_size, None);
    let m = encode_poly(&m_poly,1);
    let r = vec![0x01, 0x02, 0x03, 0x04];
    let k_pke_encrypt_output = mlkem._k_pke_encrypt(ek_pke, m, r);
    println!("_k_pke_encrypt output = {:?}", k_pke_encrypt_output);

}
