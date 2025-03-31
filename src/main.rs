use ml_kem::ml_kem::MLKEM;
use ml_kem::utils::Parameters;
use ml_kem::utils::generate_polynomial;
use ntt::ntt;
mod tests;

fn main() {

    let params = Parameters::default();
    let mlkem = MLKEM::new(params);
    let sigma = vec![0u8; 32]; // Example seed
    let prf_count = 0;
    let (poly, _prf_count) = generate_polynomial(sigma.clone(), mlkem.params.eta_1, prf_count, mlkem.params.n);
    let ntt_poly = ntt(poly.coeffs(), mlkem.params.omega, mlkem.params.n, mlkem.params.q);
    println!("{:?}", ntt_poly);

    let d = vec![0x01, 0x02, 0x03, 0x04];
    let (_ek_pke, _dk_pke) = mlkem._k_pke_keygen(d);

}
