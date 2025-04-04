use criterion::{criterion_group, criterion_main, Criterion};
use ml_kem::ml_kem::MLKEM;
use ml_kem::parameters::Parameters;

// benchmark keygen for 512
fn bench_encaps_512(c: &mut Criterion) {
    let params = Parameters::mlkem512();
    let mut mlkem = MLKEM::new(params);
    let (ek, _dk) = mlkem.keygen();
    c.bench_function("encaps_512", |b| {
        b.iter(|| {
            match mlkem.encaps(ek.clone()) {
                Ok(ciphertext) => ciphertext,
                Err(e) => panic!("Encryption failed: {}", e),
            }
        })
    });
}

// benchmark keygen for 768
fn bench_encaps_768(c: &mut Criterion) {
    let params = Parameters::mlkem768();
    let mut mlkem = MLKEM::new(params);
    let (ek, _dk) = mlkem.keygen();
    c.bench_function("encaps_768", |b| {
        b.iter(|| {
            match mlkem.encaps(ek.clone()) {
                Ok(ciphertext) => ciphertext,
                Err(e) => panic!("Encryption failed: {}", e),
            }
        })
    });
}

// benchmark keygen for 1024
fn bench_encaps_1024(c: &mut Criterion) {
    let params = Parameters::mlkem1024();
    let mut mlkem = MLKEM::new(params);
    let (ek, _dk) = mlkem.keygen();
    c.bench_function("encaps_1024", |b| {
        b.iter(|| {
            match mlkem.encaps(ek.clone()) {
                Ok(ciphertext) => ciphertext,
                Err(e) => panic!("Encryption failed: {}", e),
            }
        })
    });
}

criterion_group!(benches, bench_encaps_512, bench_encaps_768, bench_encaps_1024);
criterion_main!(benches);