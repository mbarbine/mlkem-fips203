use criterion::{criterion_group, criterion_main, Criterion};
use mlkem_fips203::ml_kem::MLKEM;
use mlkem_fips203::parameters::Parameters;

// benchmark decaps for 512
fn bench_decaps_512(crit: &mut Criterion) {
    let params = Parameters::mlkem512();
    let mut mlkem = MLKEM::new(params);
    let (ek, dk) = mlkem.keygen();
    let (_shared_k,c) = match mlkem.encaps(ek) {
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("Encryption failed: {}", e),
    };
    crit.bench_function("decaps_512", |b| {
        b.iter(|| {
            match mlkem.decaps(dk.clone(),c.clone()) {
                Ok(decapsulated_shared_key) => decapsulated_shared_key,
                Err(e) => panic!("Decryption failed: {}", e),
             }
        })
    });
}

// benchmark decaps for 768
fn bench_decaps_768(crit: &mut Criterion) {
    let params = Parameters::mlkem768();
    let mut mlkem = MLKEM::new(params);
    let (ek, dk) = mlkem.keygen();
    let (_shared_k,c) = match mlkem.encaps(ek) {
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("Encryption failed: {}", e),
    };
    crit.bench_function("decaps_768", |b| {
        b.iter(|| {
            match mlkem.decaps(dk.clone(),c.clone()) {
                Ok(decapsulated_shared_key) => decapsulated_shared_key,
                Err(e) => panic!("Decryption failed: {}", e),
             }
        })
    });
}

// benchmark decaps for 1024
fn bench_decaps_1024(crit: &mut Criterion) {
    let params = Parameters::mlkem1024();
    let mut mlkem = MLKEM::new(params);
    let (ek, dk) = mlkem.keygen();
    let (_shared_k,c) = match mlkem.encaps(ek) {
        Ok(ciphertext) => ciphertext,
        Err(e) => panic!("Encryption failed: {}", e),
    };
    crit.bench_function("decaps_1024", |b| {
        b.iter(|| {
            match mlkem.decaps(dk.clone(),c.clone()) {
                Ok(decapsulated_shared_key) => decapsulated_shared_key,
                Err(e) => panic!("Decryption failed: {}", e),
             }
        })
    });
}

criterion_group!(benches, bench_decaps_512, bench_decaps_768, bench_decaps_1024);
criterion_main!(benches);