use criterion::{criterion_group, criterion_main, Criterion};
use ml_kem::ml_kem::MLKEM;
use ml_kem::parameters::Parameters;

// benchmark keygen for 512
fn bench_keygen_512(c: &mut Criterion) {
    let params = Parameters::mlkem512();
    let mut mlkem = MLKEM::new(params);
    c.bench_function("keygen_512", |b| {
        b.iter(|| mlkem.keygen())
    });
}

// benchmark keygen for 768
fn bench_keygen_768(c: &mut Criterion) {
    let params = Parameters::mlkem768();
    let mut mlkem = MLKEM::new(params);
    c.bench_function("keygen_768", |b| {
        b.iter(|| mlkem.keygen())
    });
}

// benchmark keygen for 1024
fn bench_keygen_1024(c: &mut Criterion) {
    let params = Parameters::mlkem1024();
    let mut mlkem = MLKEM::new(params);
    c.bench_function("keygen_1024", |b| {
        b.iter(|| mlkem.keygen())
    });
}

criterion_group!(benches, bench_keygen_512, bench_keygen_768, bench_keygen_1024);
criterion_main!(benches);