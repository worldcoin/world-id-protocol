use criterion::*;
use poseidon2::Poseidon2;

fn poseidon2_bench(c: &mut Criterion) {
    c.bench_function("Poseidon2 Permutation (t=3)", |b| {
        let poseidon2 = Poseidon2::<_, 3, 5>::default();
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
        ];

        b.iter(|| poseidon2.permutation(&input));
    });
    c.bench_function("Poseidon2 Permutation (t=4)", |b| {
        let poseidon2 = Poseidon2::<_, 4, 5>::default();
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
            ark_bn254::Fr::from(45u64),
        ];

        b.iter(|| poseidon2.permutation(&input));
    });
}

criterion_group!(benches, poseidon2_bench);
criterion_main!(benches);
