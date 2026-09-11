# Mobile ZK results

- **Status:** ready
- **Updated:** 2026-09-11T13:53:37Z
- **Commit:** `a913f24cad47ae7bc7990fe32ea9a17e96b57432`
- **Workflow run:** [34599588466](https://github.com/worldcoin/world-id-protocol/actions/runs/34599588466)
- **mobench:** 0.2.0
- **Iterations / warmup:** 30 / 5
- **Device profile:** low-spec

## iOS

### Benchmark Summary

- Generated: 2026-09-11T13:49:03.468837Z
- Target: iOS
- Function: multiple
- Iterations/Warmup: 30 / 5
- Devices: iPhone 14-16

| Device | Function | Samples | Warmup | Wall mean / iter | Wall total | CPU median / iter | CPU total | CPU / wall | Peak growth | Process peak |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| iPhone 14-16 | zk_mobile_bench::bench_nullifier_proof_generation | 30 | 5 | 876.242ms | 26.287s | 4.059s | 121.379s | 461.7% | 105.59 MB | 238.58 MB |
| iPhone 14-16 | zk_mobile_bench::bench_nullifier_proving_only | 30 | 5 | 504.879ms | 15.146s | 2.596s | 77.731s | 513.2% | 55.84 MB | 215.50 MB |
| iPhone 14-16 | zk_mobile_bench::bench_nullifier_witness_generation_only | 30 | 5 | 27.827ms | 834.797ms | 28ms | 842ms | 100.9% | 5.66 MB | 161.11 MB |
| iPhone 14-16 | zk_mobile_bench::bench_query_cached_proof_generation | 30 | 5 | 269.672ms | 8.090s | 1.211s | 36.391s | 449.8% | 27.02 MB | 158.80 MB |
| iPhone 14-16 | zk_mobile_bench::bench_query_proof_generation | 30 | 5 | 271.971ms | 8.159s | 1.267s | 38.093s | 466.9% | 62.75 MB | 185.80 MB |
| iPhone 14-16 | zk_mobile_bench::bench_query_proving_only | 30 | 5 | 256.933ms | 7.708s | 1.329s | 39.746s | 515.6% | 26.27 MB | 161.16 MB |
| iPhone 14-16 | zk_mobile_bench::bench_query_witness_generation_only | 30 | 5 | 7.643ms | 229.295ms | 8ms | 265ms | 115.6% | 3.38 MB | 131.62 MB |


### Device Comparison Plots

### nullifier-proof-generation
![nullifier-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/nullifier-proof-generation.svg)

### nullifier-proving-only
![nullifier-proving-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/nullifier-proving-only.svg)

### nullifier-witness-generation-only
![nullifier-witness-generation-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/nullifier-witness-generation-only.svg)

### query-cached-proof-generation
![query-cached-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/query-cached-proof-generation.svg)

### query-proof-generation
![query-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/query-proof-generation.svg)

### query-proving-only
![query-proving-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/query-proving-only.svg)

### query-witness-generation-only
![query-witness-generation-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/ios/plots/query-witness-generation-only.svg)


## Android

### Benchmark Summary

- Generated: 2026-09-11T13:27:53.526848Z
- Target: Android
- Function: multiple
- Iterations/Warmup: 30 / 5
- Devices: Motorola Moto G71 5G-11.0

| Device | Function | Samples | Warmup | Wall mean / iter | Wall total | CPU median / iter | CPU total | CPU / wall | Peak growth | Process peak |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_nullifier_proof_generation | 30 | 5 | 3.049s | 91.479s | 11.853s | 348.783s | 381.3% | 106.06 MB | 334.08 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_nullifier_proving_only | 30 | 5 | 1.902s | 57.053s | 7.535s | 224.087s | 392.8% | 67.24 MB | 299.95 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_nullifier_witness_generation_only | 30 | 5 | 53.168ms | 1.595s | 53ms | 1.692s | 106.1% | 9.38 MB | 247.58 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_query_cached_proof_generation | 30 | 5 | 965.471ms | 28.964s | 3.715s | 111.756s | 385.8% | 37.09 MB | 242.91 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_query_proof_generation | 30 | 5 | 1.036s | 31.094s | 3.826s | 116.743s | 375.4% | 60.41 MB | 266.68 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_query_proving_only | 30 | 5 | 917.983ms | 27.539s | 3.734s | 111.231s | 403.9% | 33.71 MB | 238.18 MB |
| Motorola Moto G71 5G-11.0 | zk_mobile_bench::bench_query_witness_generation_only | 30 | 5 | 17.264ms | 517.926ms | 14ms | 523ms | 101.0% | 0.00 MB | 199.45 MB |


### Device Comparison Plots

### nullifier-proof-generation
![nullifier-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/nullifier-proof-generation.svg)

### nullifier-proving-only
![nullifier-proving-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/nullifier-proving-only.svg)

### nullifier-witness-generation-only
![nullifier-witness-generation-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/nullifier-witness-generation-only.svg)

### query-cached-proof-generation
![query-cached-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/query-cached-proof-generation.svg)

### query-proof-generation
![query-proof-generation](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/query-proof-generation.svg)

### query-proving-only
![query-proving-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/query-proving-only.svg)

### query-witness-generation-only
![query-witness-generation-only](https://raw.githubusercontent.com/worldcoin/world-id-protocol/mobench-plots/runs/34599588466-1/android/plots/query-witness-generation-only.svg)


