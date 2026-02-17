# World ID Proof

World ID is an anonymous proof of human for the age of AI.

This crate provides the functionality for World ID Proofs.

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).

### Features

##### `embed-zkeys`

build.rs will download zkey files from github and include them into the binary.

Download from github is done as a workaround to circumvent the max crates.io hosting limit.

##### `compress-zkeys` (implies `embed-zkeys`)

build.rs will download and compress zkey files from github and include them into the binary.
At runtime, zkeys are decompressed in memory during initialization.

##### neither `compress-zkeys` or `embed-zkeys`

zkey files are not included in the bin.

### Loading proving materials explicitly

`world-id-proof` exposes explicit operations to load embedded bytes and build materials:

```rust
let files = world_id_proof::proof::load_embedded_circuit_files()?;
let query_material = world_id_proof::proof::load_query_material_from_reader(
    files.query_zkey.as_slice(),
    files.query_graph.as_slice(),
)?;
let nullifier_material = world_id_proof::proof::load_nullifier_material_from_reader(
    files.nullifier_zkey.as_slice(),
    files.nullifier_graph.as_slice(),
)?;
```

For consumer-downloaded compressed `.arks.zkey` files, use:

```rust
#[cfg(feature = "compress-zkeys")]
let uncompressed = world_id_proof::proof::ark_decompress_zkey(&compressed_bytes)?;
```
