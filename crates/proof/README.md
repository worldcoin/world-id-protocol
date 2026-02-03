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

Because decompression of the zkey files is very cpu intensive, we cache the decompress files to disk for subsequent reuse.

##### neither `compress-zkeys` or `embed-zkeys`

zkey files are not included in the bin.
