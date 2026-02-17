# World ID Authenticator

World ID is an anonymous proof of human for the age of AI.

This crate provides the functionality for a World ID Authenticator.

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).

`Authenticator::init` and `Authenticator::init_or_register` require caller-provided proving
materials (`query_material`, `nullifier_material`). The authenticator no longer loads embedded
zkeys implicitly.
