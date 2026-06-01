# World ID

World ID is a protocol built to enable anonymous proof of human (PoH) at global scale and to complement existing identity systems. World ID allows individuals to prove things about themselves — like they are a real and unique human, not a bot — without revealing any personal information. [Read more about World ID][website].


**Good places to start**:
- **Learn more about World ID**: To learn more about World ID in general, see the [World ID Website][website].
- **Integrating World ID**: The best place to start for integrating World ID is the [Developer Docs](https://docs.world.org/world-id/overview).
- **Protocol Repo**: The source code for the protocol can be found in [this repo](https://github.com/worldcoin/world-id-protocol).

## High level architecture

The following diagram shows the main parties which interact in the World ID Protocol.

![Parties of the World ID Protocol][world-id-protocol-parties]

## About this crate

Core foundational types and structures for the World ID Protocol. 

Importantly, this crate keeps dependencies to a minimum and does not implement any logic beyond serialization and deserialization.

[world-id-protocol-parties]: assets/world-id-protocol-parties.png
[website]: https://world.org/world-id
