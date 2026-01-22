# World ID Protocol Contracts




All World ID Protocol Contracts are designed explicitly to operate from behind a proxy contract to allow upgrades. As a result,
there are a few important implementation considerations:

- Updates to any contract are made by creating a new contract with a `V{number}` suffix which inherits from the previous version. This keeps explicit versioning for contract upgrades and makes it easy to understand what each version changed.
- All updates made after deploying a given version of the implementation should inherit from the latest version of the implementation. This prevents storage clashes.
  - [An example](https://github.com/worldcoin/world-id-contracts/blob/main/src/WorldIDIdentityManagerImplV2.sol) of this can be found in the previous version of the World ID Protocol (3.0). All functions that are less access-restricted than `private` should be marked `virtual` in order to enable the fixing of bugs in the existing interface. This allows overriding the functions in future updates.
- Any function that reads from or modifies state (i.e. is not marked `pure`) must be annotated with the `onlyProxy` and `onlyInitialized` modifiers. This ensures that it can only be called when it has access to the data in the proxy, otherwise results are likely to be nonsensical.
- Ensure that all newly-added functionality is carefully access controlled using `onlyOwner`, or a more granular access mechanism as appropriate.
- Do not assign any contract-level variables at the definition site unless they are `constant`.
- Initialization and ownership management are not protected behind `onlyProxy` intentionally. This ensures that the contract can safely be disposed of after it is no longer used.