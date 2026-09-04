// Deterministic browser acceptance fixture: exercises the bridge, Noir input
// construction, and the ProveKit WASM prove/verify lifecycle with a synthetic
// ES256 key instead of a platform passkey. Served by `bun run fixture`.
import { initProveKit } from "@worldcoin/provekit";

import { registerWithLocalBridge } from "./src/bridge-client";
import { buildPasskeyOwnershipNoirInputs, type PasskeyOwnershipNoirInputs } from "./src/passkey-noir-inputs";
import { loadPasskeyArtifacts, proveAndVerifyWithRuntime } from "./src/provekit-runtime";
import { base64url } from "./src/webauthn";
import { createWorldIdProofRequest } from "./src/world-id-proof-request";
import { syntheticPasskey } from "./tests/synthetic-passkey";

const result = document.querySelector<HTMLElement>("#result")!;

type Mutation = (inputs: PasskeyOwnershipNoirInputs) => void;

const flipLowBit = (values: string[], index: number) => {
  values[index] = String(Number(values[index]) ^ 1);
};
const incrementField = (values: string[], index: number) => {
  values[index] = String(BigInt(values[index]!) + 1n);
};

/** Every mutation must make the circuit reject the witness. */
const MUTATIONS: Record<string, Mutation> = {
  challenge: (inputs) => flipLowBit(inputs.challenge, 0),
  rpIdHash: (inputs) => flipLowBit(inputs.rp_id_hash, 0),
  nonce: (inputs) => flipLowBit(inputs.nonce, 0),
  signature: (inputs) => flipLowBit(inputs.inputs.webauthn.signature, 0),
  publicKey: (inputs) => flipLowBit(inputs.inputs.webauthn.public_key_x, 31),
  registryRoot: (inputs) => {
    inputs.root = String(BigInt(inputs.root) + 1n);
  },
  merklePath: (inputs) => incrementField(inputs.inputs.merkle_proof.siblings, 0),
};

async function rejectedMutations(
  runtime: Awaited<ReturnType<typeof initProveKit>>,
  proverArtifact: Uint8Array,
  inputs: PasskeyOwnershipNoirInputs,
): Promise<Record<string, boolean>> {
  const prover = await runtime.loadProver(proverArtifact);
  const rejected: Record<string, boolean> = {};
  try {
    for (const [name, mutate] of Object.entries(MUTATIONS)) {
      const candidate = structuredClone(inputs);
      mutate(candidate);
      try {
        await prover.prove(candidate);
        rejected[name] = false;
      } catch {
        rejected[name] = true;
      }
    }
  } finally {
    prover.dispose();
  }
  return rejected;
}

function describeError(value: unknown, depth = 0): unknown {
  if (!(value instanceof Error) || depth > 4) return String(value);
  return {
    name: value.name,
    message: value.message,
    code: "code" in value ? String(value.code) : undefined,
    cause: value.cause === undefined ? undefined : describeError(value.cause, depth + 1),
  };
}

try {
  const nonce = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const rpId = location.hostname;

  const { passkey, assert } = syntheticPasskey();
  const registry = await registerWithLocalBridge(passkey);
  const proofRequest = await createWorldIdProofRequest({ registryRoot: registry.root, rpId, nonce });
  const assertion = await assert({ challenge: proofRequest.challenge, rpId, origin: location.origin });

  const witnessStarted = performance.now();
  const inputs = buildPasskeyOwnershipNoirInputs(passkey, assertion, registry, proofRequest.nonce);
  const witnessMs = performance.now() - witnessStarted;

  const threads = new URLSearchParams(location.search).get("threads") === "false" ? false : "auto";
  const runtime = await initProveKit({ threads });
  const [proverArtifact, verifierArtifact] = await loadPasskeyArtifacts();
  const proof = await proveAndVerifyWithRuntime(runtime, inputs, proverArtifact, verifierArtifact);
  const mutationsRejected = await rejectedMutations(runtime, proverArtifact, inputs);

  result.textContent = JSON.stringify(
    {
      ok: proof.valid && proof.tamperedRejected && Object.values(mutationsRejected).every(Boolean),
      statement: {
        action: proofRequest.action,
        request: proofRequest.message,
        challenge: base64url(proofRequest.challenge),
      },
      registry: { leafIndex: registry.leafIndex, root: registry.root, accountLeaf: registry.accountLeaf },
      threading: runtime.threading,
      witnessMs,
      ...proof,
      mutationsRejected,
      crossOriginIsolated,
      userAgent: navigator.userAgent,
    },
    null,
    2,
  );
} catch (error) {
  result.textContent = JSON.stringify({ ok: false, error: describeError(error) }, null, 2);
}
