import { p256 } from "@noble/curves/nist.js";
import { initProveKit } from "@worldcoin/provekit";

import { registerWithLocalBridge } from "./src/demo-adapter";
import { buildPasskeyOwnershipNoirInputs } from "./src/passkey-noir-inputs";
import { proveAndVerifyWithRuntime } from "./src/provekit-runtime";
import { base64url, type AssertionWitness, type RegisteredPasskey } from "./src/webauthn";
import proverArtifactUrl from "../../crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkp?url";
import verifierArtifactUrl from "../../crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkv?url";

const result = document.querySelector<HTMLElement>("#result")!;

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

async function digest(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

try {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;
  const point = p256.getPublicKey(privateKey, false);
  const passkey: RegisteredPasskey = {
    credentialId: Uint8Array.of(1),
    publicKey: { x: point.slice(1, 33), y: point.slice(33, 65) },
  };
  const registry = await registerWithLocalBridge(passkey);

  const challenge = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const clientDataJson = new TextEncoder().encode(JSON.stringify({
    type: "webauthn.get",
    challenge: base64url(challenge),
    origin: location.origin,
  }));
  const rpIdHash = await digest(new TextEncoder().encode(location.hostname));
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpIdHash);
  authenticatorData[32] = 0x05;
  const signature = p256.sign(concat(authenticatorData, await digest(clientDataJson)), privateKey);
  const assertion: AssertionWitness = {
    authenticatorData,
    clientDataJson,
    challenge,
    challengeIndex: new TextDecoder().decode(clientDataJson).indexOf(base64url(challenge)),
    signature,
    rpIdHash,
  };

  const witnessStarted = performance.now();
  const inputs = await buildPasskeyOwnershipNoirInputs(passkey, assertion, registry);
  const witnessMs = performance.now() - witnessStarted;
  const threads = new URLSearchParams(location.search).get("threads") === "false" ? false : "auto";
  const runtime = await initProveKit({ threads });
  const [pkp, pkv] = await Promise.all([
    fetch(proverArtifactUrl).then((r) => r.arrayBuffer()),
    fetch(verifierArtifactUrl).then((r) => r.arrayBuffer()),
  ]);
  const proof = await proveAndVerifyWithRuntime(runtime, inputs, new Uint8Array(pkp), new Uint8Array(pkv));
  result.textContent = JSON.stringify({
    ok: proof.valid && proof.tamperedRejected,
    registry: { leafIndex: registry.leafIndex, root: registry.root, accountLeaf: registry.accountLeaf },
    threading: runtime.threading,
    witnessMs,
    ...proof,
    crossOriginIsolated,
    userAgent: navigator.userAgent,
  }, null, 2);
} catch (error) {
  const describe = (value: unknown, depth = 0): unknown => {
    if (!(value instanceof Error) || depth > 4) return String(value);
    return {
      name: value.name,
      message: value.message,
      code: "code" in value ? String(value.code) : undefined,
      cause: value.cause === undefined ? undefined : describe(value.cause, depth + 1),
    };
  };
  result.textContent = JSON.stringify({
    ok: false,
    error: describe(error),
  }, null, 2);
}
