import "./style.css";
import { registerWithLocalBridge, type RegistryState } from "./bridge-client";
import { buildPasskeyOwnershipNoirInputs } from "./passkey-noir-inputs";
import { describeProveKitFailure, preparePasskeyProof, type PreparedPasskeyProof } from "./provekit-runtime";
import { bytesToHex, registerPasskey, requestAssertion, type RegisteredPasskey } from "./webauthn";
import { createWorldIdProofRequest } from "./world-id-proof-request";

const registerButton = document.querySelector<HTMLButtonElement>("#register-button")!;
const assertButton = document.querySelector<HTMLButtonElement>("#assert-button")!;
const runtimeStatus = document.querySelector<HTMLElement>("#runtime-status")!;
const worldIdValue = document.querySelector<HTMLElement>("#world-id-value")!;
const rootValue = document.querySelector<HTMLElement>("#root-value")!;
const leafValue = document.querySelector<HTMLElement>("#leaf-value")!;
const credentialValue = document.querySelector<HTMLElement>("#credential-value")!;
const rpValue = document.querySelector<HTMLElement>("#rp-value")!;
const challengeValue = document.querySelector<HTMLElement>("#challenge-value")!;
const actionValue = document.querySelector<HTMLElement>("#action-value")!;
const output = document.querySelector<HTMLElement>("#output")!;

let passkey: RegisteredPasskey | null = null;
let registry: RegistryState | null = null;
let pendingProof: PreparedPasskeyProof | null = null;

function proofStatement(
  proofRequest: Awaited<ReturnType<typeof createWorldIdProofRequest>>,
  worldId: string,
) {
  return {
    action: proofRequest.action,
    worldId,
    registryRoot: proofRequest.registryRoot,
    rpId: proofRequest.rpId,
    origin: proofRequest.origin,
    request: proofRequest.message,
    challenge: bytesToHex(proofRequest.challenge),
  };
}

function setStatus(message: string): void {
  runtimeStatus.textContent = message;
}

function showSummary(summary: unknown): void {
  output.textContent = JSON.stringify(summary, null, 2);
}

registerButton.addEventListener("click", async () => {
  registerButton.disabled = true;
  try {
    pendingProof?.dispose();
    pendingProof = null;
    passkey = null;
    registry = null;
    assertButton.disabled = true;
    setStatus("Registering");
    const nextPasskey = await registerPasskey();
    const nextRegistry = await registerWithLocalBridge(nextPasskey);
    passkey = nextPasskey;
    registry = nextRegistry;

    credentialValue.textContent = "ES256 passkey created";
    worldIdValue.textContent = registry.accountLeaf;
    rootValue.textContent = registry.root;
    leafValue.textContent = String(registry.leafIndex);
    showSummary({
      registry: {
        accountLeaf: registry.accountLeaf,
        accountLeafMeaning: "local account identifier",
        accountManagement: "management remains with the local administrator",
        root: registry.root,
        leafIndex: registry.leafIndex,
        slotIndex: registry.slotIndex,
      },
      passkey: "registered as the World ID proving authenticator",
      secretDerivation: "none; control is demonstrated by a passkey signature",
    });

    assertButton.disabled = false;
    setStatus("Registered");
  } catch (error) {
    setStatus("Registration failed");
    showSummary({ error: error instanceof Error ? error.message : String(error) });
  } finally {
    registerButton.disabled = false;
  }
});

assertButton.addEventListener("click", async () => {
  if (!passkey || !registry) return;

  try {
    registerButton.disabled = true;
    assertButton.disabled = true;
    pendingProof?.dispose();
    pendingProof = null;
    const proofRequest = await createWorldIdProofRequest({
      registryRoot: registry.root,
      rpId: window.location.hostname,
      origin: window.location.origin,
    });
    actionValue.textContent = proofRequest.action;
    setStatus("Signing proof request with passkey");
    const assertion = await requestAssertion(passkey.credentialId, proofRequest.challenge);
    const proofInputs = buildPasskeyOwnershipNoirInputs(
      passkey,
      assertion,
      registry,
      proofRequest.nonce,
      proofRequest.originHash,
    );

    rpValue.textContent = bytesToHex(assertion.rpIdHash);
    challengeValue.textContent = bytesToHex(assertion.challenge);
    setStatus("Proving locally with ProveKit");
    pendingProof = await preparePasskeyProof(proofInputs);
    showSummary({
      sdk: pendingProof.sdk,
      threading: pendingProof.threading,
      artifacts: {
        proverBytes: pendingProof.proverBytes,
        verifierBytes: pendingProof.verifierBytes,
      },
      proof: {
        bytes: pendingProof.proofBytes,
        status: "generated locally from a passkey signature",
      },
      statement: proofStatement(proofRequest, registry.accountLeaf),
      timingsMs: pendingProof.timings,
    });

    setStatus("Verifying proof locally");
    const result = await pendingProof.verify();
    if (!result.valid) throw new Error("the browser verifier rejected the generated proof");
    if (!result.tamperedRejected) throw new Error("the browser verifier accepted a tampered proof");
    setStatus("Passkey ownership proof verified");
    showSummary({
      statement: proofStatement(proofRequest, registry.accountLeaf),
      proof: {
        bytes: pendingProof.proofBytes,
        valid: result.valid,
        tamperedRejected: result.tamperedRejected,
      },
      threading: pendingProof.threading,
      timingsMs: { ...pendingProof.timings, ...result.timings },
    });
    pendingProof.dispose();
    pendingProof = null;
  } catch (error) {
    pendingProof?.dispose();
    pendingProof = null;
    setStatus("Proof failed");
    showSummary({ sdkError: describeProveKitFailure(error) });
  } finally {
    registerButton.disabled = false;
    assertButton.disabled = false;
  }
});
