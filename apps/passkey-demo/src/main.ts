import "./style.css";
import { buildProofPayload, registerWithLocalBridge, verifyWithLocalBridge, type ProofPayload, type RegistryState } from "./demo-adapter";
import { base64url, bytesToHex, registerPasskey, requestAssertion, type RegisteredPasskey } from "./webauthn";

const registerButton = document.querySelector<HTMLButtonElement>("#register-button")!;
const assertButton = document.querySelector<HTMLButtonElement>("#assert-button")!;
const verifyButton = document.querySelector<HTMLButtonElement>("#verify-button")!;
const runtimeStatus = document.querySelector<HTMLElement>("#runtime-status")!;
const rootValue = document.querySelector<HTMLElement>("#root-value")!;
const leafValue = document.querySelector<HTMLElement>("#leaf-value")!;
const credentialValue = document.querySelector<HTMLElement>("#credential-value")!;
const rpValue = document.querySelector<HTMLElement>("#rp-value")!;
const challengeValue = document.querySelector<HTMLElement>("#challenge-value")!;
const output = document.querySelector<HTMLElement>("#output")!;

let passkey: RegisteredPasskey | null = null;
let registry: RegistryState | null = null;
let proofPayload: ProofPayload | null = null;

function setStatus(message: string): void {
  runtimeStatus.textContent = message;
}

function showPayload(payload: unknown): void {
  output.textContent = JSON.stringify(payload, null, 2);
}

registerButton.addEventListener("click", async () => {
  try {
    setStatus("Registering");
    passkey = await registerPasskey();
    registry = await registerWithLocalBridge(passkey);

    credentialValue.textContent = base64url(passkey.credentialId);
    rootValue.textContent = registry.root;
    leafValue.textContent = String(registry.leafIndex);
    showPayload({
      publicKeyX: bytesToHex(passkey.publicKey.x),
      publicKeyY: bytesToHex(passkey.publicKey.y),
      registry,
    });

    assertButton.disabled = false;
    setStatus("Registered");
  } catch (error) {
    setStatus("Registration failed");
    showPayload({ error: error instanceof Error ? error.message : String(error) });
  }
});

assertButton.addEventListener("click", async () => {
  if (!passkey || !registry) return;

  try {
    setStatus("Requesting assertion");
    const assertion = await requestAssertion(passkey.credentialId);
    proofPayload = buildProofPayload(passkey, assertion, registry);

    rpValue.textContent = bytesToHex(assertion.rpIdHash);
    challengeValue.textContent = bytesToHex(assertion.challenge);
    showPayload(proofPayload);

    verifyButton.disabled = false;
    setStatus("Witness ready");
  } catch (error) {
    setStatus("Proof failed");
    showPayload({ error: error instanceof Error ? error.message : String(error) });
  }
});

verifyButton.addEventListener("click", async () => {
  if (!proofPayload) return;

  setStatus("Verifying");
  const status = await verifyWithLocalBridge(proofPayload);
  setStatus(status);
});
