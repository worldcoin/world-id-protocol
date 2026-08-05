import "./style.css";
import { registerWithLocalBridge, type RegistryState } from "./demo-adapter";
import {
  buildPasskeyOwnershipNoirInputs,
} from "./passkey-noir-inputs";
import {
  describeProveKitFailure,
  preparePasskeyProof,
  type PreparedPasskeyProofResult,
} from "./provekit-runtime";
import { bytesToHex, registerPasskey, requestAssertion, type RegisteredPasskey } from "./webauthn";

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
let pendingProof: PreparedPasskeyProofResult | null = null;

function setStatus(message: string): void {
  runtimeStatus.textContent = message;
}

function showSummary(summary: unknown): void {
  output.textContent = JSON.stringify(summary, null, 2);
}

registerButton.addEventListener("click", async () => {
  try {
    pendingProof?.dispose();
    pendingProof = null;
    verifyButton.disabled = true;
    setStatus("Registering");
    passkey = await registerPasskey();
    registry = await registerWithLocalBridge(passkey);

    credentialValue.textContent = "ES256 passkey created";
    rootValue.textContent = registry.root;
    leafValue.textContent = String(registry.leafIndex);
    showSummary({
      registry: {
        root: registry.root,
        leafIndex: registry.leafIndex,
        slotIndex: registry.slotIndex,
      },
      passkey: "registered as a proving authenticator",
    });

    assertButton.disabled = false;
    setStatus("Registered");
  } catch (error) {
    setStatus("Registration failed");
    showSummary({ error: error instanceof Error ? error.message : String(error) });
  }
});

assertButton.addEventListener("click", async () => {
  if (!passkey || !registry) return;

  try {
    assertButton.disabled = true;
    verifyButton.disabled = true;
    pendingProof?.dispose();
    pendingProof = null;
    setStatus("Requesting assertion");
    const assertion = await requestAssertion(passkey.credentialId);
    const proofInputs = await buildPasskeyOwnershipNoirInputs(passkey, assertion, registry);

    rpValue.textContent = bytesToHex(assertion.rpIdHash);
    challengeValue.textContent = bytesToHex(assertion.challenge);
    setStatus("Proving locally with ProveKit");
    pendingProof = await preparePasskeyProof(proofInputs);
    showSummary({
      sdk: {
        package: pendingProof.sdkPackage,
        commit: pendingProof.sdkCommit,
        tarballSha256: pendingProof.sdkTarballSha256,
      },
      threading: pendingProof.threading,
      artifacts: {
        proverBytes: pendingProof.proverBytes,
        verifierBytes: pendingProof.verifierBytes,
      },
      proof: {
        bytes: pendingProof.proofBytes,
        status: "generated locally; awaiting verification",
      },
      timingsMs: pendingProof.timings,
    });

    verifyButton.disabled = false;
    setStatus("Proof ready");
  } catch (error) {
    pendingProof?.dispose();
    pendingProof = null;
    setStatus("Proof failed");
    showSummary({ sdkError: describeProveKitFailure(error) });
  } finally {
    assertButton.disabled = false;
  }
});

verifyButton.addEventListener("click", async () => {
  if (!pendingProof) return;

  const proofToVerify = pendingProof;
  pendingProof = null;
  try {
    verifyButton.disabled = true;
    setStatus("Verifying proof locally");
    const result = await proofToVerify.verify();
    if (!result.valid) throw new Error("the browser verifier rejected the generated proof");
    if (!result.tamperedRejected) throw new Error("the browser verifier accepted a tampered proof");
    setStatus("Proof verified locally");
    showSummary({
      sdk: {
        package: proofToVerify.sdkPackage,
        commit: proofToVerify.sdkCommit,
        tarballSha256: proofToVerify.sdkTarballSha256,
      },
      threading: proofToVerify.threading,
      artifacts: {
        proverBytes: proofToVerify.proverBytes,
        verifierBytes: proofToVerify.verifierBytes,
      },
      proof: {
        bytes: proofToVerify.proofBytes,
        valid: result.valid,
        tamperedRejected: result.tamperedRejected,
      },
      timingsMs: {
        ...proofToVerify.timings,
        ...result.timings,
      },
    });
  } catch (error) {
    const failure = describeProveKitFailure(error);
    setStatus(failure.code === "ARTIFACT_VERSION" ? "Artifact migration required" : "Local verification unavailable");
    showSummary({ sdkError: failure });
  } finally {
    proofToVerify.dispose();
  }
});
