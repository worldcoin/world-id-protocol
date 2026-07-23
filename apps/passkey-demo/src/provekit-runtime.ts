import {
  initProveKit,
  Proof,
  ProveKitError,
  type ProveKitRuntime,
  type ThreadSetting,
  type ThreadingStatus,
} from "@worldcoin/provekit";
import proverArtifactUrl from "../../../crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkp?url";
import verifierArtifactUrl from "../../../crates/proof/noir/passkey-ownership-proof/artifacts/passkey_ownership_proof.pkv?url";

export type PasskeyArtifactStatus = {
  sdkPackage: "@worldcoin/provekit@0.1.0";
  sdkCommit: "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff";
  sdkTarballSha256: "a1257a1d9512b058a7b8122e29123ac725d6efd1a86e1a634222f56a52563056";
  threading: ThreadingStatus;
  proverBytes: number;
  verifierBytes: number;
};

export type ProveKitFailure = {
  code: string;
  message: string;
};

export type PasskeyProofResult = PasskeyArtifactStatus & {
  proofBytes: number;
  valid: boolean;
  tamperedRejected: boolean;
  timings: {
    initializationMs: number;
    artifactLoadMs: number;
    proverVerifierLoadMs: number;
    witnessAndProveMs: number;
    verifyMs: number;
    tamperCheckMs: number;
  };
};

export type PasskeyVerificationResult = Pick<PasskeyProofResult, "valid" | "tamperedRejected"> & {
  timings: Pick<PasskeyProofResult["timings"], "verifyMs" | "tamperCheckMs">;
};

export type PreparedPasskeyProof = {
  proofBytes: number;
  timings: Pick<PasskeyProofResult["timings"], "proverVerifierLoadMs" | "witnessAndProveMs">;
  verify(): Promise<PasskeyVerificationResult>;
  dispose(): void;
};

export type PreparedPasskeyProofResult = PasskeyArtifactStatus & PreparedPasskeyProof & {
  timings: Pick<
    PasskeyProofResult["timings"],
    "initializationMs" | "artifactLoadMs" | "proverVerifierLoadMs" | "witnessAndProveMs"
  >;
};

async function fetchArtifact(url: string, label: string): Promise<Uint8Array> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Failed to load ${label} artifact: ${response.status} ${response.statusText}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Loads the exact checked-in passkey artifacts through the first-party browser SDK.
 *
 * This deliberately stops before witness generation and never sends artifact
 * or witness data to the bridge.
 */
export async function checkPasskeyArtifacts(
  threads: ThreadSetting = "auto",
): Promise<PasskeyArtifactStatus> {
  const runtime = await initProveKit({ threads });
  const [proverBytes, verifierBytes] = await Promise.all([
    fetchArtifact(proverArtifactUrl, "passkey prover"),
    fetchArtifact(verifierArtifactUrl, "passkey verifier"),
  ]);

  const prover = await runtime.loadProver(proverBytes);
  try {
    const verifier = await runtime.loadVerifier(verifierBytes);
    verifier.dispose();
  } finally {
    prover.dispose();
  }

  return {
    sdkPackage: "@worldcoin/provekit@0.1.0",
    sdkCommit: "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff",
    sdkTarballSha256: "a1257a1d9512b058a7b8122e29123ac725d6efd1a86e1a634222f56a52563056",
    threading: runtime.threading,
    proverBytes: proverBytes.byteLength,
    verifierBytes: verifierBytes.byteLength,
  };
}

type ProofLifecycleResult = Pick<PasskeyProofResult, "proofBytes" | "valid" | "tamperedRejected"> & {
  timings: Omit<PasskeyProofResult["timings"], "initializationMs" | "artifactLoadMs">;
};

/**
 * Generates a proof and retains only the verifier and proof until the caller
 * explicitly requests local verification.
 */
export async function preparePasskeyProofWithRuntime(
  runtime: ProveKitRuntime,
  inputs: Record<string, unknown>,
  proverArtifact: Uint8Array,
  verifierArtifact: Uint8Array,
  now: () => number = () => performance.now(),
): Promise<PreparedPasskeyProof> {
  let prover: Awaited<ReturnType<ProveKitRuntime["loadProver"]>> | undefined;
  let verifier: Awaited<ReturnType<ProveKitRuntime["loadVerifier"]>> | undefined;
  const loadStarted = now();

  try {
    prover = await runtime.loadProver(proverArtifact);
    verifier = await runtime.loadVerifier(verifierArtifact);
    const loaded = now();
    const proof = await prover.prove(inputs);
    const proved = now();
    prover.dispose();
    prover = undefined;

    let pendingVerifier: Awaited<ReturnType<ProveKitRuntime["loadVerifier"]>> | undefined = verifier;
    verifier = undefined;
    return {
      proofBytes: proof.size,
      timings: {
        proverVerifierLoadMs: loaded - loadStarted,
        witnessAndProveMs: proved - loaded,
      },
      async verify() {
        if (!pendingVerifier) throw new Error("the pending proof has already been verified or disposed");
        const activeVerifier = pendingVerifier;
        pendingVerifier = undefined;
        const verifyStarted = now();
        try {
          const valid = await activeVerifier.verify(proof);
          const verified = now();
          const tamperedBytes = proof.bytes;
          tamperedBytes[Math.floor(tamperedBytes.length / 2)] ^= 1;
          let tamperedRejected = false;
          try {
            tamperedRejected = !(await activeVerifier.verify(Proof.fromBytes(tamperedBytes)));
          } catch {
            // A structurally malformed mutation is also a correct rejection.
            tamperedRejected = true;
          } finally {
            tamperedBytes.fill(0);
          }
          const tamperChecked = now();
          return {
            valid,
            tamperedRejected,
            timings: {
              verifyMs: verified - verifyStarted,
              tamperCheckMs: tamperChecked - verified,
            },
          };
        } finally {
          activeVerifier.dispose();
        }
      },
      dispose() {
        pendingVerifier?.dispose();
        pendingVerifier = undefined;
      },
    };
  } finally {
    verifier?.dispose();
    prover?.dispose();
  }
}

/**
 * Runs the sensitive proof lifecycle entirely inside the browser process.
 * This function returns metrics and booleans only; inputs and proof bytes are
 * never logged, serialized into UI state, or sent to an application endpoint.
 */
export async function proveAndVerifyWithRuntime(
  runtime: ProveKitRuntime,
  inputs: Record<string, unknown>,
  proverArtifact: Uint8Array,
  verifierArtifact: Uint8Array,
  now: () => number = () => performance.now(),
): Promise<ProofLifecycleResult> {
  const pending = await preparePasskeyProofWithRuntime(
    runtime,
    inputs,
    proverArtifact,
    verifierArtifact,
    now,
  );
  try {
    const verification = await pending.verify();
    return {
      proofBytes: pending.proofBytes,
      valid: verification.valid,
      tamperedRejected: verification.tamperedRejected,
      timings: {
        ...pending.timings,
        ...verification.timings,
      },
    };
  } finally {
    pending.dispose();
  }
}

/** Loads local artifacts and generates a proof without verifying it. */
export async function preparePasskeyProof(
  inputs: Record<string, unknown>,
  threads: ThreadSetting = "auto",
): Promise<PreparedPasskeyProofResult> {
  const initializationStarted = performance.now();
  const runtime = await initProveKit({ threads });
  const initialized = performance.now();
  const artifactStarted = initialized;
  const [proverBytes, verifierBytes] = await Promise.all([
    fetchArtifact(proverArtifactUrl, "passkey prover"),
    fetchArtifact(verifierArtifactUrl, "passkey verifier"),
  ]);
  const artifactsLoaded = performance.now();
  const pending = await preparePasskeyProofWithRuntime(runtime, inputs, proverBytes, verifierBytes);

  return {
    sdkPackage: "@worldcoin/provekit@0.1.0",
    sdkCommit: "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff",
    sdkTarballSha256: "a1257a1d9512b058a7b8122e29123ac725d6efd1a86e1a634222f56a52563056",
    threading: runtime.threading,
    proverBytes: proverBytes.byteLength,
    verifierBytes: verifierBytes.byteLength,
    proofBytes: pending.proofBytes,
    timings: {
      initializationMs: initialized - initializationStarted,
      artifactLoadMs: artifactsLoaded - artifactStarted,
      ...pending.timings,
    },
    verify: () => pending.verify(),
    dispose: () => pending.dispose(),
  };
}

/** Loads local artifacts, proves the supplied Noir inputs, and verifies locally. */
export async function proveAndVerifyPasskey(
  inputs: Record<string, unknown>,
  threads: ThreadSetting = "auto",
): Promise<PasskeyProofResult> {
  const initializationStarted = performance.now();
  const runtime = await initProveKit({ threads });
  const initialized = performance.now();
  const artifactStarted = initialized;
  const [proverBytes, verifierBytes] = await Promise.all([
    fetchArtifact(proverArtifactUrl, "passkey prover"),
    fetchArtifact(verifierArtifactUrl, "passkey verifier"),
  ]);
  const artifactsLoaded = performance.now();
  const proofResult = await proveAndVerifyWithRuntime(runtime, inputs, proverBytes, verifierBytes);

  return {
    sdkPackage: "@worldcoin/provekit@0.1.0",
    sdkCommit: "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff",
    sdkTarballSha256: "a1257a1d9512b058a7b8122e29123ac725d6efd1a86e1a634222f56a52563056",
    threading: runtime.threading,
    proverBytes: proverBytes.byteLength,
    verifierBytes: verifierBytes.byteLength,
    ...proofResult,
    timings: {
      initializationMs: initialized - initializationStarted,
      artifactLoadMs: artifactsLoaded - artifactStarted,
      ...proofResult.timings,
    },
  };
}

export function describeProveKitFailure(error: unknown): ProveKitFailure {
  if (error instanceof ProveKitError) {
    return { code: error.code, message: error.message };
  }
  return {
    code: "UNKNOWN",
    message: error instanceof Error ? error.message : String(error),
  };
}
