import {
  initProveKit,
  Proof,
  ProveKitError,
  type ProveKitRuntime,
  type ThreadSetting,
  type ThreadingStatus,
} from "@worldcoin/provekit";
import type { PasskeyOwnershipNoirInputs } from "./passkey-noir-inputs";
import proverArtifactUrl from "../artifacts/passkey_ownership_proof.pkp?url";
import verifierArtifactUrl from "../artifacts/passkey_ownership_proof.pkv?url";

/** Provenance of the pinned browser SDK, surfaced in the demo UI. */
export const SDK_PROVENANCE = {
  package: "@worldcoin/provekit@0.1.0",
  commit: "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff",
  tarballSha256: "a1257a1d9512b058a7b8122e29123ac725d6efd1a86e1a634222f56a52563056",
} as const;

export type ProveKitFailure = {
  code: string;
  message: string;
};

export type VerificationResult = {
  valid: boolean;
  tamperedRejected: boolean;
  timings: {
    verifyMs: number;
    tamperCheckMs: number;
  };
};

/** A generated proof whose verifier stays loaded until `verify` or `dispose` is called. */
export type PendingProof = {
  proofBytes: number;
  timings: {
    proverVerifierLoadMs: number;
    witnessAndProveMs: number;
  };
  verify(): Promise<VerificationResult>;
  dispose(): void;
};

export type ProofLifecycleResult = Pick<VerificationResult, "valid" | "tamperedRejected"> & {
  proofBytes: number;
  timings: PendingProof["timings"] & VerificationResult["timings"];
};

export type PreparedPasskeyProof = PendingProof & {
  sdk: typeof SDK_PROVENANCE;
  threading: ThreadingStatus;
  proverBytes: number;
  verifierBytes: number;
  timings: PendingProof["timings"] & {
    initializationMs: number;
    artifactLoadMs: number;
  };
};

type LoadedVerifier = Awaited<ReturnType<ProveKitRuntime["loadVerifier"]>>;

async function fetchArtifact(url: string, label: string): Promise<Uint8Array> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Failed to load ${label} artifact: ${response.status} ${response.statusText}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

/** Fetches the checked-in browser PKP/PKV pair. */
export function loadPasskeyArtifacts(): Promise<[prover: Uint8Array, verifier: Uint8Array]> {
  return Promise.all([
    fetchArtifact(proverArtifactUrl, "passkey prover"),
    fetchArtifact(verifierArtifactUrl, "passkey verifier"),
  ]);
}

async function verifyWithTamperCheck(
  verifier: LoadedVerifier,
  proof: Proof,
  now: () => number,
): Promise<VerificationResult> {
  const verifyStarted = now();
  const valid = await verifier.verify(proof);
  const verified = now();

  const tamperedBytes = proof.bytes;
  tamperedBytes[Math.floor(tamperedBytes.length / 2)] ^= 1;
  let tamperedRejected: boolean;
  try {
    tamperedRejected = !(await verifier.verify(Proof.fromBytes(tamperedBytes)));
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
}

/**
 * Generates a proof and keeps only the verifier and proof alive until the
 * caller explicitly verifies or disposes the result. Inputs and proof bytes
 * never leave the browser process.
 */
export async function preparePasskeyProofWithRuntime(
  runtime: ProveKitRuntime,
  inputs: Record<string, unknown>,
  proverArtifact: Uint8Array,
  verifierArtifact: Uint8Array,
  now: () => number = () => performance.now(),
): Promise<PendingProof> {
  const loadStarted = now();
  const prover = await runtime.loadProver(proverArtifact);
  let verifier: LoadedVerifier | undefined;
  let loaded: number;
  let proof: Proof;
  try {
    verifier = await runtime.loadVerifier(verifierArtifact);
    loaded = now();
    proof = await prover.prove(inputs);
  } catch (error) {
    verifier?.dispose();
    throw error;
  } finally {
    prover.dispose();
  }
  const proved = now();

  let pendingVerifier: LoadedVerifier | undefined = verifier;
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
      try {
        return await verifyWithTamperCheck(activeVerifier, proof, now);
      } finally {
        activeVerifier.dispose();
      }
    },
    dispose() {
      pendingVerifier?.dispose();
      pendingVerifier = undefined;
    },
  };
}

/** Proves and immediately verifies; returns metrics and booleans only. */
export async function proveAndVerifyWithRuntime(
  runtime: ProveKitRuntime,
  inputs: Record<string, unknown>,
  proverArtifact: Uint8Array,
  verifierArtifact: Uint8Array,
  now: () => number = () => performance.now(),
): Promise<ProofLifecycleResult> {
  const pending = await preparePasskeyProofWithRuntime(runtime, inputs, proverArtifact, verifierArtifact, now);
  try {
    const verification = await pending.verify();
    return {
      proofBytes: pending.proofBytes,
      valid: verification.valid,
      tamperedRejected: verification.tamperedRejected,
      timings: { ...pending.timings, ...verification.timings },
    };
  } finally {
    pending.dispose();
  }
}

/** Initialises the SDK, loads the checked-in artifacts, and generates a proof without verifying it. */
export async function preparePasskeyProof(
  inputs: PasskeyOwnershipNoirInputs,
  threads: ThreadSetting = "auto",
): Promise<PreparedPasskeyProof> {
  const initializationStarted = performance.now();
  const runtime = await initProveKit({ threads });
  const initialized = performance.now();
  const [proverBytes, verifierBytes] = await loadPasskeyArtifacts();
  const artifactsLoaded = performance.now();
  const pending = await preparePasskeyProofWithRuntime(runtime, inputs, proverBytes, verifierBytes);

  return {
    ...pending,
    sdk: SDK_PROVENANCE,
    threading: runtime.threading,
    proverBytes: proverBytes.byteLength,
    verifierBytes: verifierBytes.byteLength,
    timings: {
      initializationMs: initialized - initializationStarted,
      artifactLoadMs: artifactsLoaded - initialized,
      ...pending.timings,
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
