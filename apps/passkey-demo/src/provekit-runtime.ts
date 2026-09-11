import {
  initProveKit,
  Proof,
  ProveKitError,
  ProveKitErrorCode,
  type ProveKitRuntime,
  type ThreadSetting,
  type ThreadingStatus,
} from "@worldcoin/provekit";
import initAcvm, { executeProgram, type ForeignCallHandler, type WitnessStack } from "@noir-lang/acvm_js";
import acvmWasmUrl from "@noir-lang/acvm_js/web/acvm_js_bg.wasm?url";
import initAbi, { abiEncode, type InputMap } from "@noir-lang/noirc_abi";
import abiWasmUrl from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url";
import type { PasskeyOwnershipNoirInputs } from "./passkey-noir-inputs";
import proverArtifactUrl from "../artifacts/passkey_ownership_proof.pkp?url";
import verifierArtifactUrl from "../artifacts/passkey_ownership_proof.pkv?url";

/** Provenance of the pinned browser SDK, surfaced in the demo UI. */
export const SDK_PROVENANCE = {
  package: "@worldcoin/provekit@0.1.1",
  releaseCommit: "11bfde0c3409ae55a924ff07ce394e7cdab6c040",
  tarballSha256: "d093f14ef043050779c826af6c574f94f9c836db1f16017daf2cdbfcbe342270",
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
    /** Time spent by Noir/ACVM solving the circuit inputs into a witness. */
    witnessGenerationMs: number | null;
    /** Time spent by the ProveKit backend turning the witness into a proof. */
    provingMs: number;
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

type LowLevelProverHandle = {
  getCircuit(): Uint8Array;
  proveBytes(witness: Record<string, string>): Uint8Array;
  free(): void;
};

type LowLevelProveKitModule = {
  Prover: new (artifact: Uint8Array) => LowLevelProverHandle;
};

// The public ProveKit `Prover.prove` API intentionally combines witness generation
// and proving. The 0.1.x runtime keeps its initialized WASM module on the runtime
// object, which lets this diagnostic demo measure the two operations separately.
type RuntimeWithLowLevelModule = ProveKitRuntime & { module?: LowLevelProveKitModule };

type WitnessExecution = {
  witnessMap: Map<unknown, unknown>;
  release(): void;
};

type CompiledCircuit = {
  abi: Parameters<typeof abiEncode>[0];
  bytecode: string;
};

let noirRuntimeInitialization: Promise<void> | undefined;

async function ensureNoirRuntime(): Promise<void> {
  if (typeof window === "undefined") return;
  noirRuntimeInitialization ??= Promise.all([initAcvm(acvmWasmUrl), initAbi(abiWasmUrl)]).then(() => undefined);
  await noirRuntimeInitialization;
}

async function executeNoirWitness(
  circuit: CompiledCircuit,
  inputs: Record<string, unknown>,
): Promise<WitnessExecution> {
  let witnessMap: Map<unknown, unknown> | undefined;
  try {
    await ensureNoirRuntime();
    const initialWitness = abiEncode(circuit.abi, inputs as InputMap);
    const stack = (await executeProgram(
      base64Decode(circuit.bytecode),
      initialWitness,
      defaultForeignCallHandler,
    )) as WitnessStack;
    if (!Array.isArray(stack) || stack.length === 0 || !(stack[0]?.witness instanceof Map)) {
      throw new Error("ACVM witness stack is empty or malformed");
    }
    witnessMap = stack[0].witness as Map<unknown, unknown>;
    return {
      witnessMap,
      release() {
        witnessMap?.clear();
      },
    };
  } catch (error) {
    witnessMap?.clear();
    if (error instanceof ProveKitError) throw error;
    throw new ProveKitError(ProveKitErrorCode.WITNESS_GENERATION, "Noir witness generation failed", {
      cause: error,
    });
  }
}

const defaultForeignCallHandler: ForeignCallHandler = async (name, args) => {
  if (name === "print") return [];
  throw new Error(`Unexpected oracle during execution: ${name}(${args.join(", ")})`);
};

function base64Decode(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

const BN254_MODULUS = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
const WITNESS_INDEX = /^(?:Witness\()?([0-9]+)\)?$/;
const FIELD_HEX = /^(?:0x)?([0-9a-fA-F]+)$/;

function convertWitnessMap(witnessMap: Map<unknown, unknown>): Record<string, string> {
  if (witnessMap.size === 0) {
    throw new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, "Witness map is empty");
  }
  const converted: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [rawIndex, rawValue] of witnessMap) {
    const match = WITNESS_INDEX.exec(String(rawIndex));
    const index = match?.[1];
    if (!index || !/^(0|[1-9][0-9]*)$/.test(index)) {
      throw new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, "Witness index is not canonical");
    }
    if (Object.hasOwn(converted, index)) {
      throw new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, `Duplicate witness index: ${index}`);
    }
    const value = String(rawValue);
    const field = FIELD_HEX.exec(value)?.[1];
    if (!field || field.length > 64 || BigInt(`0x${field}`) >= BN254_MODULUS) {
      throw new ProveKitError(ProveKitErrorCode.WITNESS_FORMAT, `Witness ${index} is not canonical`);
    }
    converted[index] = `0x${field.toLowerCase()}`;
  }
  return converted;
}

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
  let witnessStarted: number | null = null;
  let witnessGenerated: number | null = null;
  let proved: number;
  let rawProver: LowLevelProverHandle | undefined;
  let witnessExecution: WitnessExecution | undefined;
  try {
    verifier = await runtime.loadVerifier(verifierArtifact);
    loaded = now();
    const lowLevelModule = (runtime as RuntimeWithLowLevelModule).module;
    if (lowLevelModule) {
      // Extract the circuit before starting the witness timer. This is artifact
      // loading work, not witness solving.
      rawProver = new lowLevelModule.Prover(proverArtifact);
      const circuit = JSON.parse(new TextDecoder().decode(rawProver.getCircuit())) as CompiledCircuit;

      witnessStarted = now();
      witnessExecution = await executeNoirWitness(circuit, inputs);
      witnessGenerated = now();

      const converted = convertWitnessMap(witnessExecution.witnessMap);
      try {
        proof = Proof.fromBytes(rawProver.proveBytes(converted));
      } finally {
        for (const key of Object.keys(converted)) converted[key] = "0x0";
      }
      proved = now();
    } else {
      // Keep the helper usable with lightweight test doubles that only expose
      // the public ProveKit API. That API cannot provide a timing split.
      proof = await prover.prove(inputs);
      proved = now();
    }
  } catch (error) {
    verifier?.dispose();
    throw error;
  } finally {
    witnessExecution?.release();
    rawProver?.free();
    prover.dispose();
  }

  let pendingVerifier: LoadedVerifier | undefined = verifier;
  return {
    proofBytes: proof.size,
    timings: {
      proverVerifierLoadMs: loaded - loadStarted,
      witnessGenerationMs:
        witnessGenerated === null || witnessStarted === null ? null : witnessGenerated - witnessStarted,
      provingMs: witnessGenerated === null ? proved - loaded : proved - witnessGenerated,
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
