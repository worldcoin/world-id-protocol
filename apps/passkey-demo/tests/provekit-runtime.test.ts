import {
  Proof,
  ProveKitError,
  ProveKitErrorCode,
  type ProveKitRuntime,
} from "@worldcoin/provekit";
import { describe, expect, it, vi } from "vitest";

import {
  describeProveKitFailure,
  preparePasskeyProofWithRuntime,
  proveAndVerifyWithRuntime,
} from "../src/provekit-runtime";

describe("ProveKit passkey runtime", () => {
  it("preserves typed artifact-version failures", () => {
    const failure = describeProveKitFailure(
      new ProveKitError(
        ProveKitErrorCode.ARTIFACT_VERSION,
        "Unsupported prover artifact version 1.1; expected 2.0 or newer compatible minor",
      ),
    );

    expect(failure).toEqual({
      code: "ARTIFACT_VERSION",
      message: "Unsupported prover artifact version 1.1; expected 2.0 or newer compatible minor",
    });
  });

  it("does not expose arbitrary error objects", () => {
    expect(describeProveKitFailure({ witness: "secret" })).toEqual({
      code: "UNKNOWN",
      message: "[object Object]",
    });
  });

  it("proves, verifies, rejects a tampered proof, and disposes both handles", async () => {
    const proofBytes = Uint8Array.of(1, 2, 3, 4);
    const proverDispose = vi.fn();
    const verifierDispose = vi.fn();
    const prove = vi.fn().mockResolvedValue(Proof.fromBytes(proofBytes));
    const verify = vi.fn(async (proof: Proof) =>
      proof.bytes.length === proofBytes.length && proof.bytes.every((byte, index) => byte === proofBytes[index]),
    );
    const runtime = {
      threading: { mode: "single", threads: 1 },
      loadProver: vi.fn().mockResolvedValue({ prove, serialize: vi.fn(), dispose: proverDispose }),
      loadVerifier: vi.fn().mockResolvedValue({ verify, serialize: vi.fn(), dispose: verifierDispose }),
      inspectProver: vi.fn(),
    } as unknown as ProveKitRuntime;
    let tick = 0;
    const inputs = { private_value: "kept in browser memory" };

    const result = await proveAndVerifyWithRuntime(
      runtime,
      inputs,
      Uint8Array.of(10),
      Uint8Array.of(11),
      () => tick++,
    );

    expect(result).toEqual({
      proofBytes: 4,
      valid: true,
      tamperedRejected: true,
      timings: { proverVerifierLoadMs: 1, witnessAndProveMs: 1, verifyMs: 1, tamperCheckMs: 1 },
    });
    expect(prove).toHaveBeenCalledWith(inputs);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(verifierDispose).toHaveBeenCalledOnce();
    expect(proverDispose).toHaveBeenCalledOnce();
  });

  it("defers verification until the prepared proof is explicitly verified", async () => {
    const proofBytes = Uint8Array.of(1, 2, 3, 4);
    const proverDispose = vi.fn();
    const verifierDispose = vi.fn();
    const prove = vi.fn().mockResolvedValue(Proof.fromBytes(proofBytes));
    const verify = vi.fn(async (proof: Proof) =>
      proof.bytes.length === proofBytes.length && proof.bytes.every((byte, index) => byte === proofBytes[index]),
    );
    const runtime = {
      threading: { mode: "single", threads: 1 },
      loadProver: vi.fn().mockResolvedValue({ prove, serialize: vi.fn(), dispose: proverDispose }),
      loadVerifier: vi.fn().mockResolvedValue({ verify, serialize: vi.fn(), dispose: verifierDispose }),
      inspectProver: vi.fn(),
    } as unknown as ProveKitRuntime;
    let tick = 0;

    const pending = await preparePasskeyProofWithRuntime(
      runtime,
      { private_value: "kept in browser memory" },
      Uint8Array.of(10),
      Uint8Array.of(11),
      () => tick++,
    );

    expect(pending.proofBytes).toBe(4);
    expect(verify).not.toHaveBeenCalled();
    expect(proverDispose).toHaveBeenCalledOnce();
    expect(verifierDispose).not.toHaveBeenCalled();

    await expect(pending.verify()).resolves.toEqual({
      valid: true,
      tamperedRejected: true,
      timings: { verifyMs: 1, tamperCheckMs: 1 },
    });
    expect(verify).toHaveBeenCalledTimes(2);
    expect(verifierDispose).toHaveBeenCalledOnce();
  });

  it("disposes the prover when verifier loading fails", async () => {
    const proverDispose = vi.fn();
    const runtime = {
      threading: { mode: "single", threads: 1 },
      loadProver: vi.fn().mockResolvedValue({ prove: vi.fn(), serialize: vi.fn(), dispose: proverDispose }),
      loadVerifier: vi.fn().mockRejectedValue(new Error("verifier load failed")),
      inspectProver: vi.fn(),
    } as unknown as ProveKitRuntime;

    await expect(
      proveAndVerifyWithRuntime(runtime, {}, Uint8Array.of(10), Uint8Array.of(11)),
    ).rejects.toThrow("verifier load failed");
    expect(proverDispose).toHaveBeenCalledOnce();
  });
});
