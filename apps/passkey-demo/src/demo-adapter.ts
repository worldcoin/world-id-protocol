import { base64url, bytesToHex, p256BeBytesToLimbs, type AssertionWitness, type RegisteredPasskey } from "./webauthn";

export type RegistryState = {
  leafIndex: number;
  root: string;
  slotIndex: number;
  slotCommitment: string;
  accountLeaf: string;
};

export type ProofPayload = {
  publicInputs: {
    root: string;
    challenge: string;
    rpIdHash: string;
  };
  privateInputs: {
    publicKeyXLimbs: string[];
    publicKeyYLimbs: string[];
    signature: string;
    authenticatorData: string;
    clientDataJson: string;
    challengeIndex: number;
    slotIndex: number;
  };
};

export async function registerWithLocalBridge(passkey: RegisteredPasskey): Promise<RegistryState> {
  const response = await fetch("/api/register-passkey", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyX: bytesToHex(passkey.publicKey.x),
      publicKeyY: bytesToHex(passkey.publicKey.y),
      slotIndex: 1,
    }),
  });

  if (response.ok) {
    return response.json() as Promise<RegistryState>;
  }

  const localOnlyLeaf = `local:${base64url(passkey.publicKey.x).slice(0, 12)}`;
  return {
    leafIndex: 1,
    root: "local bridge unavailable",
    slotIndex: 1,
    slotCommitment: localOnlyLeaf,
    accountLeaf: localOnlyLeaf,
  };
}

export function buildProofPayload(
  passkey: RegisteredPasskey,
  assertion: AssertionWitness,
  registry: RegistryState,
): ProofPayload {
  return {
    publicInputs: {
      root: registry.root,
      challenge: bytesToHex(assertion.challenge),
      rpIdHash: bytesToHex(assertion.rpIdHash),
    },
    privateInputs: {
      publicKeyXLimbs: p256BeBytesToLimbs(passkey.publicKey.x).map((value) => value.toString()),
      publicKeyYLimbs: p256BeBytesToLimbs(passkey.publicKey.y).map((value) => value.toString()),
      signature: bytesToHex(assertion.signature),
      authenticatorData: bytesToHex(assertion.authenticatorData),
      clientDataJson: new TextDecoder().decode(assertion.clientDataJson),
      challengeIndex: assertion.challengeIndex,
      slotIndex: registry.slotIndex,
    },
  };
}

export async function verifyWithLocalBridge(payload: ProofPayload): Promise<string> {
  const response = await fetch("/api/verify-passkey-proof", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    return "proof payload prepared; local ProveKit bridge is not running";
  }
  const result = (await response.json()) as { status?: string };
  return result.status ?? "verified";
}
