export const WORLD_ID_PROOF_ACTION = "world-id-proof-v1";
export const WORLD_ID_PROOF_DOMAIN = new TextEncoder().encode("world-id-proof-v1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

export type WorldIdProofRequest = {
  action: typeof WORLD_ID_PROOF_ACTION;
  registryRoot: string;
  rpId: string;
  origin: string;
  originHash: Uint8Array;
  nonce: Uint8Array;
  message: string;
  challenge: Uint8Array;
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fieldBytes(value: string): Uint8Array {
  let field = BigInt(value);
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    bytes[i] = Number(field & 0xffn);
    field >>= 8n;
  }
  return bytes;
}

export async function createWorldIdProofRequest({
  registryRoot,
  rpId,
  origin,
  nonce = crypto.getRandomValues(new Uint8Array(32)),
}: {
  registryRoot: string;
  rpId: string;
  origin: string;
  nonce?: Uint8Array;
}): Promise<WorldIdProofRequest> {
  if (!/^(0|[1-9][0-9]*)$/.test(registryRoot)) {
    throw new Error("registry root must be a canonical decimal field string");
  }
  if (!rpId || rpId.includes("\n")) throw new Error("RP ID must be a non-empty hostname");
  if (!origin || !/^[\x21-\x7e]+$/.test(origin) || origin.includes('"') || origin.includes("\\")) {
    throw new Error("origin must be a non-empty, unescaped ASCII WebAuthn origin");
  }
  if (nonce.length !== 32) throw new Error("proof request nonce must contain exactly 32 bytes");

  const message = [
    WORLD_ID_PROOF_ACTION,
    `rpId=${rpId}`,
    `registryRoot=${registryRoot}`,
    `nonce=${hex(nonce)}`,
  ].join("\n");
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
  const challengeInput = new Uint8Array(128);
  challengeInput.set(WORLD_ID_PROOF_DOMAIN, 0);
  challengeInput.set(rpIdHash, 32);
  challengeInput.set(fieldBytes(registryRoot), 64);
  challengeInput.set(nonce, 96);
  const challenge = new Uint8Array(await crypto.subtle.digest("SHA-256", challengeInput));
  const originHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(origin)),
  );

  return {
    action: WORLD_ID_PROOF_ACTION,
    registryRoot,
    rpId,
    origin,
    originHash,
    nonce: nonce.slice(),
    message,
    challenge,
  };
}
