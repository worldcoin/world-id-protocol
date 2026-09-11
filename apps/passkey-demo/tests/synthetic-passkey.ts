import { p256 } from "@noble/curves/nist.js";

import { base64url, type AssertionWitness, type RegisteredPasskey } from "../src/webauthn";

export type SyntheticPasskey = {
  passkey: RegisteredPasskey;
  /** Produces a WebAuthn-shaped assertion over `challenge` signed by the synthetic key. */
  assert(
    request: { challenge: Uint8Array; rpId: string; origin: string },
    options?: { clientDataJson?: Uint8Array; authenticatorFlags?: number },
  ): Promise<AssertionWitness>;
};

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)));
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

/**
 * Builds a deterministic ES256 key pair that stands in for a platform passkey.
 * Its assertions are cryptographically valid, so they satisfy the circuit;
 * only the browser-side WebAuthn policy checks are bypassed.
 */
export function syntheticPasskey(privateKeyByte = 1): SyntheticPasskey {
  const privateKey = new Uint8Array(32);
  privateKey[31] = privateKeyByte;
  const point = p256.getPublicKey(privateKey, false);

  return {
    passkey: {
      credentialId: Uint8Array.of(privateKeyByte),
      publicKey: { x: point.slice(1, 33), y: point.slice(33, 65) },
    },
    async assert({ challenge, rpId, origin }, options = {}) {
      const clientDataJson = options.clientDataJson ?? new TextEncoder().encode(
        JSON.stringify({ type: "webauthn.get", challenge: base64url(challenge), origin }),
      );
      const rpIdHash = await sha256(new TextEncoder().encode(rpId));
      const authenticatorData = new Uint8Array(37);
      authenticatorData.set(rpIdHash);
      authenticatorData[32] = options.authenticatorFlags ?? 0x05; // UP | UV
      const signature = p256.sign(concat(authenticatorData, await sha256(clientDataJson)), privateKey);

      return {
        authenticatorData,
        clientDataJson,
        challenge,
        challengeIndex: new TextDecoder().decode(clientDataJson).indexOf(base64url(challenge)),
        signature,
        rpIdHash,
      };
    },
  };
}
