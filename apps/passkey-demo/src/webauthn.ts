export type P256PublicKey = {
  x: Uint8Array;
  y: Uint8Array;
};

export type RegisteredPasskey = {
  credentialId: Uint8Array;
  publicKey: P256PublicKey;
};

export type AssertionWitness = {
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  challenge: Uint8Array;
  challengeIndex: number;
  signature: Uint8Array;
  rpIdHash: Uint8Array;
};

const ES256 = -7;

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function randomChallenge(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function p256BeBytesToLimbs(bytes: Uint8Array): [bigint, bigint, bigint] {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }

  const fold = (slice: Uint8Array): bigint => {
    let result = 0n;
    for (const byte of slice) {
      result = (result << 8n) | BigInt(byte);
    }
    return result;
  };

  return [fold(bytes.slice(17, 32)), fold(bytes.slice(2, 17)), fold(bytes.slice(0, 2))];
}

export function extractP256PublicKeyFromSpki(spki: ArrayBuffer): P256PublicKey {
  const bytes = new Uint8Array(spki);
  const uncompressedPointOffset = bytes.length - 65;
  if (uncompressedPointOffset < 0 || bytes[uncompressedPointOffset] !== 0x04) {
    throw new Error("SPKI does not end with an uncompressed P-256 point");
  }

  return {
    x: bytes.slice(uncompressedPointOffset + 1, uncompressedPointOffset + 33),
    y: bytes.slice(uncompressedPointOffset + 33, uncompressedPointOffset + 65),
  };
}

export function derEcdsaToRawSignature(der: ArrayBuffer): Uint8Array {
  const bytes = new Uint8Array(der);
  if (bytes[0] !== 0x30) {
    throw new Error("ECDSA signature is not a DER sequence");
  }
  let offset = 2;
  if (bytes[1] & 0x80) {
    const lenBytes = bytes[1] & 0x7f;
    offset = 2 + lenBytes;
  }

  const readInt = (): Uint8Array => {
    if (bytes[offset] !== 0x02) {
      throw new Error("ECDSA signature integer is malformed");
    }
    const len = bytes[offset + 1];
    const value = bytes.slice(offset + 2, offset + 2 + len);
    offset += 2 + len;
    const trimmed = value[0] === 0 ? value.slice(1) : value;
    if (trimmed.length > 32) {
      throw new Error("ECDSA signature integer exceeds 32 bytes");
    }
    const padded = new Uint8Array(32);
    padded.set(trimmed, 32 - trimmed.length);
    return padded;
  };

  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

export async function registerPasskey(): Promise<RegisteredPasskey> {
  const challenge = randomChallenge();
  const userId = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: toArrayBuffer(challenge),
      rp: { id: window.location.hostname, name: "World ID Passkey Demo" },
      user: {
        id: toArrayBuffer(userId),
        name: "demo@world.id",
        displayName: "World ID Demo",
      },
      pubKeyCredParams: [{ type: "public-key", alg: ES256 }],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      attestation: "none",
    },
  });

  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("browser did not return a public key credential");
  }
  const response = credential.response;
  if (!(response instanceof AuthenticatorAttestationResponse)) {
    throw new Error("credential response is not attestation data");
  }
  const spki = response.getPublicKey();
  if (!spki) {
    throw new Error("browser did not expose the passkey public key");
  }
  if (response.getPublicKeyAlgorithm() !== ES256) {
    throw new Error("passkey is not ES256/P-256");
  }

  return {
    credentialId: new Uint8Array(credential.rawId),
    publicKey: extractP256PublicKeyFromSpki(spki),
  };
}

export async function requestAssertion(credentialId: Uint8Array): Promise<AssertionWitness> {
  const challenge = randomChallenge();
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(challenge),
      rpId: window.location.hostname,
      allowCredentials: [{ type: "public-key", id: toArrayBuffer(credentialId) }],
      userVerification: "preferred",
    },
  });

  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("browser did not return a public key assertion");
  }
  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) {
    throw new Error("credential response is not assertion data");
  }

  const clientDataJson = new Uint8Array(response.clientDataJSON);
  const challengeIndex = new TextDecoder().decode(clientDataJson).indexOf(base64url(challenge));
  if (challengeIndex < 0) {
    throw new Error("clientDataJSON does not contain the challenge");
  }
  const authenticatorData = new Uint8Array(response.authenticatorData);

  return {
    authenticatorData,
    clientDataJson,
    challenge,
    challengeIndex,
    signature: derEcdsaToRawSignature(response.signature),
    rpIdHash: authenticatorData.slice(0, 32),
  };
}
