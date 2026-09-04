import { describe, expect, it } from "vitest";
import {
  base64url,
  derEcdsaToRawSignature,
  extractP256PublicKeyFromSpki,
  p256BeBytesToLimbs,
  validateAssertionPolicy,
} from "../src/webauthn";
import { createWorldIdProofRequest } from "../src/world-id-proof-request";

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

describe("webauthn helpers", () => {
  it("encodes challenge bytes as unpadded base64url", () => {
    expect(base64url(new Uint8Array([8, 87, 4, 106]))).toBe("CFcEag");
  });

  it("splits P-256 bytes into low, mid, high limbs", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, index) => index);

    expect(p256BeBytesToLimbs(bytes).map((value) => value.toString(16))).toEqual([
      "1112131415161718191a1b1c1d1e1f",
      "2030405060708090a0b0c0d0e0f10",
      "1",
    ]);
  });

  it("converts DER ECDSA signatures to raw r||s", () => {
    const der = Uint8Array.from([
      0x30, 0x46,
      0x02, 0x21, 0x00, ...Array(32).fill(0x91),
      0x02, 0x21, 0x00, ...Array(32).fill(0xa2),
    ]);

    expect(Array.from(derEcdsaToRawSignature(der.buffer))).toEqual([
      ...Array(32).fill(0x91),
      ...Array(32).fill(0xa2),
    ]);
  });

  it("rejects non-canonical DER and out-of-range P-256 scalars", () => {
    const trailingByte = Uint8Array.from([
      0x30, 0x44,
      0x02, 0x20, ...Array(32).fill(0x11),
      0x02, 0x20, ...Array(32).fill(0x22),
      0x00,
    ]);
    expect(() => derEcdsaToRawSignature(trailingByte.buffer)).toThrow("length");

    const zeroR = Uint8Array.from([
      0x30, 0x25,
      0x02, 0x01, 0x00,
      0x02, 0x20, ...Array(32).fill(0x22),
    ]);
    expect(() => derEcdsaToRawSignature(zeroR.buffer)).toThrow("r must be in");

    const redundantPadding = Uint8Array.from([
      0x30, 0x45,
      0x02, 0x21, 0x00, 0x11, ...Array(31).fill(0x11),
      0x02, 0x20, ...Array(32).fill(0x22),
    ]);
    expect(() => derEcdsaToRawSignature(redundantPadding.buffer)).toThrow("non-canonical");
  });

  it("domain-separates proof requests and binds them to a registry root and RP ID", async () => {
    const nonce = Uint8Array.from({ length: 32 }, (_, index) => index);
    const request = await createWorldIdProofRequest({ registryRoot: "123", rpId: "localhost", nonce });

    expect(request.action).toBe("world-id-proof-v1");
    expect(request.message).toBe(
      "world-id-proof-v1\nrpId=localhost\nregistryRoot=123\nnonce=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    expect(Array.from(request.challenge, (byte) => byte.toString(16).padStart(2, "0")).join(""))
      .toBe("78a66d000413695d3e0039af1d67d10ad117081c60605be0f76f70bcea96d54b");

    const otherRoot = await createWorldIdProofRequest({ registryRoot: "124", rpId: "localhost", nonce });
    expect(otherRoot.challenge).not.toEqual(request.challenge);
  });

  it("extracts an uncompressed P-256 point from SPKI", () => {
    const prefix = Uint8Array.from([1, 2, 3, 4]);
    const point = new Uint8Array(65);
    point[0] = 0x04;
    point.fill(0x11, 1, 33);
    point.fill(0x22, 33);
    const spki = new Uint8Array(prefix.length + point.length);
    spki.set(prefix);
    spki.set(point, prefix.length);

    const key = extractP256PublicKeyFromSpki(spki.buffer);
    expect(Array.from(key.x)).toEqual(Array(32).fill(0x11));
    expect(Array.from(key.y)).toEqual(Array(32).fill(0x22));
  });

  it("accepts only a same-origin, user-verified WebAuthn assertion", async () => {
    const challenge = Uint8Array.from({ length: 32 }, (_, index) => index);
    const origin = "http://localhost:5178";
    const rpId = "localhost";
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(await sha256(rpId));
    authenticatorData[32] = 0x05;
    const clientDataJson = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get",
      challenge: base64url(challenge),
      origin,
      crossOrigin: false,
    }));

    await expect(
      validateAssertionPolicy(clientDataJson, authenticatorData, challenge, origin, rpId),
    ).resolves.toBeUndefined();

    const missingUv = authenticatorData.slice();
    missingUv[32] = 0x01;
    await expect(
      validateAssertionPolicy(clientDataJson, missingUv, challenge, origin, rpId),
    ).rejects.toThrow("user-verification flag");

    const crossOrigin = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get",
      challenge: base64url(challenge),
      origin,
      crossOrigin: true,
    }));
    await expect(
      validateAssertionPolicy(crossOrigin, authenticatorData, challenge, origin, rpId),
    ).rejects.toThrow("cross-origin");
  });
});
