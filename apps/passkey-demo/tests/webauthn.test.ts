import { describe, expect, it } from "vitest";
import { base64url, derEcdsaToRawSignature, extractP256PublicKeyFromSpki, p256BeBytesToLimbs } from "../src/webauthn";

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
      0x02, 0x21, 0x00, ...Array(32).fill(0x11),
      0x02, 0x21, 0x00, ...Array(32).fill(0x22),
    ]);

    expect(Array.from(derEcdsaToRawSignature(der.buffer))).toEqual([
      ...Array(32).fill(0x11),
      ...Array(32).fill(0x22),
    ]);
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
});
