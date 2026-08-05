import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import { buildPasskeyOwnershipNoirInputs } from "../src/passkey-noir-inputs";
import { base64url, type AssertionWitness, type RegisteredPasskey } from "../src/webauthn";

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}

async function digest(bytes: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy.buffer));
}

async function fixture(privateKeyByte: number): Promise<{
  passkey: RegisteredPasskey;
  assertion: AssertionWitness;
}> {
  const privateKey = new Uint8Array(32);
  privateKey[31] = privateKeyByte;
  const publicKey = p256.getPublicKey(privateKey, false);
  const challenge = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const clientDataJson = new TextEncoder().encode(
    JSON.stringify({ type: "webauthn.get", challenge: base64url(challenge), origin: "https://127.0.0.1:5178" }),
  );
  const rpIdHash = await digest(new TextEncoder().encode("127.0.0.1"));
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpIdHash);
  authenticatorData[32] = 0x05;
  const signedBytes = concat(authenticatorData, await digest(clientDataJson));
  const signature = p256.sign(signedBytes, privateKey);

  return {
    passkey: {
      credentialId: Uint8Array.of(privateKeyByte),
      publicKey: { x: publicKey.slice(1, 33), y: publicKey.slice(33, 65) },
    },
    assertion: {
      authenticatorData,
      clientDataJson,
      challenge,
      challengeIndex: new TextDecoder().decode(clientDataJson).indexOf(base64url(challenge)),
      signature,
      rpIdHash,
    },
  };
}

describe("passkey Noir input construction", () => {
  it("builds the exact nested ABI with one key source and private Merkle inputs", async () => {
    const { passkey, assertion } = await fixture(1);
    const result = await buildPasskeyOwnershipNoirInputs(passkey, assertion, {
      leafIndex: 4,
      root: "123",
      slotIndex: 1,
      slotCommitments: ["0", "456", "0", "0", "0", "0", "0"],
      siblings: Array.from({ length: 30 }, (_, index) => String(index + 10)),
    });

    expect(Object.keys(result)).toEqual(["root", "challenge", "rp_id_hash", "inputs"]);
    expect(result.inputs.webauthn.client_data_json.storage).toHaveLength(256);
    expect(result.inputs.webauthn.client_data_json.len).toBe(String(assertion.clientDataJson.length));
    expect(result.inputs.webauthn.authenticator_data.storage).toHaveLength(64);
    expect(result.inputs.webauthn.authenticator_data.len).toBe("37");
    expect(Object.keys(result.inputs.webauthn)).toEqual([
      "public_key_x",
      "public_key_y",
      "signature",
      "client_data_json",
      "authenticator_data",
      "challenge_index",
    ]);
    expect(result.inputs.merkle_proof).toEqual({
      leaf_index: "4",
      siblings: Array.from({ length: 30 }, (_, index) => String(index + 10)),
    });
    expect(JSON.stringify(result)).not.toContain(Buffer.from(assertion.signature).toString("hex"));
  });

  it("rejects malformed registry witness dimensions and non-canonical fields", async () => {
    const { passkey, assertion } = await fixture(1);
    const base = {
      leafIndex: 0,
      root: "1",
      slotIndex: 1,
      slotCommitments: ["0", "1", "0", "0", "0", "0", "0"],
      siblings: Array(30).fill("0"),
    };

    expect(() =>
      buildPasskeyOwnershipNoirInputs(passkey, assertion, { ...base, siblings: ["0"] }),
    ).toThrow("30 Merkle siblings");
    expect(() =>
      buildPasskeyOwnershipNoirInputs(passkey, assertion, { ...base, root: "01" }),
    ).toThrow("canonical decimal field");
  });
});
