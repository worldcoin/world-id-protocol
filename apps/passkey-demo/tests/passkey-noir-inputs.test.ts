import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import {
  buildPasskeyOwnershipNoirInputs,
  deriveP256VerificationWitness,
  scalarWitness,
  signedRadix16,
} from "../src/passkey-noir-inputs";
import { base64url, type AssertionWitness, type RegisteredPasskey } from "../src/webauthn";

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

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
  it("matches ProveKit's fixed P-256 BigCurve verification vector", () => {
    // Source: provekit/noir-examples/p256_bigcurve/Prover.toml at
    // ProveKit commit 98a3471560ed246b92c1397e53094eec624af0f4.
    const witness = deriveP256VerificationWitness(
      hex("16bb245fcd61994350955f6c2a535ef5d9527daff218ddbbe466f3c759c6e618"),
      hex("7635719dc5d6a06cfb051f3c17dd0b81f12eb24bd975230a6b50063abede5561"),
      hex(
        "ba70e8aac3fe331f59c1933a6b03e3ec73e6edc5cbc98e0b7285319d73745f00" +
        "1b4be1033b3a6ea0529c876c33d579cfcc053ce4d82a96fede722f4ab219a6e9",
      ),
      hex("64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"),
    );

    expect(Buffer.from(witness.rPointY).toString("hex")).toBe(
      "24ba2604b2a24bfe1b66f9fe9bc76a0bcbcf9b5c638b5e3178e49bc2ac7f74ad",
    );
    expect(witness.sG.limbs).toEqual([
      "170971773089542374436408670931472561",
      "695132591517413837501917774821349029",
      "29046",
    ]);
    expect({ skew: witness.sG.skew, low: witness.sG.borrowLow, mid: witness.sG.borrowMid }).toEqual({
      skew: false,
      low: false,
      mid: true,
    });
    expect(witness.sP.limbs).toEqual([
      "69012095078019274964239783857231856",
      "1001316324888621778260829132369170621",
      "47633",
    ]);
    expect({ skew: witness.sP.skew, low: witness.sP.borrowLow, mid: witness.sP.borrowMid }).toEqual({
      skew: true,
      low: false,
      mid: false,
    });
    expect(witness.sG.slices).toHaveLength(65);
    expect(witness.sP.slices).toHaveLength(65);
  });

  it("reconstructs canonical P-256 scalars and the circuit limb equations", () => {
    const values = [0n, 1n, 2n, 42n, p256.Point.Fn.ORDER - 1n];
    for (const value of values) {
      const encoding = signedRadix16(value);
      const witness = scalarWitness(value);
      let reconstructed = 0n;
      for (const slice of encoding.slices) reconstructed = reconstructed * 16n + BigInt(slice * 2 - 15);
      reconstructed -= encoding.skew ? 1n : 0n;

      expect(reconstructed).toBe(value);
      expect(witness.slices).toEqual(encoding.slices.map(String));
      expect(witness.limbs).toHaveLength(3);
    }
  });

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
    expect(result.inputs.webauthn.public_key_x_limbs).toEqual(result.inputs.public_key_x_limbs_field);
    expect(result.inputs.webauthn.public_key_y_limbs).toEqual(result.inputs.public_key_y_limbs_field);
    expect(result.inputs.webauthn.s_g_slices).toHaveLength(65);
    expect(result.inputs.merkle_proof).toEqual({
      leaf_index: "4",
      siblings: Array.from({ length: 30 }, (_, index) => String(index + 10)),
    });
    expect(JSON.stringify(result)).not.toContain(Buffer.from(assertion.signature).toString("hex"));
  });

  it("rejects a signature made by a different passkey", async () => {
    const keyA = await fixture(1);
    const keyB = await fixture(2);

    await expect(
      buildPasskeyOwnershipNoirInputs(keyB.passkey, keyA.assertion, {
        leafIndex: 0,
        root: "1",
        slotIndex: 1,
        slotCommitments: ["0", "1", "0", "0", "0", "0", "0"],
        siblings: Array(30).fill("0"),
      }),
    ).rejects.toThrow("signature is invalid");
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

    await expect(
      buildPasskeyOwnershipNoirInputs(passkey, assertion, { ...base, siblings: ["0"] }),
    ).rejects.toThrow("30 Merkle siblings");
    await expect(
      buildPasskeyOwnershipNoirInputs(passkey, assertion, { ...base, root: "01" }),
    ).rejects.toThrow("canonical decimal field");
  });
});
