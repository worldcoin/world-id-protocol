import { describe, expect, it } from "vitest";

import { buildPasskeyOwnershipNoirInputs } from "../src/passkey-noir-inputs";
import { syntheticPasskey } from "./synthetic-passkey";

const CHALLENGE = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

async function fixture() {
  const { passkey, assert } = syntheticPasskey();
  const assertion = await assert({ challenge: CHALLENGE, rpId: "localhost", origin: "http://localhost:5178" });
  return { passkey, assertion };
}

describe("passkey Noir input construction", () => {
  it("builds the exact nested ABI with one key source and private Merkle inputs", async () => {
    const { passkey, assertion } = await fixture();
    const nonce = new Uint8Array(32);
    const originHash = Uint8Array.from({ length: 32 }, (_, index) => index);
    const result = await buildPasskeyOwnershipNoirInputs(passkey, assertion, {
      leafIndex: 4,
      root: "123",
      slotIndex: 1,
      slotCommitments: ["0", "456", "0", "0", "0", "0", "0"],
      siblings: Array.from({ length: 30 }, (_, index) => String(index + 10)),
    }, nonce, originHash);

    expect(Object.keys(result)).toEqual(["root", "challenge", "rp_id_hash", "origin_hash", "nonce", "inputs"]);
    expect(result.origin_hash).toEqual(Array.from(originHash, String));
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
    const { passkey, assertion } = await fixture();
    const base = {
      leafIndex: 0,
      root: "1",
      slotIndex: 1,
      slotCommitments: ["0", "1", "0", "0", "0", "0", "0"],
      siblings: Array(30).fill("0"),
    };

    expect(() =>
      buildPasskeyOwnershipNoirInputs(
        passkey, assertion, { ...base, siblings: ["0"] }, new Uint8Array(32), new Uint8Array(32),
      ),
    ).toThrow("30 Merkle siblings");
    expect(() =>
      buildPasskeyOwnershipNoirInputs(
        passkey, assertion, { ...base, root: "01" }, new Uint8Array(32), new Uint8Array(32),
      ),
    ).toThrow("canonical decimal field");
    expect(() =>
      buildPasskeyOwnershipNoirInputs(
        passkey, assertion, base, new Uint8Array(32), new Uint8Array(31),
      ),
    ).toThrow("origin hash must contain exactly 32 bytes");
  });
});
