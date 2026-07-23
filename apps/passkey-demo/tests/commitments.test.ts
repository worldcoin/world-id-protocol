import { describe, expect, it } from "vitest";
import {
  PASSKEY_SLOT_COUNT,
  mixedAuthenticatorSetCommitment,
  p256HexToLimbs,
  passkeySlotCommitment,
} from "../src/commitments";

describe("mixed passkey commitments", () => {
  it("uses the protocol P-256 limb order", () => {
    const coordinate = `0x${Array.from({ length: 32 }, (_, index) => index.toString(16).padStart(2, "0")).join("")}`;
    expect(p256HexToLimbs(coordinate).map((value) => value.toString(16))).toEqual([
      "1112131415161718191a1b1c1d1e1f",
      "2030405060708090a0b0c0d0e0f10",
      "1",
    ]);
  });

  it("is key- and slot-sensitive", () => {
    const keyA = `0x${"01".repeat(32)}`;
    const keyB = `0x${"02".repeat(32)}`;
    const slotA = passkeySlotCommitment(keyA, keyB);
    const slotB = passkeySlotCommitment(keyA, `0x${"03".repeat(32)}`);
    expect(slotA).toBe(10229045674677631920398600638535557632190592957743458177380587734662328118697n);
    expect(slotA).not.toBe(slotB);

    const left = Array<bigint>(PASSKEY_SLOT_COUNT).fill(0n);
    const right = [...left];
    left[0] = slotA;
    right[1] = slotA;
    expect(mixedAuthenticatorSetCommitment(left)).not.toBe(mixedAuthenticatorSetCommitment(right));
    expect(mixedAuthenticatorSetCommitment(right)).toBe(
      12009126683121953174053880760425134641314796832317154930329701454289069372463n,
    );
  });

  it("rejects malformed coordinates and slot sets", () => {
    expect(() => passkeySlotCommitment("0x01", `0x${"02".repeat(32)}`)).toThrow("32-byte hex");
    expect(() => mixedAuthenticatorSetCommitment([0n])).toThrow("expected 7");
  });
});
