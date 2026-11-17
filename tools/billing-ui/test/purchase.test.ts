import { encodeAbiParameters, encodeEventTopics, type Address, type Hash } from "viem";
import { describe, expect, it } from "vitest";
import { billingAbi } from "../src/abi";
import { config } from "../src/config";
import type { Reader, Signer } from "../src/lib/clients";
import { PurchaseError, purchaseSeats } from "../src/lib/purchase";

const ACCOUNT: Address = "0x00000000000000000000000000000000000000aa";
const SENT_HASH: Hash = `0x${"11".repeat(32)}`;
const MINED_HASH: Hash = `0x${"22".repeat(32)}`;
const RP_ID = 100n;
const PERIOD_START = 1796126400n;
const PAID = 10n * 10n ** 18n;

describe("purchaseSeats", () => {
  it("reports the tokens paid and the mined transaction", async () => {
    const result = await purchase([purchaseLog()]);

    expect(result.tokensPaid).toBe(PAID);
    expect(result.hash).toBe(MINED_HASH);
  });

  it("does not report success for a cancelled or replaced transaction", async () => {
    const failure = await purchase([]).catch((e: unknown) => e);

    expect(failure).toBeInstanceOf(PurchaseError);
    expect(((failure as PurchaseError).original as Error).message).toMatch(/cancelled or replaced/);
  });

  it("ignores purchase events from other contracts or other buyers", async () => {
    const otherContract = { ...purchaseLog(), address: "0x00000000000000000000000000000000000000bb" };
    const otherBuyer = purchaseLog("0x00000000000000000000000000000000000000cc");

    await expect(purchase([otherContract, otherBuyer])).rejects.toBeInstanceOf(PurchaseError);
  });
});

function purchase(logs: unknown[]) {
  const reader = {
    readContract: async () => 10n ** 30n,
    simulateContract: async () => ({ request: {} }),
    waitForTransactionReceipt: async () => ({ status: "success", transactionHash: MINED_HASH, logs }),
  } as unknown as Reader;
  const signer = { writeContract: async () => SENT_HASH } as unknown as Signer;

  return purchaseSeats({
    reader,
    signer,
    account: ACCOUNT,
    rpId: RP_ID,
    periodStart: PERIOD_START,
    seats: 1000n,
    quotedTokens: PAID,
    onStep: () => {},
  });
}

function purchaseLog(payer: Address = ACCOUNT) {
  return {
    address: config.billing,
    topics: encodeEventTopics({
      abi: billingAbi,
      eventName: "CapacityPurchased",
      args: { rpId: RP_ID, periodStart: PERIOD_START, payer },
    }),
    data: encodeAbiParameters(
      [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" }],
      [1000n, PAID, 10n ** 18n, 10n ** 16n],
    ),
  };
}
