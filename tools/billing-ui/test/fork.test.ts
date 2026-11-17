import { spawn, type ChildProcess } from "node:child_process";
import { createWalletClient, http, type Address } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { billingAbi, tokenAbi } from "../src/abi";
import { config } from "../src/config";
import { createReader, type Signer } from "../src/lib/clients";
import { explainError } from "../src/lib/errors";
import { loadCapacities, loadPeriods, loadRpStatus, loadStatics } from "../src/lib/useBillingData";
import { mintTestTokens, PurchaseError, purchaseSeats } from "../src/lib/purchase";

const FORK_URL = process.env.FORK_URL!;
const PORT = 8546;
const LOCAL_RPC = `http://127.0.0.1:${PORT}`;
const ANVIL_ACCOUNT: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const KNOWN_RP = 100n;
const UNKNOWN_RP = 1n;
const DELETED_KEY_RP = 44n;
const E18 = 10n ** 18n;

let anvil: ChildProcess;
const reader = createReader(LOCAL_RPC);
const signer = createWalletClient({ chain: config.chain, transport: http(LOCAL_RPC) }) as unknown as Signer;

beforeAll(async () => {
  anvil = spawn("anvil", ["--fork-url", FORK_URL, "--port", String(PORT), "--silent"], { stdio: "ignore" });
  await waitForAnvil();
}, 120_000);

afterAll(() => {
  anvil.kill();
});

describe("staging flow on a World Chain fork", () => {
  it("mints, approves and buys seats for the next month", async () => {
    await mintTestTokens(reader, signer, ANVIL_ACCOUNT, 1000n * E18);

    const periodStart = await nextPeriodStart();
    const capacityBefore = await seatsFor(KNOWN_RP, periodStart);
    const steps: string[] = [];

    const result = await purchaseSeats({
      reader,
      signer,
      account: ANVIL_ACCOUNT,
      rpId: KNOWN_RP,
      periodStart,
      seats: 1000n,
      onStep: (step) => steps.push(step),
    });

    expect(steps).toEqual(["approving", "buying"]);
    expect(result.tokensPaid).toBe(10n * E18);
    expect(result.maxTokens).toBe(11n * E18);
    expect(await seatsFor(KNOWN_RP, periodStart)).toBe(capacityBefore + 1000n);
    const { periods } = await loadPeriods(reader);
    const capacities = await loadCapacities(reader, KNOWN_RP, periods);
    expect(capacities.next).toEqual({ purchased: capacityBefore + 1000n, used: 0n });
    expect(capacities.current?.used).toBeTypeOf("bigint");
    expect(await balanceOf(ANVIL_ACCOUNT)).toBe(990n * E18);
  }, 120_000);

  it("skips the approval when the allowance already covers the cap", async () => {
    const periodStart = await nextPeriodStart();
    await approve(11n * E18);
    const steps: string[] = [];

    await purchaseSeats({
      reader,
      signer,
      account: ANVIL_ACCOUNT,
      rpId: KNOWN_RP,
      periodStart,
      seats: 1000n,
      onStep: (step) => steps.push(step),
    });

    expect(steps).toEqual(["buying"]);
  }, 120_000);

  it("fails with a readable reason for an unknown RP", async () => {
    const periodStart = await nextPeriodStart();
    const failure = await purchaseSeats({
      reader,
      signer,
      account: ANVIL_ACCOUNT,
      rpId: UNKNOWN_RP,
      periodStart,
      seats: 10n,
      onStep: () => {},
    }).catch((e: unknown) => e);

    expect(failure).toBeInstanceOf(PurchaseError);
    expect(explainError((failure as PurchaseError).original)).toBe("This RP id does not exist.");
  }, 120_000);
});

describe("RP status", () => {
  it("reports unusable RPs before any transaction", async () => {
    const statics = await loadStatics(reader);

    expect(await loadRpStatus(reader, statics, KNOWN_RP)).toEqual({ status: "ok", value: null });
    expect(await loadRpStatus(reader, statics, UNKNOWN_RP)).toEqual({
      status: "error",
      message: "This RP id does not exist.",
    });
    expect(await loadRpStatus(reader, statics, DELETED_KEY_RP)).toEqual({
      status: "error",
      message: "This RP's key was deleted, so seats can't be bought for it.",
    });
  }, 120_000);

  it("explains a purchase for an RP with a deleted key", async () => {
    const periodStart = await nextPeriodStart();
    const failure = await purchaseSeats({
      reader,
      signer,
      account: ANVIL_ACCOUNT,
      rpId: DELETED_KEY_RP,
      periodStart,
      seats: 10n,
      onStep: () => {},
    }).catch((e: unknown) => e);

    expect(explainError((failure as PurchaseError).original)).toBe("This RP's key was deleted, so seats can't be bought for it.");
  }, 120_000);
});

async function nextPeriodStart(): Promise<bigint> {
  const block = await reader.getBlock();
  const [, periodEnd] = await reader.readContract({
    address: config.billing,
    abi: billingAbi,
    functionName: "getBillingPeriod",
    args: [block.timestamp],
  });
  return periodEnd;
}

async function seatsFor(rpId: bigint, periodStart: bigint): Promise<bigint> {
  const [capacity] = await reader.readContract({
    address: config.billing,
    abi: billingAbi,
    functionName: "getPeriodCapacity",
    args: [rpId, periodStart],
  });
  return capacity;
}

function balanceOf(account: Address): Promise<bigint> {
  return reader.readContract({ address: config.token, abi: tokenAbi, functionName: "balanceOf", args: [account] });
}

async function approve(amount: bigint): Promise<void> {
  const hash = await signer.writeContract({
    account: ANVIL_ACCOUNT,
    chain: config.chain,
    address: config.token,
    abi: tokenAbi,
    functionName: "approve",
    args: [config.billing, amount],
  });
  await reader.waitForTransactionReceipt({ hash });
}

async function waitForAnvil(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await reader.getBlockNumber();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  throw new Error("anvil did not start");
}
