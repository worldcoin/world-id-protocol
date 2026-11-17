import { parseEventLogs, type Address, type Hash } from "viem";
import { billingAbi, tokenAbi } from "../abi";
import { config, SAFETY_MARGIN_BPS } from "../config";
import { withSafetyMargin } from "./amounts";
import type { Reader, Signer } from "./clients";

export type PurchaseStep = "approving" | "buying";

export interface PurchaseRequest {
  reader: Reader;
  signer: Signer;
  account: Address;
  rpId: bigint;
  periodStart: bigint;
  seats: bigint;
  onStep: (step: PurchaseStep) => void;
}

export interface PurchaseResult {
  hash: Hash;
  tokensPaid: bigint;
  maxTokens: bigint;
}

export class PurchaseError extends Error {
  constructor(
    readonly step: PurchaseStep,
    readonly original: unknown,
  ) {
    super(`Purchase failed while ${step}`);
  }
}

export async function purchaseSeats(request: PurchaseRequest): Promise<PurchaseResult> {
  const { reader, account, onStep } = request;
  const scope = {
    chainId: BigInt(config.chain.id),
    billingContract: config.billing,
    rpId: request.rpId,
    periodStart: request.periodStart,
  };

  const quote = await reader.readContract({
    address: config.billing,
    abi: billingAbi,
    functionName: "quotePurchase",
    args: [scope, request.seats],
  });
  const maxTokens = withSafetyMargin(quote, SAFETY_MARGIN_BPS);

  await runStep("approving", () => approveIfNeeded(request, maxTokens));

  onStep("buying");
  return runStep("buying", async () => {
    const { request: call } = await reader.simulateContract({
      account,
      address: config.billing,
      abi: billingAbi,
      functionName: "purchaseCapacity",
      args: [scope, request.seats, maxTokens],
    });
    const hash = await request.signer.writeContract(call);
    const receipt = await reader.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error("The transaction reverted on-chain.");
    const [event] = parseEventLogs({ abi: billingAbi, logs: receipt.logs, eventName: "CapacityPurchased" });
    return { hash, tokensPaid: event?.args.wldPaid ?? quote, maxTokens };
  });
}

async function approveIfNeeded(request: PurchaseRequest, amount: bigint): Promise<void> {
  const { reader, account } = request;
  const allowance = await reader.readContract({
    address: config.token,
    abi: tokenAbi,
    functionName: "allowance",
    args: [account, config.billing],
  });
  if (allowance >= amount) return;

  request.onStep("approving");
  const { request: call } = await reader.simulateContract({
    account,
    address: config.token,
    abi: tokenAbi,
    functionName: "approve",
    args: [config.billing, amount],
  });
  const hash = await request.signer.writeContract(call);
  const receipt = await reader.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("The approval transaction reverted on-chain.");
}

async function runStep<T>(step: PurchaseStep, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    throw new PurchaseError(step, error);
  }
}

export async function mintTestTokens(
  reader: Reader,
  signer: Signer,
  account: Address,
  amount: bigint,
): Promise<Hash> {
  const { request } = await reader.simulateContract({
    account,
    address: config.token,
    abi: tokenAbi,
    functionName: "mint",
    args: [account, amount],
  });
  const hash = await signer.writeContract(request);
  const receipt = await reader.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("The mint transaction reverted on-chain.");
  return hash;
}
