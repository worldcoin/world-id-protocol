import { BaseError, ContractFunctionRevertedError, encodeErrorResult } from "viem";
import { describe, expect, it } from "vitest";
import { billingAbi, rpRegistryAbi } from "../src/abi";
import { explainError } from "../src/lib/errors";

function reverted(abi: typeof billingAbi | typeof rpRegistryAbi, errorName: string, args?: unknown[]): BaseError {
  const data = encodeErrorResult({ abi, errorName, args } as never);
  const cause = new ContractFunctionRevertedError({ abi, data, functionName: "purchaseCapacity" });
  return new BaseError("call failed", { cause });
}

describe("explainError", () => {
  it("maps billing reverts to plain sentences", () => {
    expect(explainError(reverted(billingAbi, "EnforcedPause"))).toMatch(/paused/);
    expect(explainError(reverted(billingAbi, "StalePrice", [1_700_000_000n]))).toMatch(/out of date/);
    expect(explainError(reverted(billingAbi, "MaxWldAmountExceeded", [2n, 1n]))).toMatch(/above your cap/);
    expect(explainError(reverted(billingAbi, "DeletedId", [44n]))).toMatch(/key was deleted/);
  });

  it("maps RP registry reverts", () => {
    expect(explainError(reverted(rpRegistryAbi, "RpIdDoesNotExist"))).toBe("This RP id does not exist.");
    expect(explainError(reverted(rpRegistryAbi, "RpIdInactive"))).toBe("This RP is not active.");
  });

  it("recognizes a wallet rejection", () => {
    const rejection = new BaseError("rejected", { cause: Object.assign(new Error("denied"), { code: 4001 }) });
    expect(explainError(rejection)).toMatch(/Cancelled/);
  });

  it("falls back to the message", () => {
    expect(explainError(new Error("boom"))).toBe("boom");
  });
});
