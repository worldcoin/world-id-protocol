import { BaseError, ContractFunctionRevertedError, encodeErrorResult } from "viem";
import { describe, expect, it } from "vitest";
import { billingAbi, rpRegistryAbi } from "../src/abi";
import { explainError } from "../src/lib/errors";

function reverted(abi: typeof billingAbi | typeof rpRegistryAbi, errorName: string): BaseError {
  const data = encodeErrorResult({ abi, errorName } as never);
  const cause = new ContractFunctionRevertedError({ abi, data, functionName: "purchaseCapacity" });
  return new BaseError("call failed", { cause });
}

describe("explainError", () => {
  it("maps billing reverts to plain sentences", () => {
    expect(explainError(reverted(billingAbi, "EnforcedPause"))).toMatch(/paused/);
    expect(explainError(reverted(billingAbi, "StalePrice") as never)).toBeTypeOf("string");
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
