import { describe, expect, it } from "vitest";
import { inputKey } from "../src/lib/useBillingData";

const inputs = { rpId: 100n, seats: 1000n, periodKind: "current" as const };

describe("inputKey", () => {
  it("changes when the month rolls over under the same selection", () => {
    expect(inputKey(inputs, 1793534400n)).not.toBe(inputKey(inputs, 1796126400n));
  });

  it("changes with the RP, the seats and the selected period", () => {
    const base = inputKey(inputs, 1793534400n);
    expect(inputKey({ ...inputs, rpId: 101n }, 1793534400n)).not.toBe(base);
    expect(inputKey({ ...inputs, seats: 1n }, 1793534400n)).not.toBe(base);
    expect(inputKey({ ...inputs, periodKind: "next" }, 1793534400n)).not.toBe(base);
  });
});
