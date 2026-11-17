import { describe, expect, it } from "vitest";
import { formatAmountCeil, formatAmountFloor, parseRpId, parseWholeNumber, withSafetyMargin } from "../src/lib/amounts";

const E18 = 10n ** 18n;

describe("withSafetyMargin", () => {
  it("adds 10%", () => {
    expect(withSafetyMargin(1000n * E18, 1000n)).toBe(1100n * E18);
  });

  it("rounds up", () => {
    expect(withSafetyMargin(1n, 1000n)).toBe(2n);
    expect(withSafetyMargin(3154570000000000000000n, 1000n)).toBe(3470027000000000000000n);
  });
});

describe("formatting", () => {
  it("rounds requirements up and balances down", () => {
    expect(formatAmountCeil(1n, 18)).toBe("0.0001");
    expect(formatAmountFloor(1n, 18)).toBe("0.0000");
  });

  it("groups thousands and pads fractions", () => {
    expect(formatAmountCeil(3470027n * 10n ** 15n, 18)).toBe("3,470.0270");
    expect(formatAmountFloor(5n * E18, 18)).toBe("5.0000");
  });
});

describe("input parsing", () => {
  it("accepts positive whole numbers only", () => {
    expect(parseWholeNumber(" 1000 ")).toBe(1000n);
    for (const bad of ["", "0", "-1", "1.5", "1e3", "abc"]) expect(parseWholeNumber(bad)).toBeNull();
  });

  it("limits RP ids to uint64", () => {
    expect(parseRpId("100")).toBe(100n);
    expect(parseRpId("18446744073709551615")).toBe(2n ** 64n - 1n);
    expect(parseRpId("18446744073709551616")).toBeNull();
  });
});
