import { describe, expect, it } from "vitest";
import { pinnedKeyChanged } from "../src/lib/useBillingData";

const key = { id: 100n, x: 5n, y: 7n };

describe("pinnedKeyChanged", () => {
  it("accepts a period with no pinned key yet", () => {
    expect(pinnedKeyChanged({ id: 0n, x: 0n, y: 0n }, key)).toBe(false);
  });

  it("accepts the same key as the pin", () => {
    expect(pinnedKeyChanged(key, key)).toBe(false);
  });

  it("rejects a key that changed after the pin", () => {
    expect(pinnedKeyChanged(key, { ...key, x: 6n })).toBe(true);
    expect(pinnedKeyChanged(key, { ...key, y: 8n })).toBe(true);
    expect(pinnedKeyChanged(key, { ...key, id: 101n })).toBe(true);
  });
});
