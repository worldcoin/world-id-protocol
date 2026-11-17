import { describe, expect, it } from "vitest";
import { buildPeriods, daysLeft, formatUtcStart, monthLabel } from "../src/lib/periods";

const NOV_START = 1793534400n; // 1 Nov 2026 12:00 UTC (00:00 AoE)
const DEC_START = 1796126400n;
const JAN_START = 1798804800n;

describe("periods", () => {
  it("builds the current and next period", () => {
    expect(buildPeriods(NOV_START, DEC_START)).toEqual([
      { kind: "current", start: NOV_START, end: DEC_START },
      { kind: "next", start: DEC_START, end: JAN_START },
    ]);
  });

  it("labels months in UTC", () => {
    expect(monthLabel(DEC_START)).toBe("December 2026");
    expect(formatUtcStart(DEC_START)).toBe("1 Dec 12:00 UTC");
  });

  it("counts days left, never below zero", () => {
    expect(daysLeft(DEC_START, DEC_START - 86_400n * 20n + 1n)).toBe(20);
    expect(daysLeft(DEC_START, DEC_START + 5n)).toBe(0);
  });
});
