import { formatUnits } from "viem";

export function withSafetyMargin(amount: bigint, marginBps: bigint): bigint {
  const bps = 10_000n;
  return (amount * (bps + marginBps) + bps - 1n) / bps;
}

export function formatAmountCeil(value: bigint, decimals: number, fractionDigits = 4): string {
  return formatScaled(value, decimals, fractionDigits, true);
}

export function formatAmountFloor(value: bigint, decimals: number, fractionDigits = 4): string {
  return formatScaled(value, decimals, fractionDigits, false);
}

export function parseWholeNumber(input: string): bigint | null {
  const trimmed = input.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = BigInt(trimmed);
  return value > 0n ? value : null;
}

export function parseRpId(input: string): bigint | null {
  const value = parseWholeNumber(input);
  return value !== null && value < 2n ** 64n ? value : null;
}

function formatScaled(value: bigint, decimals: number, fractionDigits: number, roundUp: boolean): string {
  const step = 10n ** BigInt(Math.max(decimals - fractionDigits, 0));
  const rounded = roundUp ? ((value + step - 1n) / step) * step : (value / step) * step;
  const [whole, fraction = ""] = formatUnits(rounded, decimals).split(".");
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const padded = fraction.padEnd(fractionDigits, "0").slice(0, fractionDigits);
  return fractionDigits > 0 ? `${grouped}.${padded}` : grouped;
}
