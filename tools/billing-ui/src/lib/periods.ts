export type PeriodKind = "current" | "next";

export interface Period {
  kind: PeriodKind;
  start: bigint;
  end: bigint;
}

export function buildPeriods(currentStart: bigint, currentEnd: bigint): Period[] {
  return [
    { kind: "current", start: currentStart, end: currentEnd },
    { kind: "next", start: currentEnd, end: nextMonthStart(currentEnd) },
  ];
}

export function monthLabel(periodStart: bigint): string {
  return new Date(Number(periodStart) * 1000).toLocaleDateString("en-US", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });
}

export function formatUtcStart(periodStart: bigint): string {
  const date = new Date(Number(periodStart) * 1000);
  const day = date.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  const time = date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
  return `${day} ${time} UTC`;
}

export function daysLeft(periodEnd: bigint, now: bigint): number {
  const seconds = Number(periodEnd - now);
  return Math.max(Math.ceil(seconds / 86_400), 0);
}

function nextMonthStart(periodStart: bigint): bigint {
  const start = new Date(Number(periodStart) * 1000);
  const next = Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 1, start.getUTCHours());
  return BigInt(next / 1000);
}
