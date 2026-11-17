import { useCallback, useEffect, useRef, useState } from "react";
import type { Address } from "viem";
import { billingAbi, oprfKeyRegistryAbi, priceSourceAbi, rpRegistryAbi, tokenAbi, verifierAbi } from "../abi";
import { config, REFRESH_INTERVAL_MS } from "../config";
import type { Reader } from "./clients";
import { explainError, messageForRevert } from "./errors";
import { buildPeriods, type Period } from "./periods";

export interface StaticData {
  symbol: string;
  decimals: number;
  rpRegistry: Address;
  oprfKeyRegistry: Address;
  pricePerSeatUsd: bigint;
  tokenPriceUsd: bigint;
  paused: boolean;
}

export interface BillingInputs {
  rpId: bigint | null;
  seats: bigint | null;
  periodKind: Period["kind"];
}

export interface PeriodCapacity {
  purchased: bigint;
  used: bigint;
}

export type Capacities = Partial<Record<Period["kind"], PeriodCapacity>>;

export type Loadable<T> = { status: "idle" } | { status: "ok"; value: T } | { status: "error"; message: string };

export interface BillingData {
  statics: StaticData | undefined;
  loadError: string | undefined;
  now: bigint | undefined;
  periods: Period[];
  balance: bigint | undefined;
  allowance: bigint | undefined;
  rpStatus: Loadable<null>;
  capacities: Capacities;
  quote: Loadable<bigint>;
  refresh: () => Promise<void>;
}

export function useBillingData(
  reader: Reader,
  account: Address | undefined,
  inputs: BillingInputs,
): BillingData {
  const [statics, setStatics] = useState<StaticData>();
  const [loadError, setLoadError] = useState<string>();
  const [now, setNow] = useState<bigint>();
  const [periods, setPeriods] = useState<Period[]>([]);
  const [balance, setBalance] = useState<bigint>();
  const [allowance, setAllowance] = useState<bigint>();
  const [rpStatus, setRpStatus] = useState<Loadable<null>>({ status: "idle" });
  const [capacities, setCapacities] = useState<Capacities>({});
  const [quote, setQuote] = useState<Loadable<bigint>>({ status: "idle" });
  const latestRun = useRef(0);
  const loadedStatics = useRef<Omit<StaticData, "paused"> | undefined>(undefined);

  const refresh = useCallback(async () => {
    const run = ++latestRun.current;
    const isStale = () => run !== latestRun.current;
    try {
      loadedStatics.current ??= await loadStatics(reader);
      const paused = await reader.readContract({ address: config.billing, abi: billingAbi, functionName: "paused" });
      const clock = await loadPeriods(reader);
      if (isStale()) return;
      const currentStatics = { ...loadedStatics.current, paused };
      setStatics(currentStatics);
      setNow(clock.now);
      setPeriods(clock.periods);
      setLoadError(undefined);

      const period = clock.periods.find((p) => p.kind === inputs.periodKind);
      const [wallet, rp, capacity, price] = await Promise.all([
        account ? loadWalletState(reader, account) : undefined,
        inputs.rpId !== null ? loadRpStatus(reader, currentStatics, inputs.rpId) : undefined,
        inputs.rpId !== null ? loadCapacities(reader, inputs.rpId, clock.periods) : undefined,
        inputs.rpId !== null && inputs.seats !== null && period
          ? loadQuote(reader, inputs.rpId, period.start, inputs.seats)
          : undefined,
      ]);
      if (isStale()) return;
      setBalance(wallet?.balance);
      setAllowance(wallet?.allowance);
      setRpStatus(rp ?? { status: "idle" });
      setCapacities(capacity ?? {});
      setQuote(price ?? { status: "idle" });
    } catch (error) {
      if (!isStale()) setLoadError(explainError(error));
    }
  }, [reader, account, inputs.rpId, inputs.seats, inputs.periodKind]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  return { statics, loadError, now, periods, balance, allowance, rpStatus, capacities, quote, refresh };
}

export async function loadStatics(reader: Reader): Promise<Omit<StaticData, "paused">> {
  const billing = { address: config.billing, abi: billingAbi } as const;
  const token = { address: config.token, abi: tokenAbi } as const;
  const [symbol, decimals, rpRegistry, verifier, pricePerSeatUsd, priceSource] = await Promise.all([
    reader.readContract({ ...token, functionName: "symbol" }),
    reader.readContract({ ...token, functionName: "decimals" }),
    reader.readContract({ ...billing, functionName: "RP_REGISTRY" }),
    reader.readContract({ ...billing, functionName: "WORLD_ID_VERIFIER" }),
    reader.readContract({ ...billing, functionName: "pricePerWorldID" }),
    reader.readContract({ ...billing, functionName: "priceSource" }),
  ]);
  const [, tokenPriceUsd] = await reader.readContract({
    address: priceSource,
    abi: priceSourceAbi,
    functionName: "latestRoundData",
  });
  const oprfKeyRegistry = await reader.readContract({
    address: verifier,
    abi: verifierAbi,
    functionName: "getOprfKeyRegistry",
  });
  return { symbol, decimals, rpRegistry, oprfKeyRegistry, pricePerSeatUsd, tokenPriceUsd: BigInt(tokenPriceUsd) };
}

export async function loadPeriods(reader: Reader): Promise<{ now: bigint; periods: Period[] }> {
  const block = await reader.getBlock();
  const [start, end] = await reader.readContract({
    address: config.billing,
    abi: billingAbi,
    functionName: "getBillingPeriod",
    args: [block.timestamp],
  });
  return { now: block.timestamp, periods: buildPeriods(start, end) };
}

async function loadWalletState(reader: Reader, account: Address) {
  const [balance, allowance] = await Promise.all([
    reader.readContract({ address: config.token, abi: tokenAbi, functionName: "balanceOf", args: [account] }),
    reader.readContract({
      address: config.token,
      abi: tokenAbi,
      functionName: "allowance",
      args: [account, config.billing],
    }),
  ]);
  return { balance, allowance };
}

export async function loadRpStatus(
  reader: Reader,
  statics: Pick<StaticData, "rpRegistry" | "oprfKeyRegistry">,
  rpId: bigint,
): Promise<Loadable<null>> {
  try {
    const [oprfKeyId] = await reader.readContract({
      address: statics.rpRegistry,
      abi: rpRegistryAbi,
      functionName: "getOprfKeyIdAndSigner",
      args: [rpId],
    });
    if (oprfKeyId !== rpId) return { status: "error", message: messageForRevert("OprfKeyMismatch") };
    await reader.readContract({
      address: statics.oprfKeyRegistry,
      abi: oprfKeyRegistryAbi,
      functionName: "getOprfPublicKey",
      args: [oprfKeyId],
    });
    return { status: "ok", value: null };
  } catch (error) {
    return { status: "error", message: explainError(error) };
  }
}

export async function loadCapacities(reader: Reader, rpId: bigint, periods: Period[]): Promise<Capacities> {
  const entries = await Promise.all(
    periods.map(async (period) => {
      const [purchased, used] = await reader.readContract({
        address: config.billing,
        abi: billingAbi,
        functionName: "getPeriodCapacity",
        args: [rpId, period.start],
      });
      return [period.kind, { purchased, used }] as const;
    }),
  );
  return Object.fromEntries(entries);
}

async function loadQuote(
  reader: Reader,
  rpId: bigint,
  periodStart: bigint,
  seats: bigint,
): Promise<Loadable<bigint>> {
  try {
    const value = await reader.readContract({
      address: config.billing,
      abi: billingAbi,
      functionName: "quotePurchase",
      args: [{ chainId: BigInt(config.chain.id), billingContract: config.billing, rpId, periodStart }, seats],
    });
    return { status: "ok", value };
  } catch (error) {
    return { status: "error", message: explainError(error) };
  }
}
