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

interface WalletData {
  account: Address;
  balance: bigint;
  allowance: bigint;
}

interface InputData {
  key: string;
  rpStatus: Loadable<null>;
  capacities: Capacities;
  quote: Loadable<bigint>;
}

const IDLE: Loadable<never> = { status: "idle" };

export function useBillingData(
  reader: Reader,
  account: Address | undefined,
  inputs: BillingInputs,
): BillingData {
  const [statics, setStatics] = useState<StaticData>();
  const [loadError, setLoadError] = useState<string>();
  const [now, setNow] = useState<bigint>();
  const [periods, setPeriods] = useState<Period[]>([]);
  const [walletData, setWalletData] = useState<WalletData>();
  const [inputData, setInputData] = useState<InputData>();
  const latestRun = useRef(0);
  const immutables = useRef<Immutables | undefined>(undefined);
  const key = inputKey(inputs);

  const refresh = useCallback(async () => {
    const run = ++latestRun.current;
    const isStale = () => run !== latestRun.current;
    try {
      immutables.current ??= await loadImmutables(reader);
      const currentStatics = await loadStatics(reader, immutables.current);
      const clock = await loadPeriods(reader);
      if (isStale()) return;
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
      setWalletData(account && wallet ? { account, ...wallet } : undefined);
      setInputData({ key, rpStatus: rp ?? IDLE, capacities: capacity ?? {}, quote: price ?? IDLE });
    } catch (error) {
      if (!isStale()) setLoadError(explainError(error));
    }
  }, [reader, account, key, inputs.rpId, inputs.seats, inputs.periodKind]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  // Results are only shown for the inputs they were loaded for, so a stale quote or RP check never
  // describes a different purchase than the one the button would send.
  const wallet = account !== undefined && walletData?.account === account ? walletData : undefined;
  const current = inputData?.key === key ? inputData : undefined;
  return {
    statics,
    loadError,
    now,
    periods,
    balance: wallet?.balance,
    allowance: wallet?.allowance,
    rpStatus: current?.rpStatus ?? IDLE,
    capacities: current?.capacities ?? {},
    quote: current?.quote ?? IDLE,
    refresh,
  };
}

function inputKey(inputs: BillingInputs): string {
  return `${inputs.rpId}|${inputs.seats}|${inputs.periodKind}`;
}

type Immutables = Pick<StaticData, "symbol" | "decimals" | "rpRegistry"> & { verifier: Address };

async function loadImmutables(reader: Reader): Promise<Immutables> {
  const billing = { address: config.billing, abi: billingAbi } as const;
  const token = { address: config.token, abi: tokenAbi } as const;
  const [symbol, decimals, rpRegistry, verifier] = await Promise.all([
    reader.readContract({ ...token, functionName: "symbol" }),
    reader.readContract({ ...token, functionName: "decimals" }),
    reader.readContract({ ...billing, functionName: "RP_REGISTRY" }),
    reader.readContract({ ...billing, functionName: "WORLD_ID_VERIFIER" }),
  ]);
  return { symbol, decimals, rpRegistry, verifier };
}

export async function loadStatics(reader: Reader, known?: Immutables): Promise<StaticData> {
  const { verifier, ...fixed } = known ?? (await loadImmutables(reader));
  const billing = { address: config.billing, abi: billingAbi } as const;
  const [pricePerSeatUsd, paused, priceSource, oprfKeyRegistry] = await Promise.all([
    reader.readContract({ ...billing, functionName: "pricePerWorldID" }),
    reader.readContract({ ...billing, functionName: "paused" }),
    reader.readContract({ ...billing, functionName: "priceSource" }),
    reader.readContract({ address: verifier, abi: verifierAbi, functionName: "getOprfKeyRegistry" }),
  ]);
  const [, tokenPriceUsd] = await reader.readContract({
    address: priceSource,
    abi: priceSourceAbi,
    functionName: "latestRoundData",
  });
  return { ...fixed, oprfKeyRegistry, pricePerSeatUsd, tokenPriceUsd: BigInt(tokenPriceUsd), paused };
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
