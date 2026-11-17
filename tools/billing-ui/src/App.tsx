import { useMemo, useState } from "react";
import { formatUnits } from "viem";
import { config, SAFETY_MARGIN_BPS } from "./config";
import { formatAmountCeil, formatAmountFloor, parseRpId, parseWholeNumber, withSafetyMargin } from "./lib/amounts";
import { createReader, createSigner } from "./lib/clients";
import { explainError } from "./lib/errors";
import { daysLeft, formatUtcStart, monthLabel, type Period, type PeriodKind } from "./lib/periods";
import { mintTestTokens, PurchaseError, purchaseSeats, type PurchaseResult, type PurchaseStep } from "./lib/purchase";
import { useBillingData, type BillingData, type StaticData } from "./lib/useBillingData";
import { useWallet, type WalletState } from "./lib/wallet";

type Busy = PurchaseStep | "minting" | undefined;

interface Receipt extends PurchaseResult {
  seats: bigint;
  rpId: bigint;
  periodStart: bigint;
}

export function App() {
  const reader = useMemo(() => createReader(), []);
  const wallet = useWallet();
  const [periodKind, setPeriodKind] = useState<PeriodKind>("next");
  const [rpInput, setRpInput] = useState("");
  const [seatsInput, setSeatsInput] = useState("");
  const [busy, setBusy] = useState<Busy>();
  const [failedAfterApproval, setFailedAfterApproval] = useState(false);
  const [error, setError] = useState<string>();
  const [receipt, setReceipt] = useState<Receipt>();

  const rpId = parseRpId(rpInput);
  const seats = parseWholeNumber(seatsInput);
  const data = useBillingData(reader, wallet.account, { rpId, seats, periodKind });
  const period = data.periods.find((p) => p.kind === periodKind);

  const resetOutcome = () => {
    setError(undefined);
    setReceipt(undefined);
    setFailedAfterApproval(false);
  };

  const buy = async () => {
    if (!wallet.provider || !wallet.account || rpId === null || seats === null || !period) return;
    resetOutcome();
    const approvalNeeded = (data.allowance ?? 0n) < withSafetyMargin(requiredAmount(data) ?? 0n, SAFETY_MARGIN_BPS);
    try {
      const result = await purchaseSeats({
        reader,
        signer: createSigner(wallet.provider),
        account: wallet.account,
        rpId,
        periodStart: period.start,
        seats,
        onStep: setBusy,
      });
      setReceipt({ ...result, seats, rpId, periodStart: period.start });
    } catch (e) {
      const failure = e instanceof PurchaseError ? e : undefined;
      setFailedAfterApproval(failure?.step === "buying" && approvalNeeded);
      setError(explainError(failure ? failure.original : e));
    } finally {
      setBusy(undefined);
      await data.refresh();
    }
  };

  const mint = async () => {
    if (!wallet.provider || !wallet.account || !data.statics) return;
    resetOutcome();
    setBusy("minting");
    try {
      const amount = config.mintAmountTokens * 10n ** BigInt(data.statics.decimals);
      await mintTestTokens(reader, createSigner(wallet.provider), wallet.account, amount);
    } catch (e) {
      setError(explainError(e));
    } finally {
      setBusy(undefined);
      await data.refresh();
    }
  };

  return (
    <main>
      <Header wallet={wallet} data={data} />
      {data.loadError && <p className="notice error">Could not load billing data: {data.loadError}</p>}
      {data.statics?.paused && <p className="notice error">Billing is paused. Purchases are not possible right now.</p>}

      <section className="card">
        <h2>1. Period</h2>
        <PeriodPicker
          periods={data.periods}
          now={data.now}
          selected={periodKind}
          onSelect={(kind) => {
            setPeriodKind(kind);
            resetOutcome();
          }}
        />

        <h2>2. RP ID</h2>
        <input
          inputMode="numeric"
          placeholder="e.g. 100"
          value={rpInput}
          onChange={(e) => {
            setRpInput(e.target.value);
            resetOutcome();
          }}
        />
        <RpStatus rpInput={rpInput} rpId={rpId} data={data} />

        <h2>3. Seats</h2>
        <input
          inputMode="numeric"
          placeholder="e.g. 1000"
          value={seatsInput}
          onChange={(e) => {
            setSeatsInput(e.target.value);
            resetOutcome();
          }}
        />
        {seatsInput !== "" && seats === null && <p className="hint error">Enter a whole number of seats, at least 1.</p>}
      </section>

      {rpId !== null && data.rpStatus.status === "ok" && <CapacityPanel rpId={rpId} data={data} selected={periodKind} />}

      {data.statics && <QuotePanel data={data} statics={data.statics} seats={seats} />}

      <section className="card">
        <ActionArea
          wallet={wallet}
          data={data}
          rpId={rpId}
          seats={seats}
          busy={busy}
          failedAfterApproval={failedAfterApproval}
          onBuy={buy}
        />
        {error && <p className="notice error">{error}</p>}
        {receipt && data.statics && <Success receipt={receipt} statics={data.statics} balance={data.balance} />}
      </section>

      {config.mockToken && wallet.account && wallet.onCorrectChain && data.statics && (
        <section className="card staging">
          <h2>Test tokens</h2>
          <p className="hint">
            This is a staging setup: the fee token is a mock anyone can mint. This button sends a transaction that
            mints {config.mintAmountTokens.toString()} {data.statics.symbol} to your connected address.
          </p>
          <button className="secondary" disabled={busy !== undefined} onClick={mint}>
            {busy === "minting" ? "Minting…" : `Get ${config.mintAmountTokens} test ${data.statics.symbol}`}
          </button>
        </section>
      )}
    </main>
  );
}

function Header({ wallet, data }: { wallet: WalletState; data: BillingData }) {
  const balance =
    data.statics && data.balance !== undefined
      ? `${formatAmountFloor(data.balance, data.statics.decimals)} ${data.statics.symbol}`
      : undefined;
  return (
    <header>
      <div>
        <h1>World ID Billing: buy seats</h1>
        <span className="badge">
          {config.label} · {config.chain.name} ({config.chain.id})
        </span>
      </div>
      {wallet.account && (
        <div className="account">
          <code>{shorten(wallet.account)}</code>
          {balance && <span>Balance: {balance}</span>}
        </div>
      )}
    </header>
  );
}

function PeriodPicker(props: {
  periods: Period[];
  now: bigint | undefined;
  selected: PeriodKind;
  onSelect: (kind: PeriodKind) => void;
}) {
  if (props.periods.length === 0 || props.now === undefined) return <p className="hint">Loading periods…</p>;
  return (
    <div className="radios">
      {[...props.periods].reverse().map((p) => (
        <label key={p.kind}>
          <input type="radio" checked={props.selected === p.kind} onChange={() => props.onSelect(p.kind)} />
          <span>
            <b>{p.kind === "next" ? "Next month" : "Current month"}</b> · {monthLabel(p.start)}
            <br />
            <small>
              {p.kind === "next"
                ? `full price, starts ${formatUtcStart(p.start)}`
                : `prorated, ${daysLeft(p.end, props.now!)} days left`}
            </small>
          </span>
        </label>
      ))}
    </div>
  );
}

function RpStatus({ rpInput, rpId, data }: { rpInput: string; rpId: bigint | null; data: BillingData }) {
  if (rpInput !== "" && rpId === null) return <p className="hint error">Enter a valid RP id (a whole number).</p>;
  if (rpId === null) return null;
  if (data.rpStatus.status === "ok") return <p className="hint ok">✓ RP is active</p>;
  if (data.rpStatus.status === "error") return <p className="hint error">{data.rpStatus.message}</p>;
  return null;
}

function CapacityPanel({ rpId, data, selected }: { rpId: bigint; data: BillingData; selected: PeriodKind }) {
  const rows = [...data.periods].reverse().filter((p) => data.capacities[p.kind]);
  if (rows.length === 0) return null;
  return (
    <section className="card">
      <h2>Capacity of RP {rpId.toString()}</h2>
      <table>
        <thead>
          <tr>
            <th>Month</th>
            <th>Purchased</th>
            <th>Used</th>
            <th>Remaining</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => {
            const { purchased, used } = data.capacities[p.kind]!;
            return (
              <tr key={p.kind} className={p.kind === selected ? "selected" : undefined}>
                <td>{monthLabel(p.start)}</td>
                <td>{purchased.toString()}</td>
                <td>{used.toString()}</td>
                <td>{(purchased - used).toString()}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="hint">Seats are one per registered World ID. The numbers refresh every 15 seconds.</p>
    </section>
  );
}

function QuotePanel({ data, statics, seats }: { data: BillingData; statics: StaticData; seats: bigint | null }) {
  const required = requiredAmount(data);
  const safe = required === undefined ? undefined : withSafetyMargin(required, SAFETY_MARGIN_BPS);
  const symbol = statics.symbol;
  return (
    <section className="card">
      <h2>Quote</h2>
      <dl>
        <dt>Price per seat (full month)</dt>
        <dd>{trimUsd(statics.pricePerSeatUsd)} USD</dd>
        <dt>
          {symbol}/USD (price feed)
        </dt>
        <dd>{trimUsd(statics.tokenPriceUsd)}</dd>
        <dt>{symbol} required</dt>
        <dd className="strong">
          {required !== undefined ? `${formatAmountCeil(required, statics.decimals)} ${symbol}` : "–"}
        </dd>
        <dt>Safe amount to hold (+{Number(SAFETY_MARGIN_BPS) / 100}%)</dt>
        <dd className="strong">{safe !== undefined ? `${formatAmountCeil(safe, statics.decimals)} ${symbol}` : "–"}</dd>
      </dl>
      {data.quote.status === "error" && <p className="notice error">{data.quote.message}</p>}
      {data.quote.status === "idle" && seats === null && (
        <p className="hint">Enter an RP id and a number of seats to see the quote.</p>
      )}
      <p className="hint">The quote refreshes every 15 seconds.</p>
    </section>
  );
}

interface ActionProps {
  wallet: WalletState;
  data: BillingData;
  rpId: bigint | null;
  seats: bigint | null;
  busy: Busy;
  failedAfterApproval: boolean;
  onBuy: () => void;
}

function ActionArea(props: ActionProps) {
  const { wallet, data, busy } = props;
  if (!wallet.provider) return <p className="notice error">No wallet found. Install MetaMask to continue.</p>;
  if (!wallet.account) return <button onClick={() => void wallet.connect()}>Connect wallet</button>;
  if (!wallet.onCorrectChain) {
    return <button onClick={() => void wallet.switchChain()}>Switch to {config.chain.name}</button>;
  }
  if (!data.statics) return <button disabled>Loading…</button>;

  const required = requiredAmount(data);
  const safe = required === undefined ? undefined : withSafetyMargin(required, SAFETY_MARGIN_BPS);
  const symbol = data.statics.symbol;
  const blocker = blockedReason(props, required);
  const needsApproval = safe !== undefined && (data.allowance ?? 0n) < safe;
  const label = props.failedAfterApproval
    ? "Resume purchase"
    : `${needsApproval ? "Approve and buy" : "Buy"} ${props.seats ?? ""} seats`;

  return (
    <>
      <button disabled={blocker !== undefined || busy !== undefined} onClick={props.onBuy}>
        {busyLabel(busy) ?? label}
      </button>
      {blocker && <p className="hint">{blocker}</p>}
      {!blocker && needsApproval && (
        <p className="hint">
          Your wallet will ask for two confirmations: first the permission to use up to{" "}
          {formatAmountCeil(safe!, data.statics.decimals)} {symbol}, then the purchase.
        </p>
      )}
      {!blocker && safe !== undefined && data.balance !== undefined && data.balance < safe && (
        <p className="hint warn">
          Your balance is below the safe amount. The purchase works at today's price, but a rate move could make it
          fail.
        </p>
      )}
    </>
  );
}

function Success({ receipt, statics, balance }: { receipt: Receipt; statics: StaticData; balance: bigint | undefined }) {
  return (
    <div className="notice success">
      <b>
        ✅ Done: {receipt.seats.toString()} seats bought for RP {receipt.rpId.toString()} (
        {monthLabel(receipt.periodStart)})
      </b>
      <p>
        Paid {formatAmountCeil(receipt.tokensPaid, statics.decimals)} {statics.symbol}
        {balance !== undefined && ` · balance now ${formatAmountFloor(balance, statics.decimals)} ${statics.symbol}`}
      </p>
      <a href={`${config.explorerUrl}/tx/${receipt.hash}`} target="_blank" rel="noreferrer">
        View transaction {shorten(receipt.hash)}
      </a>
    </div>
  );
}

function blockedReason(props: ActionProps, required: bigint | undefined): string | undefined {
  const { data, rpId, seats } = props;
  if (data.statics?.paused) return "Billing is paused.";
  if (rpId === null || seats === null) return "Enter an RP id and a number of seats.";
  if (data.rpStatus.status === "error") return data.rpStatus.message;
  if (data.quote.status === "error") return data.quote.message;
  if (required === undefined || data.balance === undefined || !data.statics) return "Loading the quote…";
  if (data.balance < required) {
    const missing = formatAmountCeil(required - data.balance, data.statics.decimals);
    return `Not enough ${data.statics.symbol}: ${missing} more needed.`;
  }
  return undefined;
}

function busyLabel(busy: Busy): string | undefined {
  if (busy === "approving") return "Step 1 of 2: approving…";
  if (busy === "buying") return "Buying seats…";
  if (busy === "minting") return "Minting…";
  return undefined;
}

function requiredAmount(data: BillingData): bigint | undefined {
  return data.quote.status === "ok" ? data.quote.value : undefined;
}

function trimUsd(value: bigint): string {
  const [whole, fraction = ""] = formatUnits(value, 18).split(".");
  return fraction.length > 4 ? `${whole}.${fraction.slice(0, 4)}` : fraction ? `${whole}.${fraction}` : `${whole}.00`;
}

function shorten(value: string): string {
  return `${value.slice(0, 6)}…${value.slice(-4)}`;
}
