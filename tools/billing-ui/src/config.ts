import type { Address } from "viem";
import { worldchain } from "viem/chains";

export interface AppConfig {
  label: string;
  chain: typeof worldchain;
  rpcUrl: string;
  billing: Address;
  token: Address;
  /** The fee token is a mock anyone can mint; shows the "get test tokens" button. */
  mockToken: boolean;
  mintAmountTokens: bigint;
  explorerUrl: string;
}

export const config: AppConfig = {
  label: "Staging",
  chain: worldchain,
  rpcUrl: import.meta.env.VITE_RPC_URL ?? worldchain.rpcUrls.default.http[0],
  billing: "0x7e275a4d03Bc482258E552F2A0af47CE06eD6dE6",
  token: "0x7f44cB99537F922ee6b63806Ff565De4C210fDe4",
  mockToken: true,
  mintAmountTokens: 1000n,
  explorerUrl: "https://worldscan.org",
};

export const SAFETY_MARGIN_BPS = 1000n;
export const REFRESH_INTERVAL_MS = 15_000;
