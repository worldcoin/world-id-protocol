import { createPublicClient, createWalletClient, custom, http, type EIP1193Provider } from "viem";
import { config } from "../config";

export type Reader = ReturnType<typeof createReader>;
export type Signer = ReturnType<typeof createSigner>;

export function createReader(rpcUrl: string = config.rpcUrl) {
  return createPublicClient({ chain: config.chain, transport: http(rpcUrl) });
}

export function createSigner(provider: EIP1193Provider) {
  return createWalletClient({ chain: config.chain, transport: custom(provider) });
}
