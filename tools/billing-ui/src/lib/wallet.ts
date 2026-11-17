import type { EIP1193Provider } from "viem";
import { useCallback, useEffect, useState } from "react";
import type { Address } from "viem";
import { config } from "../config";

declare global {
  interface Window {
    ethereum?: EIP1193Provider;
  }
}

const CHAIN_NOT_ADDED_CODE = 4902;

export interface WalletState {
  provider: EIP1193Provider | undefined;
  account: Address | undefined;
  onCorrectChain: boolean;
  connect: () => Promise<void>;
  switchChain: () => Promise<void>;
}

export function useWallet(): WalletState {
  const provider = typeof window === "undefined" ? undefined : window.ethereum;
  const [account, setAccount] = useState<Address | undefined>();
  const [chainId, setChainId] = useState<number | undefined>();

  useEffect(() => {
    if (!provider) return;
    void loadInitialState(provider, setAccount, setChainId);
    const onAccounts = (accounts: unknown) => setAccount((accounts as Address[])[0]);
    const onChain = (id: unknown) => setChainId(Number(id));
    provider.on("accountsChanged", onAccounts);
    provider.on("chainChanged", onChain);
    return () => {
      provider.removeListener("accountsChanged", onAccounts);
      provider.removeListener("chainChanged", onChain);
    };
  }, [provider]);

  const connect = useCallback(async () => {
    if (!provider) return;
    const accounts = (await provider.request({ method: "eth_requestAccounts" })) as Address[];
    setAccount(accounts[0]);
  }, [provider]);

  const switchChain = useCallback(async () => {
    if (!provider) return;
    await switchOrAddChain(provider);
  }, [provider]);

  return { provider, account, onCorrectChain: chainId === config.chain.id, connect, switchChain };
}

async function loadInitialState(
  provider: EIP1193Provider,
  setAccount: (account: Address | undefined) => void,
  setChainId: (chainId: number) => void,
): Promise<void> {
  const accounts = (await provider.request({ method: "eth_accounts" })) as Address[];
  setAccount(accounts[0]);
  setChainId(Number(await provider.request({ method: "eth_chainId" })));
}

async function switchOrAddChain(provider: EIP1193Provider): Promise<void> {
  const chainId = `0x${config.chain.id.toString(16)}`;
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  } catch (error) {
    if ((error as { code?: number }).code !== CHAIN_NOT_ADDED_CODE) throw error;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId,
          chainName: config.chain.name,
          nativeCurrency: config.chain.nativeCurrency,
          rpcUrls: [config.rpcUrl],
          blockExplorerUrls: [config.explorerUrl],
        },
      ],
    });
  }
}
