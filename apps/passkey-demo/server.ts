import { readFile } from "node:fs/promises";
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  type Abi,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import {
  PASSKEY_SLOT_COUNT,
  mixedAuthenticatorSetCommitment,
  passkeySlotCommitment,
} from "./src/commitments";

const DEFAULT_RPC_URL = "http://127.0.0.1:8545";
const DEFAULT_ANVIL_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

type LinkReference = { start: number; length: number };
export type ContractArtifact = {
  abi: Abi;
  bytecode: {
    object: string;
    linkReferences?: Record<string, Record<string, LinkReference[]>>;
  };
};

type RegisterRequest = {
  publicKeyX: string;
  publicKeyY: string;
  slotIndex: number;
};

type RegistryDeployment = {
  address: Address;
  abi: Abi;
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function assertLoopbackRpc(rpcUrl: string): void {
  const url = new URL(rpcUrl);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error("PASSKEY_DEMO_ANVIL_RPC_URL must be a loopback HTTP URL");
  }
}

async function loadArtifact(relativePath: string): Promise<ContractArtifact> {
  const url = new URL(`../../contracts/out/${relativePath}`, import.meta.url);
  try {
    return JSON.parse(await readFile(url, "utf8")) as ContractArtifact;
  } catch (error) {
    throw new Error(`missing contract artifact ${relativePath}; run 'cd contracts && forge build'`, { cause: error });
  }
}

function artifactBytecode(artifact: ContractArtifact): Hex {
  const object = artifact.bytecode.object;
  return (object.startsWith("0x") ? object : `0x${object}`) as Hex;
}

export function linkArtifactBytecode(artifact: ContractArtifact, libraries: ReadonlyMap<string, Address>): Hex {
  let bytecode = artifactBytecode(artifact).slice(2);
  for (const [source, sourceReferences] of Object.entries(artifact.bytecode.linkReferences ?? {})) {
    for (const [name, references] of Object.entries(sourceReferences)) {
      const key = `${source}:${name}`;
      const address = libraries.get(key);
      if (!address) throw new Error(`missing deployed library for ${key}`);
      const replacement = address.slice(2);
      for (const { start, length } of references) {
        if (replacement.length !== length * 2) throw new Error(`unexpected link width for ${key}`);
        const offset = start * 2;
        bytecode = `${bytecode.slice(0, offset)}${replacement}${bytecode.slice(offset + length * 2)}`;
      }
    }
  }
  if (bytecode.includes("__$")) throw new Error("contract bytecode still contains unlinked libraries");
  return `0x${bytecode}`;
}

const rpcUrl = process.env.PASSKEY_DEMO_ANVIL_RPC_URL ?? DEFAULT_RPC_URL;
assertLoopbackRpc(rpcUrl);
const privateKey = (process.env.PASSKEY_DEMO_ANVIL_PRIVATE_KEY ?? DEFAULT_ANVIL_PRIVATE_KEY) as Hex;
const account = privateKeyToAccount(privateKey);
const publicClient = createPublicClient({ chain: foundry, transport: http(rpcUrl) });
const walletClient = createWalletClient({ account, chain: foundry, transport: http(rpcUrl) });

async function deploy(artifact: ContractArtifact, args: readonly unknown[] = [], bytecode = artifactBytecode(artifact)) {
  const hash = await walletClient.deployContract({ abi: artifact.abi, bytecode, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success" || !receipt.contractAddress) throw new Error("contract deployment failed");
  return receipt.contractAddress;
}

async function deployRegistry(): Promise<RegistryDeployment> {
  if ((await publicClient.getChainId()) !== foundry.id) {
    throw new Error(`refusing non-Anvil chain: expected chain ID ${foundry.id}`);
  }

  const [packedArtifact, treeArtifact, registryArtifact, proxyArtifact] = await Promise.all([
    loadArtifact("PackedAccountData.sol/PackedAccountData.json"),
    loadArtifact("FullStorageBinaryIMT.sol/FullStorageBinaryIMT.json"),
    loadArtifact("WorldIDRegistryV2.sol/WorldIDRegistryV2.json"),
    loadArtifact("ERC1967Proxy.sol/ERC1967Proxy.json"),
  ]);
  const packedAddress = await deploy(packedArtifact);
  const treeAddress = await deploy(treeArtifact);
  const libraries = new Map<string, Address>([
    ["src/core/libraries/PackedAccountData.sol:PackedAccountData", packedAddress],
    ["src/core/libraries/FullStorageBinaryIMT.sol:FullStorageBinaryIMT", treeAddress],
  ]);
  const implementation = await deploy(registryArtifact, [], linkArtifactBytecode(registryArtifact, libraries));
  const initData = encodeFunctionData({
    abi: registryArtifact.abi,
    functionName: "initialize",
    args: [30n, ZERO_ADDRESS, ZERO_ADDRESS, 0n],
  });
  const address = await deploy(proxyArtifact, [implementation, initData]);
  return { address, abi: registryArtifact.abi };
}

let registryPromise: Promise<RegistryDeployment> | undefined;
function registry(): Promise<RegistryDeployment> {
  registryPromise ??= deployRegistry().catch((error) => {
    registryPromise = undefined;
    throw error;
  });
  return registryPromise;
}

function parseRegisterRequest(value: unknown): RegisterRequest {
  if (!value || typeof value !== "object") throw new Error("request body must be a JSON object");
  const request = value as Partial<RegisterRequest>;
  if (request.slotIndex !== 1) throw new Error("the demo passkey slot must be 1");
  if (typeof request.publicKeyX !== "string" || typeof request.publicKeyY !== "string") {
    throw new Error("publicKeyX and publicKeyY are required");
  }
  // The commitment helper performs exact coordinate shape validation.
  passkeySlotCommitment(request.publicKeyX, request.publicKeyY);
  return request as RegisterRequest;
}

async function waitForWrite(hash: Hex): Promise<void> {
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("registry transaction reverted");
}

export async function registerPasskey(request: RegisterRequest) {
  const deployed = await registry();
  // Each registry account needs a unique management authenticator. This local
  // admin authorizes WIP-104 insertion but never sends a transaction or holds funds.
  const admin = privateKeyToAccount(generatePrivateKey());
  const emptySlots = Array<bigint>(PASSKEY_SLOT_COUNT).fill(0n);
  const oldLeaf = mixedAuthenticatorSetCommitment(emptySlots);
  const slotCommitment = passkeySlotCommitment(request.publicKeyX, request.publicKeyY);
  const slots = [...emptySlots];
  slots[request.slotIndex] = slotCommitment;
  const accountLeaf = mixedAuthenticatorSetCommitment(slots);

  const leafIndex = await publicClient.readContract({
    address: deployed.address,
    abi: deployed.abi,
    functionName: "getNextLeafIndex",
  }) as bigint;
  await waitForWrite(await walletClient.writeContract({
    address: deployed.address,
    abi: deployed.abi,
    functionName: "createAccount",
    args: [admin.address, [admin.address], [0n], oldLeaf],
  }));
  const nonce = await publicClient.readContract({
    address: deployed.address,
    abi: deployed.abi,
    functionName: "getSignatureNonce",
    args: [leafIndex],
  }) as bigint;
  const signature = await admin.signTypedData({
    domain: { name: "WorldIDRegistry", version: "1.0", chainId: foundry.id, verifyingContract: deployed.address },
    primaryType: "InsertAuthenticator",
    types: {
      InsertAuthenticator: [
        { name: "leafIndex", type: "uint64" },
        { name: "newAuthenticatorAddress", type: "address" },
        { name: "pubkeyId", type: "uint32" },
        { name: "newAuthenticatorPubkey", type: "uint256" },
        { name: "newOffchainSignerCommitment", type: "uint256" },
        { name: "nonce", type: "uint256" },
      ],
    },
    message: {
      leafIndex,
      newAuthenticatorAddress: ZERO_ADDRESS,
      pubkeyId: request.slotIndex,
      newAuthenticatorPubkey: slotCommitment,
      newOffchainSignerCommitment: accountLeaf,
      nonce,
    },
  });
  await waitForWrite(await walletClient.writeContract({
    address: deployed.address,
    abi: deployed.abi,
    functionName: "insertAuthenticator",
    args: [leafIndex, ZERO_ADDRESS, request.slotIndex, slotCommitment, oldLeaf, accountLeaf, signature, nonce],
  }));
  const [root, siblings] = await Promise.all([
    publicClient.readContract({ address: deployed.address, abi: deployed.abi, functionName: "getLatestRoot" }) as Promise<bigint>,
    publicClient.readContract({ address: deployed.address, abi: deployed.abi, functionName: "getProof", args: [leafIndex] }) as Promise<readonly bigint[]>,
  ]);
  return {
    leafIndex: Number(leafIndex),
    root: root.toString(),
    slotIndex: request.slotIndex,
    slotCommitment: slotCommitment.toString(),
    slotCommitments: slots.map(String),
    accountLeaf: accountLeaf.toString(),
    siblings: siblings.map(String),
  };
}

let registrationQueue = Promise.resolve();
function serializeRegistration<T>(operation: () => Promise<T>): Promise<T> {
  const result = registrationQueue.then(operation, operation);
  registrationQueue = result.then(() => undefined, () => undefined);
  return result;
}

export function createApiHandler(register: typeof registerPasskey = registerPasskey) {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/api/verify-passkey-proof") {
      return json({ error: "server-side proof verification is intentionally unavailable; verify in the browser" }, 501);
    }
    if (request.method === "POST" && url.pathname === "/api/register-passkey") {
      let body: RegisterRequest;
      try {
        body = parseRegisterRequest(await request.json());
      } catch (error) {
        return json({ error: error instanceof Error ? error.message : "invalid request" }, 400);
      }
      try {
        return json(await serializeRegistration(() => register(body)));
      } catch (error) {
        console.error("passkey registration failed", error);
        return json({ error: error instanceof Error ? error.message : "passkey registration failed" }, 500);
      }
    }
    return json({ error: "not found" }, 404);
  };
}

if (import.meta.main) {
  const port = Number(process.env.PASSKEY_DEMO_BRIDGE_PORT ?? "8787");
  Bun.serve({ hostname: "127.0.0.1", port, fetch: createApiHandler() });
  console.log(`Passkey demo bridge listening on http://127.0.0.1:${port}`);
}
