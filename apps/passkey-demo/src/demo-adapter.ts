import { bytesToHex, type RegisteredPasskey } from "./webauthn";

export type RegistryState = {
  leafIndex: number;
  root: string;
  slotIndex: number;
  slotCommitment: string;
  slotCommitments: string[];
  accountLeaf: string;
  siblings: string[];
};

export async function registerWithLocalBridge(passkey: RegisteredPasskey): Promise<RegistryState> {
  const response = await fetch("/api/register-passkey", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      publicKeyX: bytesToHex(passkey.publicKey.x),
      publicKeyY: bytesToHex(passkey.publicKey.y),
      slotIndex: 1,
    }),
  });

  if (!response.ok) throw new Error(await responseError(response));
  return response.json() as Promise<RegistryState>;
}

async function responseError(response: Response): Promise<string> {
  const fallback = `${response.status} ${response.statusText}`.trim();
  try {
    const body = await response.json() as { error?: unknown };
    return typeof body.error === "string" ? body.error : fallback;
  } catch {
    return fallback;
  }
}
