import { bn254 } from "@taceo/poseidon2";

export const PASSKEY_SLOT_COUNT = 7;
export const DS_PASSKEY_SLOT = 1946547295039501641724099466078281182247605809n;
export const DS_MIXED_AUTH_SET = 127568923526698591992218025179744430956107526002225n;

function hexToBytes(value: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("P-256 coordinates must be 32-byte hex strings");
  }
  return Uint8Array.from(value.slice(2).match(/.{2}/g)!, (byte) => Number.parseInt(byte, 16));
}

function fold(bytes: Uint8Array): bigint {
  return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

export function p256HexToLimbs(value: string): [bigint, bigint, bigint] {
  const bytes = hexToBytes(value);
  return [fold(bytes.slice(17, 32)), fold(bytes.slice(2, 17)), fold(bytes.slice(0, 2))];
}

export function passkeySlotCommitment(publicKeyX: string, publicKeyY: string): bigint {
  const state = Array<bigint>(16).fill(0n);
  state[0] = DS_PASSKEY_SLOT;
  state.splice(1, 3, ...p256HexToLimbs(publicKeyX));
  state.splice(4, 3, ...p256HexToLimbs(publicKeyY));
  return bn254.t16.permutation(state)[1];
}

export function mixedAuthenticatorSetCommitment(slotCommitments: readonly bigint[]): bigint {
  if (slotCommitments.length !== PASSKEY_SLOT_COUNT) {
    throw new Error(`expected ${PASSKEY_SLOT_COUNT} authenticator slots`);
  }
  const state = Array<bigint>(16).fill(0n);
  state[0] = DS_MIXED_AUTH_SET;
  state.splice(1, PASSKEY_SLOT_COUNT, ...slotCommitments);
  return bn254.t16.permutation(state)[1];
}
