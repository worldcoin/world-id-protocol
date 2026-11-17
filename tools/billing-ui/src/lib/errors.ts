import { BaseError, ContractFunctionRevertedError } from "viem";

const MESSAGES: Record<string, string> = {
  EnforcedPause: "Billing is paused right now. Try again later.",
  PeriodOutsidePurchaseWindow: "That month can't be bought yet. Only the current and next month are available.",
  ZeroCapacityAmount: "Enter at least 1 seat.",
  MaxWldAmountExceeded: "The price moved above your cap. Refresh the quote and try again.",
  PriceUnavailable: "The price feed is unavailable. Try again in a few minutes.",
  InvalidPrice: "The price feed returned an invalid price. Try again in a few minutes.",
  PriceFromFuture: "The price feed returned an invalid price. Try again in a few minutes.",
  StalePrice: "The price feed is out of date. Try again in a few minutes.",
  RpIdDoesNotExist: "This RP id does not exist.",
  RpIdInactive: "This RP is not active.",
  OprfKeyMismatch: "This RP has no usable key, so seats can't be bought for it now.",
  DeletedId: "This RP's key was deleted, so seats can't be bought for it.",
  UnknownId: "This RP has no key yet (key generation is not finished), so seats can't be bought for it.",
  PinnedOprfKeyChanged: "This RP's key changed during the month, so seats can't be bought for it now.",
  ERC20InsufficientBalance: "Not enough tokens in the wallet.",
  ERC20InsufficientAllowance: "The approval is missing or too small.",
};

const USER_REJECTED_CODE = 4001;

export function explainError(error: unknown): string {
  if (isUserRejection(error)) return "Cancelled in the wallet. Nothing was sent.";
  const name = revertedErrorName(error);
  if (name) return messageForRevert(name);
  if (error instanceof BaseError) return error.shortMessage;
  return error instanceof Error ? error.message : "Something went wrong.";
}

export function messageForRevert(errorName: string): string {
  return MESSAGES[errorName] ?? `The contract rejected the request (${errorName}).`;
}

function isUserRejection(error: unknown): boolean {
  if (!(error instanceof BaseError)) return false;
  const cause = error.walk((e) => (e as { code?: number }).code === USER_REJECTED_CODE);
  return cause !== null;
}

function revertedErrorName(error: unknown): string | undefined {
  if (!(error instanceof BaseError)) return undefined;
  const reverted = error.walk((e) => e instanceof ContractFunctionRevertedError);
  return reverted instanceof ContractFunctionRevertedError ? reverted.data?.errorName : undefined;
}
