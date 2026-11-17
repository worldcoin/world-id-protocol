import { parseAbi } from "viem";

const scope = "(uint256 chainId, address billingContract, uint64 rpId, uint64 periodStart)";

export const billingAbi = parseAbi([
  `function purchaseCapacity(${scope} scope, uint256 capacityAmount, uint256 maxWldAmount)`,
  `function quotePurchase(${scope} scope, uint256 capacityAmount) view returns (uint256 wldAmount)`,
  "function getBillingPeriod(uint64 timestamp) pure returns (uint64 periodStart, uint64 periodEnd)",
  "function getPinnedOprfKey(uint64 rpId, uint64 periodStart) view returns (uint160 oprfKeyId, uint256[2] oprfPublicKey)",
  "function getPeriodCapacity(uint64 rpId, uint64 periodStart) view returns (uint256 capacity, uint256 registeredCount)",
  "function pricePerWorldID() view returns (uint256)",
  "function priceSource() view returns (address)",
  "function RP_REGISTRY() view returns (address)",
  "function WORLD_ID_VERIFIER() view returns (address)",
  "function getFeeToken() view returns (address)",
  "function paused() view returns (bool)",
  "event CapacityPurchased(uint64 indexed rpId, uint64 indexed periodStart, address indexed payer, uint256 capacityAmount, uint256 wldPaid, uint256 usdPerWld, uint256 pricePerWorldID)",
  "error EnforcedPause()",
  "error PeriodOutsidePurchaseWindow()",
  "error ZeroCapacityAmount()",
  "error MaxWldAmountExceeded(uint256 wldAmount, uint256 maxWldAmount)",
  "error FeeTransferMismatch(uint256 expected, uint256 received)",
  "error PriceUnavailable()",
  "error InvalidPrice()",
  "error InvalidPriceDecimals(uint8 decimals)",
  "error PriceFromFuture(uint256 observedAt)",
  "error StalePrice(uint256 observedAt)",
  "error OprfKeyMismatch()",
  "error PinnedOprfKeyChanged()",
  "error InvalidChainId()",
  "error InvalidBillingContract()",
  "error NonCanonicalPeriodStart()",
  "error RpIdDoesNotExist()",
  "error RpIdInactive()",
  "error DeletedId(uint160 id)",
  "error UnknownId(uint160 id)",
  "error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)",
  "error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)",
]);

export const verifierAbi = parseAbi(["function getOprfKeyRegistry() view returns (address)"]);

export const oprfKeyRegistryAbi = parseAbi([
  "function getOprfPublicKey(uint160 oprfKeyId) view returns ((uint256 x, uint256 y))",
  "error DeletedId(uint160 id)",
  "error UnknownId(uint160 id)",
]);

export const rpRegistryAbi = parseAbi([
  "function getOprfKeyIdAndSigner(uint64 rpId) view returns (uint160, address)",
  "error RpIdDoesNotExist()",
  "error RpIdInactive()",
]);

export const priceSourceAbi = parseAbi([
  "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
  "function decimals() view returns (uint8)",
]);

export const tokenAbi = parseAbi([
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function balanceOf(address account) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function mint(address to, uint256 amount)",
  "error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)",
  "error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)",
]);
