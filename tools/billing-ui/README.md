# World ID Billing UI

A static page to buy WIP-107 registration capacity (seats) from `WorldIDBilling` on World Chain. It talks to the
chain through the connected wallet and a public RPC. There is no backend.

## Run locally

```bash
cd tools/billing-ui
npm install
npm run dev
```

Open the printed URL in a browser with MetaMask. The checked-in config points to the **staging** Billing Contract,
whose fee token is a mock anyone can mint. The wallet needs a little ETH on World Chain for gas.

## Test the workflow

1. Connect the wallet and switch to World Chain when asked.
2. Click **Get 1,000 test E20M** to mint tokens to your address.
3. Pick **Next month**, enter RP id `100` and a number of seats. The page shows the tokens required and a safe amount (+10%).
4. Click **Approve and buy**, then confirm both wallet prompts (the permission, then the purchase).
5. The capacity table for the RP updates with the new seats.

Other staging RPs that work: 46, 66, 67, 89, 101, 102, 103, 123.

## Configuration

Addresses and the mock-token switch live in `src/config.ts`; `VITE_RPC_URL` overrides the RPC. For production, set the
production Billing Contract and WLD addresses and `mockToken: false`, which hides the mint button.

## Tests

```bash
npm test          # unit tests
npm run test:fork # mint, approve and buy on an anvil fork of World Chain (needs foundry)
```
