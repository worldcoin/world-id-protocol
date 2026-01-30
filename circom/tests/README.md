# Nullifier Service Test Suite

This repository provides a lightweight test harness for out Circom circuits using:
- Mocha as the test runner
- Chai for assertions
- circom_tester for circuit unit tests (witness generation and constraint checks)

## Prerequisites

- Node.js 18+ (LTS recommended)
- Circom v2 installed and available on your PATH
  - Check: `circom --version`
  - Install guide: https://docs.circom.io/getting-started/installation/
- (Optional) Rust toolchain for building circom, depending on your setup
- This repo’s dev dependencies are installed with `npm install`

## Installation

```bash
# From the repository root
npm install
```

## Scripts

The package.json includes:

- test: runs all tests under `tests/**/*.test.js` with Mocha

Usage:
```bash
npm test
```

Mocha will discover and run any `*.test.js` files under `tests/`.

