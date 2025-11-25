# Bot Father

WASI module for managing multiple NEAR accounts with AI-generated names.

## Features

- **Create Accounts**: Generate multiple NEAR accounts with AI-generated names
- **Key Derivation**: Derive unique ed25519 keys from a master key using SHA-256
- **Batch Calls**: Execute contract calls on created accounts (all or filtered by indices)
- **List Accounts**: View all created accounts with balances

## Build

```bash
./build.sh
```

Output: `target/wasm/bot-father.wasm`

## Environment Variables

Required:
- `OPENAI_API_KEY` - OpenAI API key for name generation
- `BOT_FATHER_MASTER_KEY` - Master seed for key derivation (generates deterministic child keys, NOT used for blockchain transactions)
- `NEAR_SENDER_ID` - User's account ID (pays for account creation and transfers)
- `NEAR_SENDER_PRIVATE_KEY` - **SECRET** Private key for NEAR_SENDER_ID account (ed25519:... format, provided by user who runs WASM, used to sign all blockchain transactions)

Optional:
- `OPENAI_ENDPOINT` - Custom OpenAI API endpoint (default: `https://api.openai.com/v1/chat/completions`)
- `OPENAI_MODEL` - Model name (default: `gpt-3.5-turbo`)
- `NEAR_NETWORK` - Network suffix: `testnet` or `near` (default: `testnet`)
- `FASTNEAR_URL` - Fastnear API URL (default: `https://test.api.fastnear.com`)

**Important**:
- All environment variables are passed via `--env` flag to the WASM module
- `NEAR_SENDER_PRIVATE_KEY` should be passed via OutLayer secrets mechanism in production
- **CRITICAL**: Worker NEVER signs transactions with its own key - WASM ALWAYS provides signer credentials via RPC calls

## Actions

### Create Accounts

```json
{
  "action": "create_accounts",
  "prompt": "space exploration theme",
  "count": 3,
  "deposit_per_account": "1000000000000000000000000"
}
```

Creates accounts like `mars-rover.testnet`, `moon-base.testnet`, `star-voyager.testnet`.

### Batch Call

Execute contract calls on all or selected accounts:

```json
{
  "action": "batch_call",
  "contract_id": "v2.ref-finance.near",
  "method_name": "deposit",
  "args": {},
  "deposit": "1",
  "gas": "30000000000000",
  "indices": []
}
```

- **Empty `indices`**: Execute for ALL accounts
- **Single index** `[0]`: Execute for account at index 0
- **Multiple indices** `[0, 2, 5]`: Execute for accounts 0, 2, and 5

Use `{{account_id}}` placeholder in args to inject current account ID:
```json
{
  "action": "batch_call",
  "contract_id": "token.near",
  "method_name": "transfer",
  "args": {"receiver_id": "{{account_id}}", "amount": "1000"},
  "deposit": "1",
  "gas": "30000000000000",
  "indices": [1, 3]
}
```

### List Accounts

```json
{
  "action": "list_accounts"
}
```

### Fund Accounts

Transfer NEAR tokens to created accounts. Total amount is split evenly:

```json
{
  "action": "fund_accounts",
  "total_amount": "30000000000000000000000000",
  "indices": []
}
```

- **Empty `indices`**: Fund ALL accounts equally
- **Single index** `[0]`: Fund only account at index 0
- **Multiple indices** `[0, 2]`: Fund accounts 0 and 2 equally

Example: Fund 3 accounts with 30 NEAR total = 10 NEAR each:
```json
{
  "action": "fund_accounts",
  "total_amount": "30000000000000000000000000",
  "indices": []
}
```

## Output Format

```json
{
  "success": true,
  "accounts": [
    {
      "index": 0,
      "account_id": "mars_rover.testnet",
      "public_key": "ed25519:...",
      "balance": "1000000000000000000000000",
      "balance_near": "1.0000"
    }
  ],
  "transactions": [
    {
      "account_id": "mars_rover.testnet",
      "tx_hash": "Abc123...",
      "success": true
    }
  ]
}
```

**Note:** `balance_near` is formatted in NEAR tokens (1 NEAR = 10^24 yoctoNEAR) with 4 decimal places.

## Key Derivation

Keys are derived using SHA-256:
```
derived_seed = SHA256(master_key_bytes + predecessor_bytes + index_bytes)
derived_key = ed25519_from_seed(derived_seed)
```

This allows deterministic key recovery from the master key, predecessor (NEAR_SENDER_ID), and index.

**Important**: Each user (predecessor) has their own isolated account list. The same master key with different predecessors produces completely different sets of accounts.

## Account Discovery

Bot Father uses **fastnear API** to discover previously created accounts:
1. Derives public keys for indices 0..99
2. Queries fastnear API: `/v0/public_key/{public_key}/all`
3. Returns list of accounts owned by each derived key
4. Stops when no accounts found for a key

This enables **stateless operation** - no need to store account list between runs.

## Testing with wasi-test-runner

```bash
# Build first
./build.sh

# Example 1: Create accounts
../wasi-test-runner/target/release/wasi-test \
  --wasm target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"create_accounts","prompt":"space theme","count":3,"deposit_per_account":"1000000000000000000000000"}' \
  --env OPENAI_API_KEY=sk-... \
  --env BOT_FATHER_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc --rpc-allow-transactions \
  --max-instructions 50000000000

# Example 2: Fund all accounts with 30 NEAR total (10 NEAR each if 3 accounts exist)
../wasi-test-runner/target/release/wasi-test \
  --wasm target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"fund_accounts","total_amount":"30000000000000000000000000"}' \
  --env BOT_FATHER_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc-allow-transactions \
  --max-instructions 50000000000

# Example 3: Fund only accounts at indices 0 and 2
../wasi-test-runner/target/release/wasi-test \
  --wasm target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"fund_accounts","total_amount":"20000000000000000000000000","indices":[0,2]}' \
  --env BOT_FATHER_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc-allow-transactions \
  --max-instructions 50000000000

# Example 4: List all created accounts
../wasi-test-runner/target/release/wasi-test \
  --wasm target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"list_accounts"}' \
  --env BOT_FATHER_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --rpc \
  --max-instructions 50000000000

# Example 5: Batch call on all accounts
../wasi-test-runner/target/release/wasi-test \
  --wasm target/wasm32-wasip2/release/bot-father.wasm \
  --input '{"action":"batch_call","contract_id":"v2.ref-finance.near","method_name":"deposit","args":{},"deposit":"1","gas":"30000000000000","indices":[]}' \
  --env BOT_FATHER_MASTER_KEY=ed25519:... \
  --env NEAR_SENDER_ID=alice.testnet \
  --env NEAR_SENDER_PRIVATE_KEY=ed25519:... \
  --rpc-allow-transactions \
  --max-instructions 50000000000
```

**Note**:
- Use `--env NEAR_SENDER_ID=youraccount.testnet` to specify master account
- Use `--env NEAR_SENDER_PRIVATE_KEY=ed25519:...` to pass the private key (will come from secrets in production)
- **DO NOT use** `--rpc-signer-account` / `--rpc-signer-key` - worker NEVER signs with its own key

## Architecture

```
User Input
    │
    ▼
┌───────────────────┐
│    Bot Father     │
│   (WASI Module)   │
├───────────────────┤
│ • Parse action    │
│ • AI name gen     │◄──── HTTP (WASI P2)
│ • Key derivation  │◄──── SHA-256 + ed25519
│ • NEAR operations │◄──── near:rpc/api@0.1.0 (WIT)
└───────────────────┘
    │
    ▼
 JSON Output
```
