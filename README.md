# Web3 Tx Guard MCP (`web3-tx-guard-mcp`)

> **CI: Passing (Ubuntu + Windows)** · **Node.js >= 20** · **MCP: stdio | Streamable HTTP | SSE** · **x402: Base USDC (`$0.01`/call)** · **License: MIT**

**Deterministic Pre-Flight Transaction, Calldata & EIP-712 Signature Security Guard for Web3, DeFi & Treasury AI Agents**

AI agents holding `USDC`, `ETH`, `SOL`, `BTC`, `USDT`, or `TON` wallets face irreversible loss from a single corrupted checksum character, TON `EQ` vs `UQ` bounce trap, off-curve Solana PDA confusion, `MAX_UINT256` / `Permit2` unlimited token approval, `amountOutMin == 0` MEV sandwich swap, or `Seaport` zero-consideration blind signature. **`web3-tx-guard-mcp`** provides sub-5ms, 100% deterministic cryptographic verification with **zero external RPC or LLM API dependencies**:

## Tools

- `validate_multichain_address` (`$0.01 USDC` / call): Cryptographically validates and normalizes addresses across **8 ecosystems**:
  - **EVM** (`Ethereum`, `Base`, `Arbitrum`, `Polygon`, `Optimism`, `BNB`, `Avalanche`): Pure Keccak-256 **EIP-55** mixed-case checksum verification (blocks character typos, normalizes unchecksummed lowercase/uppercase, flags `0x000...000` / `0x...dEaD` / `0x01..0x0f` precompile burn traps).
  - **Tron** (`TRC-20`): `T...` SHA-256d Base58Check (`0x41` mainnet / `0xa0` testnet), outputs equivalent `0x...` EVM address, blocks `T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb` burn address.
  - **Bitcoin**: BIP-173 **Bech32** (`bc1q` SegWit v0 `P2WPKH`/`P2WSH`), BIP-350 **Bech32m** (`bc1p` Taproot v1 `P2TR`), and Legacy/P2SH Base58Check (`1...`, `3...`) with strict witness-version encoding enforcement.
  - **Solana**: Base58 32-byte decode + mathematical **Ed25519 Twisted Edwards curve check** ($p = 2^{255}-19$) distinguishing user wallet public keys (`isOnEd25519Curve: true`) from off-curve **Program Derived Addresses (`PDA`)** and System/Incinerator burn IDs.
  - **TON**: Friendly `EQ...` / `UQ...` / `kQ...` / `0Q...` **CRC16-XMODEM** verification + raw `0:<hex>` conversion, warning when bounceable `EQ...` risks bouncing transfers to uninitialized wallets.
  - **XRP Ledger**: Classic `r...` Ripple-alphabet Base58Check + **XLS-5d `X...` / `T...` X-Address** decoder extracting the underlying classic `r...` account and `destinationTag`.
  - **Cosmos SDK** (`cosmos1`, `noble1`, `osmo1`, `celestia1`, `inj1`, `sei1`, `dydx1`, `thor1`) & **Stacks** (`SP`/`SM`/`ST`/`SN` c32check).
- `decode_and_audit_evm_calldata` (`$0.01 USDC` / call): Decodes raw hex EVM calldata (`to`, `value`, `data`, `chainId`) across `ERC-20`, `ERC-721/1155`, `Permit2`, `Uniswap V2/V3/UniversalRouter`, `1inch`, **recursive `Multicall`**, and **Gnosis Safe `execTransaction`** — blocking `CRITICAL` unlimited approvals (`>= 2^255` / `MAX_UINT160`), `setApprovalForAll(true)`, `amountOutMin == 0` MEV sandwich exposure, payable-approval ETH traps, expired deadlines, and `operation=1` `DELEGATECALL` takeovers.
- `audit_eip712_signature_payload` (`$0.01 USDC` / call): Audits off-chain `eth_signTypedData_v4` payloads (`EIP-2612 Permit`, `DAI Permit`, `Permit2` `PermitSingle`/`PermitBatch`, `Seaport OrderComponents`, `EIP-3009` `x402` `TransferWithAuthorization`, `ForwardRequest`, `SafeTx`), computing the exact EIP-712 `domainSeparator` and catching zero-consideration NFT/token drains, unlimited gasless permits, multi-month signature expirations, and cross-chain `chainId` / `verifyingContract` spoofing.

---

## Quick Connect

### 1. Hosted `x402` Streamable HTTP MCP (MCPize / Base `USDC`)

```json
{
  "mcpServers": {
    "web3-tx-guard": {
      "type": "streamable-http",
      "url": "https://web3-tx-guard-mcp.mcpize.run/mcp"
    }
  }
}
```

### 2. Zero-Install Local `stdio` Mode (`npx` / Node 20+)

```json
{
  "mcpServers": {
    "web3-tx-guard": {
      "command": "npx",
      "args": ["-y", "github:2848823170/web3-tx-guard-mcp"]
    }
  }
}
```

<a href="https://glama.ai/mcp/servers/2848823170/web3-tx-guard-mcp">Glama MCP Directory — web3-tx-guard-mcp</a>

---

## 中文快速上手（Web3 交易预检与防钓鱼签名卫士）

**`web3-tx-guard-mcp`** 为 AI Agent、量化脚本与多链金库提供零外部 API 依赖的确定性链上交易安全预检：
1. **`validate_multichain_address`**：支持 **EVM / Tron (`TRC-20`) / Bitcoin (`Taproot` & `SegWit`) / Solana (自动区分钱包公钥与链下 `PDA`) / TON (`EQ`/`UQ` 退回陷阱预警) / XRP (`X-Address` 标签解析) / Cosmos / Stacks** 八大生态地址密码学校验与黑洞地址拦截。
2. **`decode_and_audit_evm_calldata`**：离线解码原始十六进制 `calldata`（含嵌套 `Multicall` 与 `Safe` 多签），精准拦截无限授权（`MAX_UINT256` / `Permit2`）、`setApprovalForAll(true)`、`amountOutMin == 0` 三明治夹子风险与恶意 `DELEGATECALL`。
3. **`audit_eip712_signature_payload`**：在调用 `eth_signTypedData_v4` 前审计 `Permit` / `Permit2` / `Seaport` / `x402 EIP-3009` 离线签名，防止零对价钓鱼盗币与跨链重放攻击。

---

## Local Verification

```bash
npm ci
npm test
```
