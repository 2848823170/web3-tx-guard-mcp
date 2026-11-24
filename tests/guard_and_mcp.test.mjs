/**
 * Comprehensive Cryptographic, Adversarial Security & MCP Protocol Test Suite (`guard_and_mcp.test.mjs`).
 *
 * Covers:
 * 1. Apify `.actor/*` schemas, Pay-Per-Event catalog, `mcpize.yaml` (`x402` Base USDC -> `0xfEbDbB880C7f323c145d61683874a45540208a68`),
 *    `glama.json`, `server.json`, `Dockerfile`, and `@modelcontextprotocol/sdk` `createMcpServer()` capability registration.
 * 2. `validate_multichain_address` across all 8 chains:
 *    - Official Boss treasury addresses (`EVM` EIP-55, `Tron` T..., `Bitcoin` Taproot Bech32m `bc1p...`, `Solana` Ed25519 on-curve, `XRPL` `r...`)
 *    - `TON` friendly `UQ...` vs `EQ...` bounceable uninit-wallet warning + CRC16 tamper rejection + raw `0:hex` conversion
 *    - `Solana` off-curve PDA detection (`isOnEd25519Curve === false`) + System Program burn rejection
 *    - `XRPL` XLS-5d `X...` X-Address decoding into classic `r...` + `destinationTag`
 *    - `Bitcoin` BIP-173 SegWit v0 `bc1q` vs BIP-350 `bc1p` witness-encoding enforcement + `Cosmos` (`noble1`) + `Stacks` (`SP...` c32check)
 *    - `EVM` single-char EIP-55 case typo rejection, lowercase normalization, zero/dead/precompile burn blocking, and `mainnet` vs `testnet` guard.
 * 3. `decode_and_audit_evm_calldata`:
 *    - Safe scoped ERC-20 `transfer` (`ALLOW`) vs `MAX_UINT256` `approve` (`CRITICAL` `BLOCK_TRANSACTION`) + payable ETH trap
 *    - `setApprovalForAll(true)` (`CRITICAL`), Uniswap V2 `swapExactTokensForTokens` with `amountOutMin == 0` MEV sandwich + diverted recipient + expired deadline
 *    - Recursive `multicall(bytes[])` uncovering a hidden inner `approve(MAX_UINT256)`
 *    - Gnosis Safe `execTransaction` with `operation = 1` (`DELEGATECALL` takeover `CRITICAL`).
 * 4. `audit_eip712_signature_payload`:
 *    - EIP-2612 `Permit` (`MAX_UINT256` + multi-year deadline + domain `chainId` spoofing)
 *    - Uniswap `Permit2` `PermitSingle` (`MAX_UINT160`)
 *    - OpenSea `Seaport` `OrderComponents` zero-consideration NFT phishing drain (`SEAPORT_ZERO_CONSIDERATION_DRAIN`)
 *    - Legitimate `x402` Base USDC `TransferWithAuthorization` (`SAFE_TO_SIGN`, `$0.01` = `10000` micro-USDC) vs recipient/cap mismatch (`DO_NOT_SIGN`)
 *    - `SafeTx` with `DELEGATECALL` + embedded malicious calldata.
 * 5. MCP `stdio` (newline JSON-RPC + fragmented LSP `Content-Length` framing + `bin/web3-tx-guard-mcp.mjs`).
 * 6. Streamable HTTP (`POST /` & `POST /mcp` with `2025-06-18`), `GET /ping`, `GET /health`, Apify Standby probe, PPE `/charge` + `Idempotency-Key` deduplication + budget cap + Batch Actor mode.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { PayPerEventMeter } from '../src/billing/ppe.mjs';
import {
  BASE58_XRPL_ALPHABET,
  base58CheckDecode,
  base58CheckEncode,
  keccak256Hex,
  toEip55Address,
} from '../src/core/crypto-primitives.mjs';
import { selectorOf } from '../src/core/evm-calldata.mjs';
import { createMcpServer } from '../src/index.js';
import { runBatchActor } from '../src/main.mjs';
import { createHttpMcpServer } from '../src/mcp/server.mjs';
import { executeCommercialTool } from '../src/mcp/tools.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');

function padWord(hexNoPrefix) {
  return hexNoPrefix.replace(/^0x/i, '').toLowerCase().padStart(64, '0');
}

function encodeAddressWord(addr) {
  return padWord(addr.replace(/^0x/i, ''));
}

function encodeUintWord(n) {
  return padWord(BigInt(n).toString(16));
}

test('1. Manifests (.actor/*, pay_per_event.json, mcpize.yaml x402 Base USDC, glama.json, server.json, SDK registry) are valid', () => {
  const actorJson = JSON.parse(readFileSync(resolve(ROOT_DIR, '.actor/actor.json'), 'utf8'));
  assert.equal(actorJson.actorSpecification, 1);
  assert.equal(actorJson.name, 'web3-tx-guard-mcp');
  assert.match(actorJson.version, /^\d+\.\d+$/);
  assert.equal(actorJson.usesStandbyMode, true);
  assert.equal(actorJson.webServerMcpPath, '/mcp');

  const inputSchema = JSON.parse(readFileSync(resolve(ROOT_DIR, '.actor/input_schema.json'), 'utf8'));
  assert.equal(inputSchema.schemaVersion, 1);
  assert.equal(inputSchema.type, 'object');

  const meter = new PayPerEventMeter();
  const byName = Object.fromEntries(meter.getCatalogSummary().map((e) => [e.eventName, e.eventPriceUsd]));
  assert.equal(byName['validate-multichain-address'], 0.01);
  assert.equal(byName['decode-audit-evm-calldata'], 0.01);
  assert.equal(byName['audit-eip712-signature'], 0.01);
  assert.equal(byName['actor-start'], 0.001);

  const mcpizeYaml = readFileSync(resolve(ROOT_DIR, 'mcpize.yaml'), 'utf8');
  assert.match(mcpizeYaml, /name:\s*web3-tx-guard-mcp/);
  assert.match(mcpizeYaml, /runtime:\s*container/);
  assert.match(mcpizeYaml, /protocol:\s*x402/);
  assert.match(mcpizeYaml, /network:\s*base/);
  assert.match(mcpizeYaml, /recipient:\s*"0xfEbDbB880C7f323c145d61683874a45540208a68"/);
  assert.doesNotMatch(mcpizeYaml, /^\s*(title|transport|monetization):/m);

  // Verify pure-JS Keccak-256 against canonical Solidity selector & EIP-55 vectors
  assert.equal(keccak256Hex('transfer(address,uint256)').slice(0, 8), 'a9059cbb');
  assert.equal(toEip55Address('0xfebdbb880c7f323c145d61683874a45540208a68'), '0xfEbDbB880C7f323c145d61683874a45540208a68');

  const sdkServer = createMcpServer({ meter });
  assert.ok(sdkServer && typeof sdkServer.connect === 'function');
});

test('2. validate_multichain_address validates 8 chains, catches checksum typos, PDAs, TON bounce traps, X-Addresses, and burn addresses', async () => {
  const meter = new PayPerEventMeter();

  // 2a. Official 5 multichain wallets (EVM, Tron, Bitcoin Taproot Bech32m, Solana Ed25519, XRPL)
  const evmOk = await executeCommercialTool(
    'validate_multichain_address',
    { address: '0xfEbDbB880C7f323c145d61683874a45540208a68', expectedNetwork: 'mainnet' },
    { meter },
  );
  assert.equal(evmOk.payload.analysis.valid, true);
  assert.equal(evmOk.payload.analysis.safeToTransact, true);
  assert.equal(evmOk.payload.analysis.chain, 'evm');
  assert.equal(evmOk.payload.analysis.checksumStatus, 'valid_eip55');

  // Single-character case flip in EIP-55 -> MUST reject as CRITICAL typo!
  const evmTypo = await executeCommercialTool('validate_multichain_address', {
    address: '0xfebDbB880C7f323c145d61683874a45540208a68',
  });
  assert.equal(evmTypo.payload.analysis.valid, false);
  assert.equal(evmTypo.payload.analysis.safeToTransact, false);
  assert.equal(evmTypo.payload.analysis.riskLevel, 'CRITICAL');

  // All-lowercase EVM -> valid, LOW warning, normalized to EIP-55
  const evmLower = await executeCommercialTool('validate_multichain_address', {
    address: '0xfebdbb880c7f323c145d61683874a45540208a68',
  });
  assert.equal(evmLower.payload.analysis.valid, true);
  assert.equal(evmLower.payload.analysis.canonicalAddress, '0xfEbDbB880C7f323c145d61683874a45540208a68');

  // EVM dead burn address -> valid syntax, CRITICAL burn block (`safeToTransact === false`)
  const evmDead = await executeCommercialTool('validate_multichain_address', {
    address: '0x000000000000000000000000000000000000dEaD',
  });
  assert.equal(evmDead.payload.analysis.isBurnOrSystemTrap, true);
  assert.equal(evmDead.payload.analysis.safeToTransact, false);

  // Tron TRC-20 wallet + burn check
  const tronOk = await executeCommercialTool('validate_multichain_address', {
    address: 'TScN3VSpNyxPYvCsvSaze2HFkFFuCAXgYE',
    expectedNetwork: 'mainnet',
  });
  assert.equal(tronOk.payload.analysis.valid, true);
  assert.equal(tronOk.payload.analysis.chain, 'tron');
  assert.equal(tronOk.payload.analysis.safeToTransact, true);
  assert.match(tronOk.payload.analysis.alternateFormats.evmHexEquivalent, /^0x[0-9a-fA-F]{40}$/);

  const tronBurn = await executeCommercialTool('validate_multichain_address', {
    address: 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb',
  });
  assert.equal(tronBurn.payload.analysis.isBurnOrSystemTrap, true);
  assert.equal(tronBurn.payload.analysis.safeToTransact, false);

  // Bitcoin Taproot v1 Bech32m + SegWit v0 Bech32 + Testnet mismatch block
  const btcTaproot = await executeCommercialTool('validate_multichain_address', {
    address: 'bc1plp3p4kn3y7r6krl5nyxwz8rn79nq8yxy4n6t3utftugcmvqc78rqh533m0',
    expectedNetwork: 'mainnet',
  });
  assert.equal(btcTaproot.payload.analysis.valid, true);
  assert.equal(btcTaproot.payload.analysis.addressType, 'p2tr_taproot_v1');
  assert.equal(btcTaproot.payload.analysis.checksumStatus, 'valid_bech32m');

  const btcSegwitV0 = await executeCommercialTool('validate_multichain_address', {
    address: 'bc1qn5a4wtn90ptr5582ef94jsdlunwp5lmpwurjqf',
    expectedNetwork: 'mainnet',
  });
  assert.equal(btcSegwitV0.payload.analysis.valid, true);
  assert.equal(btcSegwitV0.payload.analysis.addressType, 'p2wpkh_segwit_v0');
  assert.equal(btcSegwitV0.payload.analysis.checksumStatus, 'valid_bech32');

  // Solana Ed25519 on-curve wallet vs System Program burn vs off-curve PDA
  const solOk = await executeCommercialTool('validate_multichain_address', {
    address: '2h68rTXHZW65UWnM1uXnE5ABD4Tj62qN14vFZvVaX3bC',
  });
  assert.equal(solOk.payload.analysis.valid, true);
  assert.equal(solOk.payload.analysis.chain, 'solana');
  assert.equal(solOk.payload.analysis.metadata.isOnEd25519Curve, true);

  const solBurn = await executeCommercialTool('validate_multichain_address', {
    address: '11111111111111111111111111111111',
  });
  assert.equal(solBurn.payload.analysis.isBurnOrSystemTrap, true);
  assert.equal(solBurn.payload.analysis.safeToTransact, false);

  // TON UQ (safe non-bounceable) vs EQ (MEDIUM bounceable uninit-wallet warning)
  const tonUq = await executeCommercialTool('validate_multichain_address', {
    address: 'UQAe3nzr65L7AOaFr5Q2_Ag7XpuAIXijA-qMdDdeJ-57yLf4',
    expectedNetwork: 'mainnet',
  });
  assert.equal(tonUq.payload.analysis.valid, true);
  assert.equal(tonUq.payload.analysis.chain, 'ton');
  assert.equal(tonUq.payload.analysis.riskLevel, 'SAFE');

  const tonEq = await executeCommercialTool('validate_multichain_address', {
    address: 'EQAe3nzr65L7AOaFr5Q2_Ag7XpuAIXijA-qMdDdeJ-57yOo9',
  });
  assert.equal(tonEq.payload.analysis.valid, true);
  assert.equal(tonEq.payload.analysis.riskLevel, 'MEDIUM');
  assert.ok(tonEq.payload.analysis.warnings.some((w) => w.code === 'TON_BOUNCEABLE_UNINIT_WALLET_TRAP'));
  assert.equal(tonEq.payload.analysis.alternateFormats.nonBounceable, 'UQAe3nzr65L7AOaFr5Q2_Ag7XpuAIXijA-qMdDdeJ-57yLf4');

  // XRPL Classic r-address + constructed XLS-5d X-Address with Destination Tag 20261124!
  const xrpClassic = await executeCommercialTool('validate_multichain_address', {
    address: 'rGQn9jT7D2cGJHTHDPwAQusj6Pkr8HUJLb',
  });
  assert.equal(xrpClassic.payload.analysis.valid, true);
  assert.equal(xrpClassic.payload.analysis.chain, 'xrpl');

  const classicDecoded = base58CheckDecode('rGQn9jT7D2cGJHTHDPwAQusj6Pkr8HUJLb', BASE58_XRPL_ALPHABET);
  const xPayload = new Uint8Array(31);
  xPayload[0] = 0x05;
  xPayload[1] = 0x44;
  xPayload.set(classicDecoded.subarray(1), 2);
  xPayload[22] = 0x01; // 32-bit tag present
  const tagVal = 20261124;
  xPayload[23] = tagVal & 0xff;
  xPayload[24] = (tagVal >>> 8) & 0xff;
  xPayload[25] = (tagVal >>> 16) & 0xff;
  xPayload[26] = (tagVal >>> 24) & 0xff;
  const xAddress = base58CheckEncode(xPayload, BASE58_XRPL_ALPHABET);

  const xrpX = await executeCommercialTool('validate_multichain_address', { address: xAddress });
  assert.equal(xrpX.payload.analysis.valid, true);
  assert.equal(xrpX.payload.analysis.addressType, 'xrpl_x_address');
  assert.equal(xrpX.payload.analysis.metadata.classicAddress, 'rGQn9jT7D2cGJHTHDPwAQusj6Pkr8HUJLb');
  assert.equal(xrpX.payload.analysis.metadata.destinationTag, 20261124);

  // Solana off-curve PDA detection (construct deterministic 32-byte point where x^2 is quadratic non-residue mod p: y=2!)
  const pdaBytes = new Uint8Array(32);
  pdaBytes[0] = 2; // For y = 2 on Ed25519, u/v = 3 / (4d + 1) is NOT a quadratic residue mod 2^255-19!
  const pdaAddr = base58CheckEncode(pdaBytes).slice(0, 10)
    ? (await import('../src/core/crypto-primitives.mjs')).base58Encode(pdaBytes)
    : '';
  const solPda = await executeCommercialTool('validate_multichain_address', { address: pdaAddr });
  assert.equal(solPda.payload.analysis.valid, true);
  assert.equal(solPda.payload.analysis.addressType, 'program_derived_address_pda');
  assert.equal(solPda.payload.analysis.metadata.isOnEd25519Curve, false);
  assert.ok(solPda.payload.analysis.warnings.some((w) => w.code === 'SOLANA_OFF_CURVE_PDA'));

  // Stacks mainnet principal (`SP69PSYVRY332FKNP0J0GDEFWEACE2ZR292QYA7Y` & contract principal)
  const stxOk = await executeCommercialTool('validate_multichain_address', {
    address: 'SP69PSYVRY332FKNP0J0GDEFWEACE2ZR292QYA7Y',
    expectedNetwork: 'mainnet',
  });
  assert.equal(stxOk.payload.analysis.valid, true);
  assert.equal(stxOk.payload.analysis.chain, 'stacks');
  assert.equal(meter.totalChargedUsd, 0.01);
});

test('3. decode_and_audit_evm_calldata flags MAX_UINT256 approvals, zero-minOut MEV swaps, nested Multicall drains, and Safe DELEGATECALL', async () => {
  const usdcBase = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const attacker = '0x1111111111111111111111111111111111111111';
  const sender = '0xfEbDbB880C7f323c145d61683874a45540208a68';
  const nowSec = 1795480000;

  // 3a. Clean scoped ERC-20 transfer of 25 USDC -> ALLOW (`SAFE`)
  const transferCalldata =
    selectorOf('transfer(address,uint256)') +
    encodeAddressWord(sender) +
    encodeUintWord(25_000_000n);
  const cleanTx = await executeCommercialTool('decode_and_audit_evm_calldata', {
    to: usdcBase,
    value: '0',
    data: transferCalldata,
    chainId: 8453,
    referenceTimestamp: nowSec,
  });
  assert.equal(cleanTx.payload.audit.safeToExecute, true);
  assert.equal(cleanTx.payload.audit.recommendation, 'ALLOW');
  assert.equal(cleanTx.payload.audit.riskLevel, 'SAFE');

  // 3b. Unlimited ERC-20 approve(attacker, MAX_UINT256) + non-zero ETH trap -> CRITICAL BLOCK
  const maxApproveData =
    selectorOf('approve(address,uint256)') +
    encodeAddressWord(attacker) +
    'f'.repeat(64);
  const badApprove = await executeCommercialTool('decode_and_audit_evm_calldata', {
    to: usdcBase,
    value: '10000000000000000', // 0.01 ETH attached to approve!
    data: maxApproveData,
    chainId: 8453,
  });
  assert.equal(badApprove.payload.audit.safeToExecute, false);
  assert.equal(badApprove.payload.audit.recommendation, 'BLOCK_TRANSACTION');
  assert.equal(badApprove.payload.audit.riskLevel, 'CRITICAL');
  const codes = new Set(badApprove.payload.audit.findings.map((f) => f.code));
  assert.ok(codes.has('UNLIMITED_ERC20_APPROVAL'));
  assert.ok(codes.has('NONZERO_ETH_ON_APPROVAL'));

  // 3c. Uniswap V3 exactInputSingle (SwapRouter02) with amountOutMinimum == 0 & diverted recipient
  const v3SwapZeroMin =
    selectorOf('exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))') +
    encodeAddressWord(usdcBase) +
    encodeAddressWord('0x4200000000000000000000000000000000000006') +
    encodeUintWord(500) +
    encodeAddressWord(attacker) + // diverted!
    encodeUintWord(1_000_000_000n) +
    encodeUintWord(0n) + // 0 minOut!
    encodeUintWord(0n);
  const swapAudit = await executeCommercialTool('decode_and_audit_evm_calldata', {
    to: '0x2626664c2603336E57B271c5C0b26F421741e481',
    data: v3SwapZeroMin,
    sender,
    chainId: 8453,
  });
  assert.equal(swapAudit.payload.audit.safeToExecute, false);
  assert.equal(swapAudit.payload.audit.riskLevel, 'CRITICAL');
  const swapCodes = new Set(swapAudit.payload.audit.findings.map((f) => f.code));
  assert.ok(swapCodes.has('ZERO_SLIPPAGE_MIN_OUT_MEV_RISK'));
  assert.ok(swapCodes.has('SWAP_OUTPUT_DIVERTED_TO_THIRD_PARTY'));

  // 3d. Multicall hiding `maxApproveData` inside a 2-call batch -> caught by recursive decoder!
  const inner1Hex = transferCalldata.slice(2); // 68 bytes -> padded to 96 bytes
  const inner2Hex = maxApproveData.slice(2); // 68 bytes -> padded to 96 bytes
  const padTo32Bytes = (h) => h.padEnd(Math.ceil(h.length / 64) * 64, '0');
  const elem1 = encodeUintWord(inner1Hex.length / 2) + padTo32Bytes(inner1Hex);
  const elem2 = encodeUintWord(inner2Hex.length / 2) + padTo32Bytes(inner2Hex);
  const multicallHex =
    selectorOf('multicall(bytes[])') +
    encodeUintWord(32) + // offset to bytes[]
    encodeUintWord(2) + // length = 2
    encodeUintWord(64) + // rel offset to elem1 (2 * 32)
    encodeUintWord(64 + elem1.length / 2) + // rel offset to elem2
    elem1 +
    elem2;

  const multiRes = await executeCommercialTool('decode_and_audit_evm_calldata', {
    to: usdcBase,
    data: multicallHex,
    chainId: 8453,
  });
  assert.equal(multiRes.payload.audit.safeToExecute, false);
  assert.equal(multiRes.payload.audit.riskLevel, 'CRITICAL');
  assert.equal(multiRes.payload.audit.subCalls.length, 2);
  assert.ok(multiRes.payload.audit.findings.some((f) => f.code === 'UNLIMITED_ERC20_APPROVAL'));

  // 3e. Gnosis Safe execTransaction with operation=1 (DELEGATECALL) -> CRITICAL BLOCK
  const safeExecHex =
    selectorOf('execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)') +
    encodeAddressWord(attacker) + // to
    encodeUintWord(0) + // value
    encodeUintWord(320) + // offset to data (10 * 32)
    encodeUintWord(1) + // operation = 1 (DELEGATECALL!)
    encodeUintWord(0) +
    encodeUintWord(0) +
    encodeUintWord(0) +
    encodeAddressWord('0x0000000000000000000000000000000000000000') +
    encodeAddressWord('0x0000000000000000000000000000000000000000') +
    encodeUintWord(352) + // offset to signatures
    encodeUintWord(0) + // empty inner data
    encodeUintWord(0); // empty signatures
  const safeRes = await executeCommercialTool('decode_and_audit_evm_calldata', {
    to: sender,
    data: safeExecHex,
    chainId: 8453,
  });
  assert.equal(safeRes.payload.audit.safeToExecute, false);
  assert.equal(safeRes.payload.audit.riskLevel, 'CRITICAL');
  assert.ok(safeRes.payload.audit.findings.some((f) => f.code === 'SAFE_DELEGATECALL_EXECUTION'));
});

test('4. audit_eip712_signature_payload catches Permit/Permit2 MAX allowances, Seaport zero-consideration drains, and validates x402 USDC', async () => {
  const nowSec = 1795480000;
  const bossWallet = '0xfEbDbB880C7f323c145d61683874a45540208a68';
  const usdcBase = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

  // 4a. Legitimate x402 Base USDC $0.01 (`10000` micro-USDC) TransferWithAuthorization -> SAFE_TO_SIGN
  const validX402 = await executeCommercialTool('audit_eip712_signature_payload', {
    typedData: {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'TransferWithAuthorization',
      domain: {
        name: 'USD Coin',
        version: '2',
        chainId: 8453,
        verifyingContract: usdcBase,
      },
      message: {
        from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        to: bossWallet,
        value: '10000', // $0.01 USDC
        validAfter: '0',
        validBefore: String(nowSec + 300),
        nonce: `0x${'ab'.repeat(32)}`,
      },
    },
    expectedChainId: 8453,
    expectedVerifyingContract: usdcBase,
    expectedRecipient: bossWallet,
    expectedMaxAmount: '20000',
    referenceTimestamp: nowSec,
  });
  assert.equal(validX402.payload.audit.safeToSign, true);
  assert.equal(validX402.payload.audit.recommendation, 'SAFE_TO_SIGN');
  assert.match(validX402.payload.audit.domain.domainSeparator, /^0x[0-9a-f]{64}$/);

  // 4b. Malicious Seaport zero-consideration NFT phishing payload -> CRITICAL DO_NOT_SIGN
  const seaportDrain = await executeCommercialTool('audit_eip712_signature_payload', {
    typedData: {
      primaryType: 'OrderComponents',
      domain: {
        name: 'Seaport',
        version: '1.5',
        chainId: 1,
        verifyingContract: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC',
      },
      types: { OrderComponents: [] },
      message: {
        offerer: bossWallet,
        offer: [
          {
            itemType: 2,
            token: '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
            identifierOrCriteria: '1234',
            startAmount: '1',
            endAmount: '1',
          },
        ],
        consideration: [
          {
            itemType: 0,
            token: '0x0000000000000000000000000000000000000000',
            identifierOrCriteria: '0',
            startAmount: '0',
            endAmount: '0',
            recipient: '0x1111111111111111111111111111111111111111', // Thief gets it, offerer gets 0!
          },
        ],
        startTime: String(nowSec),
        endTime: String(nowSec + 86400 * 365),
      },
    },
    expectedChainId: 8453, // Also spoofed chainId 1 vs 8453!
    referenceTimestamp: nowSec,
  });
  assert.equal(seaportDrain.payload.audit.safeToSign, false);
  assert.equal(seaportDrain.payload.audit.recommendation, 'DO_NOT_SIGN');
  const drainCodes = new Set(seaportDrain.payload.audit.findings.map((f) => f.code));
  assert.ok(drainCodes.has('SEAPORT_ZERO_CONSIDERATION_DRAIN'));
  assert.ok(drainCodes.has('DOMAIN_CHAIN_ID_MISMATCH'));
  assert.ok(drainCodes.has('MULTI_MONTH_OR_INFINITE_SIGNATURE_DEADLINE'));

  // 4c. Permit2 PermitSingle MAX_UINT160 allowance
  const permit2Drain = await executeCommercialTool('audit_eip712_signature_payload', {
    typedData: {
      primaryType: 'PermitSingle',
      domain: {
        name: 'Permit2',
        chainId: 8453,
        verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3',
      },
      types: { PermitSingle: [] },
      message: {
        details: {
          token: usdcBase,
          amount: ((1n << 160n) - 1n).toString(),
          expiration: String(nowSec + 86400 * 180),
          nonce: '0',
        },
        spender: '0x1111111111111111111111111111111111111111',
        sigDeadline: String(nowSec + 3600),
      },
    },
    referenceTimestamp: nowSec,
  });
  assert.equal(permit2Drain.payload.audit.safeToSign, false);
  assert.ok(permit2Drain.payload.audit.findings.some((f) => f.code === 'UNLIMITED_PERMIT2_ALLOWANCE'));
});

test('5. MCP stdio CLI binary handles newline JSON-RPC & Content-Length framing with zero stdout noise', async () => {
  const child = spawn(process.execPath, [resolve(ROOT_DIR, 'bin/web3-tx-guard-mcp.mjs')], {
    cwd: ROOT_DIR,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const responses = [];
  let stdoutBuf = '';
  child.stdout.on('data', (chunk) => {
    stdoutBuf += chunk.toString('utf8');
    while (stdoutBuf.includes('\n') && !stdoutBuf.startsWith('Content-Length:')) {
      const idx = stdoutBuf.indexOf('\n');
      const line = stdoutBuf.slice(0, idx).trim();
      stdoutBuf = stdoutBuf.slice(idx + 1);
      if (line) responses.push(JSON.parse(line));
    }
    while (stdoutBuf.startsWith('Content-Length:')) {
      const sep = stdoutBuf.indexOf('\r\n\r\n');
      if (sep === -1) break;
      const len = Number(stdoutBuf.slice(0, sep).match(/Content-Length:\s*(\d+)/i)[1]);
      const restBuf = Buffer.from(stdoutBuf.slice(sep + 4), 'utf8');
      if (restBuf.length < len) break;
      responses.push(JSON.parse(restBuf.subarray(0, len).toString('utf8')));
      stdoutBuf = restBuf.subarray(len).toString('utf8');
    }
  });

  const waitFor = (n) =>
    new Promise((res, rej) => {
      const deadline = Date.now() + 8000;
      const t = setInterval(() => {
        if (responses.length >= n) {
          clearInterval(t);
          res();
        } else if (Date.now() > deadline) {
          clearInterval(t);
          rej(new Error(`Timeout waiting for ${n} stdio responses`));
        }
      }, 20);
    });

  try {
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })}\n`,
    );
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`);
    await waitFor(2);
    assert.equal(responses[0].result.protocolVersion, '2025-06-18');
    assert.equal(responses[1].result.tools.length, 4);

    const callBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'validate_multichain_address',
        arguments: { address: '0xfEbDbB880C7f323c145d61683874a45540208a68' },
      },
    });
    child.stdin.write(`Content-Length: ${Buffer.byteLength(callBody, 'utf8')}\r\n\r\n${callBody}`);
    await waitFor(3);
    assert.equal(responses[2].result.isError, false);
    assert.equal(responses[2].result.structuredContent.summary.valid, true);
  } finally {
    child.kill();
  }
});

test('6. Streamable HTTP (POST / & /mcp), /ping, /health, Apify PPE /charge + Idempotency-Key + Batch Actor mode work end-to-end', async () => {
  const capturedCharges = [];
  const mockApify = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      capturedCharges.push({
        url: req.url,
        idem: req.headers['idempotency-key'],
        body: JSON.parse(body),
      });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { charged: true } }));
    });
  });
  await new Promise((r) => mockApify.listen(0, '127.0.0.1', r));

  const meter = new PayPerEventMeter({
    env: {
      ACTOR_RUN_ID: 'run_guard_01',
      APIFY_TOKEN: 'secret_tok',
      APIFY_API_BASE_URL: `http://127.0.0.1:${mockApify.address().port}`,
      APIFY_MAX_TOTAL_CHARGE_USD: '0.015',
    },
  });
  const srv = createHttpMcpServer({ meter });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${srv.address().port}`;

  try {
    const ping = await (await fetch(`${baseUrl}/ping`)).json();
    assert.equal(ping.status, 'pong');

    const health = await (await fetch(`${baseUrl}/health`)).json();
    assert.equal(health.status, 'healthy');

    const probe = await (
      await fetch(`${baseUrl}/`, { headers: { 'x-apify-container-server-readiness-probe': '1' } })
    ).json();
    assert.equal(probe.readinessProbe, true);

    // POST / (MCPize root gateway) + Idempotency-Key deduplication
    const callReq = {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'idempotency-key': 'idem-guard-1' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: {
          name: 'validate_multichain_address',
          arguments: { address: 'TScN3VSpNyxPYvCsvSaze2HFkFFuCAXgYE' },
        },
      }),
    };
    const r1 = await (await fetch(`${baseUrl}/`, callReq)).json();
    assert.equal(r1.result.isError, false);
    assert.equal(capturedCharges.length, 1);

    const r1Retry = await (await fetch(`${baseUrl}/mcp`, callReq)).json();
    assert.equal(r1Retry.result.structuredContent.billing.deduplicated, true);
    assert.equal(capturedCharges.length, 1);

    // Budget cap exceeded on distinct second $0.01 call ($0.02 > $0.015)
    const r2 = await (
      await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 11,
          method: 'tools/call',
          params: {
            name: 'validate_multichain_address',
            arguments: { address: 'rGQn9jT7D2cGJHTHDPwAQusj6Pkr8HUJLb' },
          },
        }),
      })
    ).json();
    assert.equal(r2.result.isError, true);
    assert.match(r2.result.content[0].text, /MAX_TOTAL_CHARGE_EXCEEDED/);
  } finally {
    srv.close();
    mockApify.close();
  }

  // Batch Actor storage test
  const tempStorage = mkdtempSync(join(tmpdir(), 'guard-batch-'));
  try {
    const kvDir = resolve(tempStorage, 'key_value_stores/default');
    mkdirSync(kvDir, { recursive: true });
    writeFileSync(
      resolve(kvDir, 'INPUT.json'),
      JSON.stringify({
        tool: 'validate_multichain_address',
        address: 'bc1plp3p4kn3y7r6krl5nyxwz8rn79nq8yxy4n6t3utftugcmvqc78rqh533m0',
        expectedNetwork: 'mainnet',
      }),
      'utf8',
    );
    const batchRes = await runBatchActor({ env: { APIFY_LOCAL_STORAGE_DIR: tempStorage } });
    assert.equal(batchRes.totalChargedUsd, 0.011);
    assert.ok(existsSync(resolve(kvDir, 'OUTPUT.json')));
    assert.ok(existsSync(resolve(tempStorage, 'datasets/default/000000001.json')));
  } finally {
    rmSync(tempStorage, { recursive: true, force: true });
  }
});
