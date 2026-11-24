/**
 * Commercial MCP Tool Registry & Execution Dispatcher (`tools.mjs`).
 *
 * Exposes 3 deterministic Web3 pre-flight security tools ($0.01 USDC via x402 / PPE):
 * 1. `validate_multichain_address`
 * 2. `decode_and_audit_evm_calldata`
 * 3. `audit_eip712_signature_payload`
 */

import { auditEip712SignaturePayload } from '../core/eip712-audit.mjs';
import { decodeAndAuditEvmCalldata } from '../core/evm-calldata.mjs';
import { validateMultichainAddress } from '../core/multichain-address.mjs';
import { scanOnChainTokenRugRisk } from '../core/token-rug-scanner.mjs';

export const MCP_TOOLS = [
  {
    name: 'validate_multichain_address',
    title: 'Validate & Normalize Multichain Wallet Address',
    description:
      'Cryptographically validates and normalizes wallet/contract addresses across 8 ecosystems: EVM (Keccak-256 EIP-55 checksum + typo/burn detection), Tron (T... SHA-256d Base58Check + 0x41/EVM conversion), Bitcoin (BIP-173 Bech32 bc1q SegWit v0, BIP-350 Bech32m bc1p Taproot v1+, Legacy/P2SH Base58Check), Solana (Base58 32-byte Ed25519 curve point check distinguishing user wallets from off-curve PDAs), TON (friendly EQ/UQ CRC16-XMODEM + bounceable uninitialized-wallet trap warning), XRP Ledger (classic r... + XLS-5d X-address destination-tag decoder), Cosmos Bech32, and Stacks c32check.',
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description: 'Address string to validate and normalize.',
        },
        chain: {
          type: 'string',
          description:
            'Optional chain constraint: auto (default), evm, tron, bitcoin, solana, ton, xrpl, cosmos, or stacks.',
          default: 'auto',
        },
        expectedNetwork: {
          type: 'string',
          enum: ['any', 'mainnet', 'testnet'],
          description:
            'Expected network environment (default: any; pass "mainnet" before sending real funds to block testnet addresses).',
          default: 'any',
        },
      },
      required: ['address'],
    },
    annotations: {
      title: 'Validate Multichain Address ($0.01)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'decode_and_audit_evm_calldata',
    title: 'Decode & Audit Raw EVM Transaction Calldata',
    description:
      'Deterministically decodes raw hex EVM transaction payloads (`to`, `value`, `data`, `chainId`) across ERC-20 (`transfer`, `approve`, `transferFrom`, `increaseAllowance`), ERC-721/1155 (`setApprovalForAll`, `safeTransferFrom`), Permit2, Uniswap V2/V3/UniversalRouter, 1inch, Multicall (recursive inner-call decoding), and Gnosis Safe `execTransaction`. Flags CRITICAL unlimited approvals (>= 2^255 / MAX_UINT160), setApprovalForAll(true), zero-minOut MEV sandwich exposure, non-zero ETH sent with approvals, expired deadlines, and DELEGATECALL takeovers.',
    inputSchema: {
      type: 'object',
      properties: {
        to: {
          type: 'string',
          description: 'Target 0x contract or recipient address (empty for contract deployment).',
        },
        value: {
          type: 'string',
          description: 'Native ETH/gas token value in wei (decimal integer string or 0x hex, default: "0").',
          default: '0',
        },
        data: {
          type: 'string',
          description: '0x-prefixed hex calldata string (default: "0x").',
          default: '0x',
        },
        chainId: {
          type: 'number',
          description: 'EVM Chain ID (e.g. 1 = Ethereum, 8453 = Base, 42161 = Arbitrum, 137 = Polygon).',
          default: 8453,
        },
        sender: {
          type: 'string',
          description: 'Optional sender 0x address to detect swap proceeds diverted to a third-party address.',
        },
        referenceTimestamp: {
          type: 'number',
          description: 'Optional Unix timestamp in seconds for deterministic deadline checks.',
        },
      },
      required: ['data'],
    },
    annotations: {
      title: 'Decode & Audit EVM Calldata ($0.01)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'audit_eip712_signature_payload',
    title: 'Audit Off-Chain EIP-712 Typed-Data Signature Payload',
    description:
      'Audits off-chain `eth_signTypedData_v4` JSON objects or strings (`Permit`, DAI `Permit`, `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, Seaport `OrderComponents`, Circle USDC EIP-3009 `TransferWithAuthorization` / `x402`, `ForwardRequest`, `SafeTx`) before signing. Computes EIP-712 `domainSeparator` and flags unlimited allowances, Seaport zero-consideration NFT/token drains, DELEGATECALL meta-txs, multi-month/infinite signature expirations, and domain chainId/contract spoofing.',
    inputSchema: {
      type: 'object',
      properties: {
        typedData: {
          description: 'eth_signTypedData_v4 JSON object (or serialized JSON string) containing domain, types, primaryType, and message.',
        },
        expectedChainId: {
          type: 'number',
          description: 'Optional expected EVM chainId to catch cross-chain domain spoofing.',
        },
        expectedVerifyingContract: {
          type: 'string',
          description: 'Optional expected 0x verifyingContract address.',
        },
        expectedRecipient: {
          type: 'string',
          description: 'Optional expected 0x recipient for EIP-3009 / x402 TransferWithAuthorization checks.',
        },
        expectedMaxAmount: {
          type: 'string',
          description: 'Optional maximum expected raw token amount (decimal or 0x hex) to guard against over-billing.',
        },
        referenceTimestamp: {
          type: 'number',
          description: 'Optional Unix timestamp in seconds for deterministic deadline checks.',
        },
      },
      required: ['typedData'],
    },
    annotations: {
      title: 'Audit EIP-712 Signature Payload ($0.01)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'scan_token_rug_risk',
    title: 'Scan Live Base & Solana Token Honeypot, Rug-Pull & Liquidity Risk',
    description:
      'Live on-chain token security oracle for autonomous trading agents (`ElizaOS`, `Coinbase AgentKit`, `Virtuals`, `GOAT`). Queries Base Mainnet (`8453`) and Solana Mainnet RPCs to detect EIP-1967 upgradeable proxies, unrenounced `owner()`, `SELFDESTRUCT`/`DELEGATECALL`/blacklist/fee-setter bytecode selectors, Uniswap V2/V3 & Aerodrome reserve depth + LP burn %, live `eth_call` `transfer()` honeypot simulation, Solana `mintAuthority`/`freezeAuthority`, Token-2022 `permanentDelegate`/`transferFeeConfig`/`transferHook` traps, and Top-1/Top-5/Top-10 holder concentration.',
    inputSchema: {
      type: 'object',
      properties: {
        tokenAddress: {
          type: 'string',
          description:
            'Base Mainnet ERC-20 contract address (0x + 40 hex) or Solana SPL / Token-2022 mint address (32–44 Base58 chars).',
        },
        chain: {
          type: 'string',
          enum: ['auto', 'base', 'solana'],
          description: 'Target chain: auto (default), base, or solana.',
          default: 'auto',
        },
      },
      required: ['tokenAddress'],
    },
    annotations: {
      title: 'Scan Live Token Rug & Honeypot Risk ($0.01)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];

export async function executeCommercialTool(
  toolName,
  args = {},
  { meter = null, idempotencyKey = null } = {},
) {
  const preCheckBudget = (eventName) => {
    if (!meter) return;
    const check = meter.canAfford(eventName, 1, idempotencyKey);
    if (!check.ok) {
      throw new Error(`Pay-Per-Event spending limit reached (${check.reason}).`);
    }
  };

  if (toolName === 'validate_multichain_address') {
    if (!args.address || typeof args.address !== 'string' || !args.address.trim()) {
      throw new Error('`validate_multichain_address` requires a non-empty `address` string.');
    }
    preCheckBudget('validate-multichain-address');

    const analysis = validateMultichainAddress({
      address: args.address,
      chain: args.chain || 'auto',
      expectedNetwork: args.expectedNetwork || 'any',
    });

    const chargeReceipt = meter
      ? await meter.charge({ eventName: 'validate-multichain-address', count: 1, idempotencyKey })
      : null;
    if (chargeReceipt && !chargeReceipt.charged) {
      throw new Error(`Pay-Per-Event spending limit reached (${chargeReceipt.reason}).`);
    }

    const payload = {
      tool: toolName,
      status: 'ok',
      billing: chargeReceipt,
      summary: {
        valid: analysis.valid,
        safeToTransact: analysis.safeToTransact,
        riskLevel: analysis.riskLevel,
        chain: analysis.chain,
        network: analysis.network,
        canonicalAddress: analysis.canonicalAddress,
      },
      analysis,
    };
    return { payload, billing: chargeReceipt };
  }

  if (toolName === 'decode_and_audit_evm_calldata') {
    if (args.data === undefined && args.to === undefined) {
      throw new Error('`decode_and_audit_evm_calldata` requires `data` (0x hex) and/or `to` address.');
    }
    preCheckBudget('decode-audit-evm-calldata');

    const audit = decodeAndAuditEvmCalldata({
      to: args.to || '',
      value: args.value ?? '0',
      data: args.data ?? '0x',
      chainId: args.chainId ?? 8453,
      sender: args.sender || '',
      referenceTimestamp: args.referenceTimestamp ?? null,
    });

    const chargeReceipt = meter
      ? await meter.charge({ eventName: 'decode-audit-evm-calldata', count: 1, idempotencyKey })
      : null;
    if (chargeReceipt && !chargeReceipt.charged) {
      throw new Error(`Pay-Per-Event spending limit reached (${chargeReceipt.reason}).`);
    }

    const payload = {
      tool: toolName,
      status: 'ok',
      billing: chargeReceipt,
      summary: {
        safeToExecute: audit.safeToExecute,
        recommendation: audit.recommendation,
        riskLevel: audit.riskLevel,
        riskScore: audit.riskScore,
        standard: audit.standard,
        functionName: audit.functionName,
        findingCount: audit.findings.length,
      },
      audit,
    };
    return { payload, billing: chargeReceipt };
  }

  if (toolName === 'audit_eip712_signature_payload') {
    if (args.typedData === undefined || args.typedData === null || args.typedData === '') {
      throw new Error('`audit_eip712_signature_payload` requires a non-empty `typedData` object or JSON string.');
    }
    preCheckBudget('audit-eip712-signature');

    const audit = auditEip712SignaturePayload({
      typedData: args.typedData,
      expectedChainId: args.expectedChainId ?? null,
      expectedVerifyingContract: args.expectedVerifyingContract || '',
      expectedRecipient: args.expectedRecipient || '',
      expectedMaxAmount: args.expectedMaxAmount ?? null,
      referenceTimestamp: args.referenceTimestamp ?? null,
    });

    const chargeReceipt = meter
      ? await meter.charge({ eventName: 'audit-eip712-signature', count: 1, idempotencyKey })
      : null;
    if (chargeReceipt && !chargeReceipt.charged) {
      throw new Error(`Pay-Per-Event spending limit reached (${chargeReceipt.reason}).`);
    }

    const payload = {
      tool: toolName,
      status: 'ok',
      billing: chargeReceipt,
      summary: {
        safeToSign: audit.safeToSign,
        recommendation: audit.recommendation,
        riskLevel: audit.riskLevel,
        riskScore: audit.riskScore,
        schemaCategory: audit.schemaCategory,
        primaryType: audit.primaryType,
        findingCount: audit.findings.length,
      },
      audit,
    };
    return { payload, billing: chargeReceipt };
  }

  if (toolName === 'scan_token_rug_risk') {
    if (!args.tokenAddress || typeof args.tokenAddress !== 'string' || !args.tokenAddress.trim()) {
      throw new Error('`scan_token_rug_risk` requires a non-empty `tokenAddress` string.');
    }
    preCheckBudget('scan-token-rug-risk');

    const scan = await scanOnChainTokenRugRisk({
      tokenAddress: args.tokenAddress,
      chain: args.chain || 'auto',
    });

    const chargeReceipt = meter
      ? await meter.charge({ eventName: 'scan-token-rug-risk', count: 1, idempotencyKey })
      : null;
    if (chargeReceipt && !chargeReceipt.charged) {
      throw new Error(`Pay-Per-Event spending limit reached (${chargeReceipt.reason}).`);
    }

    const payload = {
      tool: toolName,
      status: 'ok',
      billing: chargeReceipt,
      summary: {
        chain: scan.chain,
        tokenAddress: scan.tokenAddress,
        symbol: scan.token?.symbol || null,
        safeToTrade: scan.safeToTrade,
        recommendation: scan.recommendation,
        riskLevel: scan.riskLevel,
        riskScore: scan.riskScore,
        findingCount: scan.findings.length,
        latencyMs: scan.latencyMs,
      },
      scan,
    };
    return { payload, billing: chargeReceipt };
  }

  const err = new Error(`Unknown MCP tool: "${toolName}"`);
  err.code = -32602;
  throw err;
}
