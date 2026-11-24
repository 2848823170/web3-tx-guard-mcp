/**
 * Official MCP SDK Entrypoint & Capability Registry (`src/index.js`).
 *
 * Registers all 3 Web3 pre-flight security tools, pricing resource, and workflow prompts
 * on `@modelcontextprotocol/sdk`'s `McpServer` for 100% static & runtime discovery across
 * MCPize (`x402` Base USDC), Apify Store (PPE Standby `/mcp`), Glama, and local `stdio`.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

import { PayPerEventMeter } from './billing/ppe.mjs';
import { main, runBatchActor } from './main.mjs';
import { createHttpMcpServer, SERVER_INFO, startStdioMcpServer } from './mcp/server.mjs';
import { executeCommercialTool, MCP_TOOLS } from './mcp/tools.mjs';

export function createMcpServer({ meter = null } = {}) {
  const server = new McpServer({
    name: SERVER_INFO.name,
    version: SERVER_INFO.version,
  });

  server.registerTool(
    'validate_multichain_address',
    {
      title: 'Validate & Normalize Multichain Wallet Address',
      description:
        'Cryptographically validates and normalizes addresses across EVM (EIP-55), Tron (Base58Check), Bitcoin (Bech32/Bech32m/Base58Check), Solana (Ed25519 curve vs PDA), TON (EQ/UQ CRC16 + bounce trap), XRP Ledger (r-address + X-address tag), Cosmos, and Stacks.',
      inputSchema: {
        address: z.string().describe('Wallet or contract address string to validate'),
        chain: z
          .string()
          .optional()
          .describe('Optional chain hint: auto, evm, tron, bitcoin, solana, ton, xrpl, cosmos, stacks'),
        expectedNetwork: z
          .enum(['any', 'mainnet', 'testnet'])
          .optional()
          .describe('Expected network environment (mainnet, testnet, or any)'),
      },
    },
    async (args) => {
      const res = await executeCommercialTool('validate_multichain_address', args, { meter });
      return {
        content: [{ type: 'text', text: JSON.stringify(res.payload, null, 2) }],
        structuredContent: res.payload,
      };
    },
  );

  server.registerTool(
    'decode_and_audit_evm_calldata',
    {
      title: 'Decode & Audit Raw EVM Transaction Calldata',
      description:
        'Decodes raw hex EVM transaction payloads (`to`, `value`, `data`, `chainId`) across ERC-20/721/1155, Permit2, Uniswap V2/V3/UniversalRouter, 1inch, Multicall, and Safe, flagging unlimited approvals, zero-minOut MEV sandwich exposure, and DELEGATECALL takeovers.',
      inputSchema: {
        to: z.string().optional().describe('Target 0x contract or recipient address'),
        value: z.string().optional().describe('Native ETH value in wei (decimal or 0x hex)'),
        data: z.string().describe('0x-prefixed hex calldata string'),
        chainId: z.number().optional().describe('EVM Chain ID (default: 8453 Base)'),
        sender: z.string().optional().describe('Optional sender 0x address for output-diversion check'),
        referenceTimestamp: z.number().optional().describe('Optional Unix timestamp in seconds'),
      },
    },
    async (args) => {
      const res = await executeCommercialTool('decode_and_audit_evm_calldata', args, { meter });
      return {
        content: [{ type: 'text', text: JSON.stringify(res.payload, null, 2) }],
        structuredContent: res.payload,
      };
    },
  );

  server.registerTool(
    'audit_eip712_signature_payload',
    {
      title: 'Audit Off-Chain EIP-712 Typed-Data Signature Payload',
      description:
        'Audits eth_signTypedData_v4 payloads (EIP-2612 Permit, DAI Permit, Permit2, Seaport, EIP-3009 x402, ForwardRequest, SafeTx) for unlimited allowances, zero-consideration NFT/token drains, DELEGATECALL, and domain spoofing.',
      inputSchema: {
        typedData: z.any().describe('eth_signTypedData_v4 JSON object or serialized JSON string'),
        expectedChainId: z.number().optional().describe('Optional expected EVM chainId'),
        expectedVerifyingContract: z.string().optional().describe('Optional expected 0x verifyingContract'),
        expectedRecipient: z.string().optional().describe('Optional expected 0x recipient for x402 / EIP-3009'),
        expectedMaxAmount: z.string().optional().describe('Optional maximum expected token amount'),
        referenceTimestamp: z.number().optional().describe('Optional Unix timestamp in seconds'),
      },
    },
    async (args) => {
      const res = await executeCommercialTool('audit_eip712_signature_payload', args, { meter });
      return {
        content: [{ type: 'text', text: JSON.stringify(res.payload, null, 2) }],
        structuredContent: res.payload,
      };
    },
  );

  server.registerResource(
    'pricing',
    'mcp://web3-tx-guard-mcp/pricing',
    {
      title: 'x402 Base USDC & Apify PPE Pricing Catalog',
      description: 'Transparent $0.01/call pricing for Web3 Tx Guard tools',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(
            {
              server: SERVER_INFO,
              events: meter ? meter.getCatalogSummary() : [],
            },
            null,
            2,
          ),
        },
      ],
    }),
  );

  server.registerPrompt(
    'preflight-wallet-transfer-guard',
    {
      description:
        'Validate recipient wallet checksum, network match, PDA/bounce flags, and burn-address safety before broadcasting an on-chain payout.',
    },
    async () => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: 'Run validate_multichain_address using web3-tx-guard-mcp before sending funds.',
          },
        },
      ],
    }),
  );

  return server;
}

export const DEFAULT_PORT = parseInt(process.env.PORT || '8080', 10);

export {
  createHttpMcpServer,
  executeCommercialTool,
  main,
  MCP_TOOLS,
  PayPerEventMeter,
  runBatchActor,
  startStdioMcpServer,
  StdioServerTransport,
  StreamableHTTPServerTransport,
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('[web3-tx-guard-mcp] Fatal error:', err?.stack || err);
    process.exit(1);
  });
}
