/**
 * Unified Entrypoint for `web3-tx-guard-mcp` (`main.mjs`).
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PayPerEventMeter } from './billing/ppe.mjs';
import { createHttpMcpServer, startStdioMcpServer } from './mcp/server.mjs';
import { executeCommercialTool } from './mcp/tools.mjs';

async function loadApifyInput({ env = process.env, inputFile = null, fetchImpl = globalThis.fetch } = {}) {
  if (inputFile && existsSync(inputFile)) {
    return JSON.parse(readFileSync(inputFile, 'utf8'));
  }

  const kvId = env.APIFY_DEFAULT_KEY_VALUE_STORE_ID || '';
  const token = env.APIFY_TOKEN || '';
  const isAtHome = env.APIFY_IS_AT_HOME === '1' || env.APIFY_IS_AT_HOME === 'true';
  const apiBase = (env.APIFY_API_BASE_URL || 'https://api.apify.com').replace(/\/+$/, '');
  const inputKey = env.APIFY_INPUT_KEY || 'INPUT';

  if (isAtHome && kvId && token && typeof fetchImpl === 'function') {
    const res = await fetchImpl(
      `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvId)}/records/${encodeURIComponent(inputKey)}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    if (res.ok) {
      return await res.json();
    }
  }

  const storageDir = resolve(env.APIFY_LOCAL_STORAGE_DIR || './storage');
  for (const candidate of [
    resolve(storageDir, `key_value_stores/default/${inputKey}.json`),
    resolve(storageDir, `key_value_stores/default/${inputKey}`),
  ]) {
    if (existsSync(candidate)) {
      return JSON.parse(readFileSync(candidate, 'utf8'));
    }
  }
  return {};
}

async function putApifyKvRecord(
  key,
  body,
  contentType,
  { env = process.env, fetchImpl = globalThis.fetch } = {},
) {
  const kvId = env.APIFY_DEFAULT_KEY_VALUE_STORE_ID || '';
  const token = env.APIFY_TOKEN || '';
  const isAtHome = env.APIFY_IS_AT_HOME === '1' || env.APIFY_IS_AT_HOME === 'true';
  const apiBase = (env.APIFY_API_BASE_URL || 'https://api.apify.com').replace(/\/+$/, '');

  if (isAtHome && kvId && token && typeof fetchImpl === 'function') {
    const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    await fetchImpl(
      `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvId)}/records/${encodeURIComponent(key)}`,
      {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': contentType,
        },
        body: payload,
      },
    );
    return;
  }

  const kvDir = resolve(env.APIFY_LOCAL_STORAGE_DIR || './storage', 'key_value_stores/default');
  mkdirSync(kvDir, { recursive: true });
  const ext = key.includes('.') ? '' : contentType.includes('json') ? '.json' : '';
  const target = resolve(kvDir, `${key}${ext}`);
  if (typeof body === 'string') {
    writeFileSync(target, body, 'utf8');
  } else {
    writeFileSync(target, JSON.stringify(body, null, 2), 'utf8');
  }
}

async function pushApifyDatasetItem(item, { env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const dsId = env.APIFY_DEFAULT_DATASET_ID || '';
  const token = env.APIFY_TOKEN || '';
  const isAtHome = env.APIFY_IS_AT_HOME === '1' || env.APIFY_IS_AT_HOME === 'true';
  const apiBase = (env.APIFY_API_BASE_URL || 'https://api.apify.com').replace(/\/+$/, '');

  if (isAtHome && dsId && token && typeof fetchImpl === 'function') {
    await fetchImpl(`${apiBase}/v2/datasets/${encodeURIComponent(dsId)}/items`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify([item]),
    });
    return;
  }

  const dsDir = resolve(env.APIFY_LOCAL_STORAGE_DIR || './storage', 'datasets/default');
  mkdirSync(dsDir, { recursive: true });
  const existing = readdirSync(dsDir).filter((f) => f.endsWith('.json')).length;
  const nextName = `${String(existing + 1).padStart(9, '0')}.json`;
  writeFileSync(resolve(dsDir, nextName), JSON.stringify(item, null, 2), 'utf8');
}

export async function runBatchActor({
  env = process.env,
  inputFile = null,
  fetchImpl = globalThis.fetch,
} = {}) {
  const meter = new PayPerEventMeter({ env, fetchImpl });
  const input = await loadApifyInput({ env, inputFile, fetchImpl });
  const toolName = input.tool || 'validate_multichain_address';

  const startCharge = await meter.charge({ eventName: 'actor-start', count: 1 });
  if (!startCharge.charged) {
    throw new Error(`Batch run aborted before execution: ${startCharge.reason}`);
  }

  const execRes = await executeCommercialTool(toolName, input, { meter });

  await putApifyKvRecord('OUTPUT', execRes.payload, 'application/json; charset=utf-8', {
    env,
    fetchImpl,
  });

  await putApifyKvRecord(
    'PPE_CHARGES',
    {
      totalChargedUsd: meter.totalChargedUsd,
      charges: meter.charges,
    },
    'application/json; charset=utf-8',
    { env, fetchImpl },
  );

  await pushApifyDatasetItem(
    {
      tool: toolName,
      status: 'ok',
      billedEvent: execRes.billing?.eventName || null,
      billedUsd: meter.totalChargedUsd,
      summary: execRes.payload.summary,
    },
    { env, fetchImpl },
  );

  return {
    payload: execRes.payload,
    totalChargedUsd: meter.totalChargedUsd,
    charges: meter.charges,
  };
}

function hasLocalBatchInput(env = process.env) {
  const inputKey = env.APIFY_INPUT_KEY || 'INPUT';
  const storageDir = resolve(env.APIFY_LOCAL_STORAGE_DIR || './storage');
  return (
    existsSync(resolve(storageDir, `key_value_stores/default/${inputKey}.json`)) ||
    existsSync(resolve(storageDir, `key_value_stores/default/${inputKey}`))
  );
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const isStdio = argv.includes('--stdio');
  const inputIdx = argv.indexOf('--input-file');
  const inputFile = inputIdx !== -1 ? argv[inputIdx + 1] : null;
  const isExplicitBatch = argv.includes('--batch') || Boolean(inputFile);
  const metaOrigin = String(env.APIFY_META_ORIGIN || '').toUpperCase();
  const isAtHome = env.APIFY_IS_AT_HOME === '1' || env.APIFY_IS_AT_HOME === 'true';

  if (isStdio) {
    const meter = new PayPerEventMeter({ env });
    startStdioMcpServer({ meter });
    return;
  }

  const shouldRunBatch =
    isExplicitBatch ||
    (!argv.includes('--http') &&
      !argv.includes('--standby') &&
      metaOrigin !== 'STANDBY' &&
      String(env.MCP_TRANSPORT || '').toLowerCase() !== 'http' &&
      (isAtHome || hasLocalBatchInput(env)));

  if (!shouldRunBatch) {
    const portArgIdx = argv.indexOf('--port');
    const port =
      portArgIdx !== -1 && argv[portArgIdx + 1]
        ? Number(argv[portArgIdx + 1])
        : Number(env.ACTOR_WEB_SERVER_PORT || env.APIFY_CONTAINER_PORT || env.PORT || 8080);

    const meter = new PayPerEventMeter({ env });
    const server = createHttpMcpServer({ meter });
    await new Promise((resolveListen) => server.listen(port, '0.0.0.0', resolveListen));
    const shutdown = () => {
      server.close(() => process.exit(0));
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);
    console.error(
      `[web3-tx-guard-mcp] Standby Streamable HTTP + SSE MCP server listening on http://0.0.0.0:${port}/mcp`,
    );
    return server;
  }

  const batchRes = await runBatchActor({ env, inputFile });
  console.log(
    JSON.stringify(
      {
        status: 'ok',
        tool: batchRes.payload.tool,
        totalChargedUsd: batchRes.totalChargedUsd,
        summary: batchRes.payload.summary,
      },
      null,
      2,
    ),
  );
  return batchRes;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('[web3-tx-guard-mcp] Fatal error:', err?.stack || err);
    process.exit(1);
  });
}
