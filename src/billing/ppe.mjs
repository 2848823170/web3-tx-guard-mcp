/**
 * Apify Pay-Per-Event (PPE) Billing Client & Local Metering Ledger (`ppe.mjs`).
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PPE_SCHEMA_PATH = resolve(__dirname, '../../.actor/pay_per_event.json');

export function loadPpeCatalog() {
  const raw = JSON.parse(readFileSync(PPE_SCHEMA_PATH, 'utf8'));
  const map = new Map();
  const entries = Array.isArray(raw) ? raw : [raw];
  for (const item of entries) {
    for (const [eventName, cfg] of Object.entries(item)) {
      map.set(eventName, {
        eventName,
        eventTitle: cfg.eventTitle,
        eventDescription: cfg.eventDescription,
        eventPriceUsd: Number(cfg.eventPriceUsd || 0),
      });
    }
  }
  return map;
}

export class PayPerEventMeter {
  constructor({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
    this.env = env;
    this.fetchImpl = fetchImpl;
    this.catalog = loadPpeCatalog();
    this.charges = [];
    this.idempotencyCache = new Map();
    this.totalChargedUsd = 0;
    this.seq = 0;
  }

  getMaxBudgetUsd() {
    const raw = this.env.APIFY_MAX_TOTAL_CHARGE_USD;
    if (raw === undefined || raw === null || raw === '') return Infinity;
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : Infinity;
  }

  getCatalogSummary() {
    return [...this.catalog.values()];
  }

  canAfford(eventName, count = 1, idempotencyKey = null) {
    if (idempotencyKey && this.idempotencyCache.has(idempotencyKey)) {
      return { ok: true, deduplicated: true };
    }
    const spec = this.catalog.get(eventName);
    if (!spec) {
      throw new Error(`Unknown Pay-Per-Event name: "${eventName}"`);
    }
    const qty = Math.max(1, Math.floor(Number(count) || 1));
    const lineUsd = Number((spec.eventPriceUsd * qty).toFixed(6));
    const maxBudget = this.getMaxBudgetUsd();
    if (this.totalChargedUsd + lineUsd > maxBudget + 1e-9) {
      return {
        ok: false,
        reason: 'MAX_TOTAL_CHARGE_EXCEEDED',
        maxBudgetUsd: maxBudget,
        totalChargedUsd: this.totalChargedUsd,
      };
    }
    return { ok: true, deduplicated: false };
  }

  async charge({ eventName, count = 1, idempotencyKey = null } = {}) {
    if (idempotencyKey && this.idempotencyCache.has(idempotencyKey)) {
      return { ...this.idempotencyCache.get(idempotencyKey), deduplicated: true };
    }
    const spec = this.catalog.get(eventName);
    if (!spec) {
      throw new Error(`Unknown Pay-Per-Event name: "${eventName}"`);
    }
    const qty = Math.max(1, Math.floor(Number(count) || 1));
    const lineUsd = Number((spec.eventPriceUsd * qty).toFixed(6));
    const maxBudget = this.getMaxBudgetUsd();

    if (this.totalChargedUsd + lineUsd > maxBudget + 1e-9) {
      return {
        charged: false,
        reason: 'MAX_TOTAL_CHARGE_EXCEEDED',
        eventName,
        count: qty,
        unitPriceUsd: spec.eventPriceUsd,
        amountUsd: 0,
        totalChargedUsd: this.totalChargedUsd,
        maxBudgetUsd: maxBudget,
      };
    }

    const runId = this.env.ACTOR_RUN_ID || this.env.APIFY_ACTOR_RUN_ID || '';
    const token = this.env.APIFY_TOKEN || '';
    const apiBase = (this.env.APIFY_API_BASE_URL || 'https://api.apify.com').replace(/\/+$/, '');
    const idemKey =
      idempotencyKey || `${runId || 'local'}-${eventName}-${++this.seq}-${randomUUID().slice(0, 8)}`;

    let remoteStatus = 'local-metered';
    if (runId && token && typeof this.fetchImpl === 'function') {
      const url = `${apiBase}/v2/actor-runs/${encodeURIComponent(runId)}/charge`;
      const res = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${token}`,
          'idempotency-key': idemKey,
        },
        body: JSON.stringify({ eventName, count: qty }),
      });

      if (res.status === 402 || res.status === 403) {
        return {
          charged: false,
          reason: `APIFY_CHARGE_LIMIT_HTTP_${res.status}`,
          eventName,
          count: qty,
          unitPriceUsd: spec.eventPriceUsd,
          amountUsd: 0,
          totalChargedUsd: this.totalChargedUsd,
        };
      }
      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        throw new Error(`Apify PPE charge HTTP ${res.status}: ${errBody.slice(0, 200)}`);
      }
      remoteStatus = 'apify-cloud-charged';
    }

    this.totalChargedUsd = Number((this.totalChargedUsd + lineUsd).toFixed(6));
    const record = {
      charged: true,
      mode: remoteStatus,
      timestamp: new Date().toISOString(),
      eventName,
      eventTitle: spec.eventTitle,
      count: qty,
      unitPriceUsd: spec.eventPriceUsd,
      amountUsd: lineUsd,
      totalChargedUsd: this.totalChargedUsd,
      idempotencyKey: idemKey,
    };
    this.charges.push(record);
    if (idempotencyKey) {
      this.idempotencyCache.set(idempotencyKey, record);
    }
    return record;
  }
}
