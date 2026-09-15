const { rateLimit, ipKeyGenerator, MemoryStore } = require('express-rate-limit');

const safeMetadataFetch = require('../services/oauth/safeMetadataFetch');

/**
 * Ticket 45 — OAuth path-specific rate limits.
 *
 * Global limiter (1000/15min ≈ 1.1 req/s per address) is wrong both ways:
 *   too loose for authorize (anonymous stranger-URL CIMD fetch / amplifier)
 *   too tight for MCP introspect+token (one Render egress for the whole population)
 *
 * Two authorize buckets, stacked — not a composite address+client key (attacker
 * controls client_id and would mint a fresh bucket per invent). Per address =
 * spray many victims; per hostname = many hosts → one victim.
 *
 * MemoryStore is per process (LEGACY #5): ceiling × instance count. Weakens,
 * does not remove. Mount rules for MCP_SERVICE_PATHS: see that constant.
 */

// Aligns with middleware/rateLimiter.js signup style; << global.
const AUTHORIZE_WINDOW_MS = 10 * 60 * 1000;
const AUTHORIZE_MAX = 10;

// Counts requests that *may* fetch (malformed still consume a slot — intentional).
// Key = assistant hostname → shared by every NutriHelp user of that assistant.
const METADATA_FETCH_WINDOW_MS = 60 * 60 * 1000;
const METADATA_FETCH_MAX = 30;

/** Measured after trimming. Longer than any real CIMD URL; see clientKey. */
const MAX_CLIENT_ID_LENGTH = 512;

// Higher than global: live introspect per tool call + exchange, one egress IP.
const MCP_SERVICE_WINDOW_MS = 15 * 60 * 1000;
const MCP_SERVICE_MAX = 6000;

const stores = [];

/** Every limiter gets its own store so one path cannot drain another's. */
const newStore = () => {
  const store = new MemoryStore();
  stores.push(store);
  return store;
};

const tooMany = (error) => ({ status: 429, error, code: 'RATE_LIMITED' });

/**
 * ipKeyGenerator(ip) — IPv6 grouped /56 so a prefix cannot walk the bucket.
 * Residual: trust proxy:1 / X-Forwarded-For (app-wide). Hostname bucket still
 * caps per-victim egress.
 */
const addressKey = (req) => ipKeyGenerator(req.ip);

/**
 * Key = client_id hostname (same parser as the fetch). Full-URL keys would
 * give every path its own budget at one host. Parser refusals → shared
 * `client:absent` (skip would bypass).
 */
const clientKey = (req) => {
  const raw = req.query && req.query.client_id;
  // Trim before length — padding used to shift the key while fetch used trim.
  const candidate = typeof raw === 'string' ? raw.trim() : '';
  if (candidate === '' || candidate.length > MAX_CLIENT_ID_LENGTH) return 'client:absent';

  const parsed = safeMetadataFetch.parseClientIdUrl(candidate);
  if (!parsed || parsed.rejected) return 'client:absent';

  return `client:${parsed.url.hostname.toLowerCase()}`;
};

const authorizeAddressLimiter = rateLimit({
  windowMs: AUTHORIZE_WINDOW_MS,
  limit: AUTHORIZE_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  store: newStore(),
  keyGenerator: addressKey,
  message: tooMany('Too many authorization requests from this address.'),
});

const metadataFetchClientLimiter = rateLimit({
  windowMs: METADATA_FETCH_WINDOW_MS,
  limit: METADATA_FETCH_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  store: newStore(),
  keyGenerator: clientKey,
  message: tooMany('Too many authorization requests for this client.'),
});

/** Factory so tests can flood a small-limit twin. Own store per instance. */
const createMcpServiceLimiter = ({
  windowMs = MCP_SERVICE_WINDOW_MS,
  limit = MCP_SERVICE_MAX,
} = {}) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    store: newStore(),
    keyGenerator: addressKey,
    message: tooMany('Too many requests.'),
  });

/** Single instance server.js mounts — do not remount (halves the budget). */
const mcpServiceAddressLimiter = createMcpServiceLimiter();

/**
 * Paths the global limiter skips. Limited only because server.js does
 * `app.use(MCP_SERVICE_PATHS, mcpServiceAddressLimiter)` unconditionally,
 * above the global limiter and the 50mb parsers — not in routes/oauth.js
 * (flag-off would leave skip with no replacement). Next: ticket 34 ingest.
 */
const MCP_SERVICE_PATHS = ['/api/oauth/introspect', '/api/oauth/token'];

const isMcpServicePath = (req) => {
  const path = req.path || '';
  return MCP_SERVICE_PATHS.some((candidate) => path === candidate);
};

/** Test seam only — express-rate-limit keeps counts on the store instance. */
const resetAllForTests = () => {
  stores.forEach((store) => {
    if (typeof store.resetAll === 'function') store.resetAll();
  });
};

module.exports = {
  authorizeAddressLimiter,
  metadataFetchClientLimiter,
  mcpServiceAddressLimiter,
  isMcpServicePath,
  resetAllForTests,
  MCP_SERVICE_PATHS,
  AUTHORIZE_WINDOW_MS,
  AUTHORIZE_MAX,
  METADATA_FETCH_WINDOW_MS,
  METADATA_FETCH_MAX,
  MCP_SERVICE_WINDOW_MS,
  MCP_SERVICE_MAX,
  MAX_CLIENT_ID_LENGTH,
  clientKey,
  createMcpServiceLimiter,
};
