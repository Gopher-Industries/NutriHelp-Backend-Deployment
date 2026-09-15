const { rateLimit, ipKeyGenerator, MemoryStore } = require('express-rate-limit');

const safeMetadataFetch = require('../services/oauth/safeMetadataFetch');

/**
 * Ticket 45 — path-specific rate limits for the OAuth routes.
 *
 * WHY THIS IS NOT COVERED BY THE GLOBAL LIMITER
 *
 * server.js's `app.use(limiter)` applies one bucket to the whole API:
 *
 *     windowMs: 15 * 60 * 1000, max: 1000
 *
 * That is 1000 requests per 900 seconds — about 1.1 req/s — keyed per address.
 * It is wrong for OAuth in both directions at once:
 *
 *   TOO LOOSE for authorize. GET /api/oauth/authorize makes this backend fetch
 *   a URL the caller chose, on an anonymous request, from
 *   our single Render egress address. Ticket 41 bounds each such fetch (no
 *   redirects, size cap, one deadline) and deliberately bounds no rate. 1.1 req/s of
 *   attacker-directed outbound fetches is an amplifier, not a limit.
 *
 *   TOO TIGHT for service traffic. The MCP server calls introspect and token
 *   from one address on behalf of every assistant user, so the entire
 *   population arrives looking like a single busy IP. Leaving the global
 *   bucket in front of those paths and enabling OAUTH_ROUTES_ENABLED breaks
 *   live introspection at ~1.1 req/s.
 *
 * TWO BUCKETS, STACKED, NOT ONE COMPOSITE KEY
 *
 * Per address bounds one host spraying many victim URLs. Per assistant bounds
 * many hosts converging on one victim HOST — the key is the client_id's
 * hostname, not the whole URL, or varying the path would mint a fresh bucket
 * per request. A single `address+client` key would fail the same way: it would
 * give an attacker a brand-new bucket for every client_id they invent, which
 * is exactly the value they control.
 *
 * STORE
 *
 * MemoryStore is per process (LEGACY #5). On more than one Render instance
 * each holds its own counts, so the effective ceiling is the number below
 * times the instance count. That weakens the bound; it does not remove it, and
 * these buckets are still mandatory before authorize merges. A shared store is
 * the target wherever Redis is available.
 */

// --- authorize, per address --------------------------------------------------
// In line with the house style in middleware/rateLimiter.js (signupLimiter is
// 10 per 10 minutes) and two orders of magnitude under the global bucket.
// Starting an OAuth connect flow is a rare, deliberate human act.
const AUTHORIZE_WINDOW_MS = 10 * 60 * 1000;
const AUTHORIZE_MAX = 10;

// --- metadata fetch, per assistant ------------------------------------------
// The tightest bucket here, measured per minute: 30 per hour is 0.5/min
// against authorize's 1/min. This is the one that bounds how hard any single
// stranger-chosen URL can be made to absorb our outbound fetches, however many
// addresses the requests arrive from.
//
// It counts REQUESTS THAT MAY COST A FETCH, not fetches. Since the syntactic
// checks moved above the outbound call, a malformed request is refused without
// fetching but has already consumed a slot. That is deliberate — a limiter
// that only counted completed fetches could be driven for free — but the name
// promises more precision than the mechanism has.
//
// ⚠️ AVAILABILITY COST, know it before tuning: the key is the assistant's
// HOSTNAME, so this ceiling is shared by EVERY NutriHelp user connecting that
// assistant. 30/hour means thirty connect-flow starts per hour for all of
// claude.ai combined, not per user — and the 31st gets a JSON 429 rather than
// a deliverable OAuth error, because the bucket sits in front of the handler
// and nothing has proven a redirect_uri yet. Raise it if real usage warrants;
// the per-address bucket is what bounds a single abuser.
const METADATA_FETCH_WINDOW_MS = 60 * 60 * 1000;
const METADATA_FETCH_MAX = 30;

/** Measured after trimming. Longer than any real CIMD URL; see clientKey. */
const MAX_CLIENT_ID_LENGTH = 512;

// --- MCP service traffic -----------------------------------------------------
// Deliberately HIGHER than the global cap. 6000 per 15 minutes is 400/min
// (~6.7 req/s) against the global 66.7/min. Sized from the shape of the
// traffic: one live introspection per tool call, plus an exchange, all from
// one egress address, for the whole assistant population at once.
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
 * ipKeyGenerator takes the ADDRESS, not the request — the v8 signature is
 * ipKeyGenerator(ip, ipv6Subnet). It groups IPv6 into /56 blocks, so a caller
 * with a routed prefix cannot walk one address at a time through the bucket.
 *
 * ⚠️ RESIDUAL, accepted and not fixed in ticket 36: server.js sets
 * `trust proxy: 1`, so req.ip is taken from the last X-Forwarded-For hop. On a
 * platform that appends rather than replaces, a caller can influence it and
 * spread itself across address buckets. That is a pre-existing app-wide
 * setting and changing it affects every limiter and every log line, so it is
 * out of scope here — but authorize makes it worth more than it used to be.
 *
 * It is a weakening, not a bypass: the per-assistant bucket below is keyed on
 * the victim HOSTNAME, which the spoofer does not control, so egress aimed at
 * any one host stays capped at METADATA_FETCH_MAX per window however many
 * addresses the requests claim to come from.
 */
const addressKey = (req) => ipKeyGenerator(req.ip);

/**
 * Keyed on the client_id's HOSTNAME, not the whole URL.
 *
 * The thing being protected is the victim HOST: every authorize request makes
 * this backend issue a real outbound GET to it, and the attacker chooses the
 * entire URL. Keying on the full client_id would give https://victim/a,
 * https://victim/b and https://victim/c three separate METADATA_FETCH_MAX
 * buckets all aimed at one host, and the path is free to vary forever. That is
 * the same objection this file already makes to a composite address+client
 * key, and it applies just as well to the client half on its own.
 *
 * Hostname keying costs legitimate traffic nothing: a real assistant has one
 * fixed client_id URL, so it lands in one bucket either way.
 *
 * Parsed with safeMetadataFetch.parseClientIdUrl — the same parser the fetch
 * itself uses — so this key cannot disagree with what actually gets fetched.
 * Anything that parser refuses shares one bucket rather than skipping the
 * limiter: `skip` on an absent or malformed value is a bypass with extra steps.
 */
const clientKey = (req) => {
  const raw = req.query && req.query.client_id;
  // Trim FIRST, then measure. Checking length against the untrimmed value let
  // 600 leading spaces move a client_id into a different bucket while the
  // fetch went ahead regardless.
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

/**
 * Factory rather than a bare instance so a test can build an identically
 * shaped bucket with a small limit and actually flood it. The real budget is
 * 6000 per window, which no test can exercise directly — and "the mount is
 * wired correctly" is the property worth proving, not the arithmetic.
 *
 * Each instance gets its OWN store. Two mounts sharing one store would halve
 * the effective budget, which is why server.js mounts this exactly once.
 */
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

/** The single instance server.js mounts. Built by the factory above so the
 * flood test and production cannot drift apart. */
const mcpServiceAddressLimiter = createMcpServiceLimiter();

/**
 * Paths the global limiter must step aside for, because they carry service
 * traffic for the whole population from one address.
 *
 * ⚠️ IF YOU ADD AN ENTRY HERE, it is limited only because server.js mounts
 * mcpServiceAddressLimiter ON THIS CONSTANT — `app.use(MCP_SERVICE_PATHS, …)`,
 * at app level, UNCONDITIONALLY, above `app.use(limiter)` and above
 * `express.json`. Do not move that mount into routes/oauth.js: that router is
 * mounted only when OAUTH_ROUTES_ENABLED === 'true', so a bucket there is
 * absent in exactly the deployment where the skip below has already fired, and
 * the path becomes completely unlimited. Do not wrap the mount in the flag for
 * the same reason, and do not mount it twice — two mounts sharing one store
 * halve the budget.
 *
 * NEXT ENTRY, when it exists: `POST /api/security-events/mcp` (ticket 34, audit
 * ingest). It is MCP service traffic from the same single egress address and
 * belongs in this list — it is absent only because the route does not exist
 * yet. Whoever lands ticket 34 adds it HERE, which is what mounts its bucket;
 * adding the route without adding it here leaves it under the global ~1.1
 * req/s, and adding it here without the app-level mount is the unlimited-path
 * trap described above.
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
