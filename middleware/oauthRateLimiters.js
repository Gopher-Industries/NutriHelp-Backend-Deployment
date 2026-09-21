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
 * MCP data routes share that egress: MCP_DATA_PATHS gets its own bucket, and
 * skipGlobalLimiter skips both.
 *
 * MemoryStore is per process (LEGACY #5): ceiling × instance count. Weakens,
 * does not remove. Mount rules for MCP_SERVICE_PATHS and MCP_DATA_PATHS: see
 * those constants.
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

// Separate bucket, same per-address ceiling as the service one. <= 3 data
// requests per tool call (unbatched ingest `started` + completion, + at most 1
// resource call); the MCP server caps audited calls at 250/15min (launch 200),
// so <= 750 here: that MCP-side cap, not this bucket, is expected to bind.
const MCP_DATA_WINDOW_MS = 15 * 60 * 1000;
const MCP_DATA_MAX = 6000;

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

/** Own store: sharing the service one would let data calls starve introspect/token. */
const createMcpDataLimiter = ({ windowMs = MCP_DATA_WINDOW_MS, limit = MCP_DATA_MAX } = {}) =>
  createMcpServiceLimiter({ windowMs, limit });

const mcpDataAddressLimiter = createMcpDataLimiter();

/**
 * The oauth router's mount path, and the ONE place it is written down.
 * MCP_SERVICE_PATHS and the global body-parser skip both derive from it.
 *
 * WARNING: deriving one string is not the same as comparing it the same way,
 * and the first reads like it gives you the second. Both predicates below were
 * built from this constant and both compared it case-sensitively, which is not
 * how express routes - so an uppercase request matched neither predicate while
 * the router served it anyway. normalisePath is what keeps the parser carve-out
 * and the limiter carve-out from drifting apart ON CASE, which is the axis that
 * was a live bypass. It does NOT make them agree on every spelling express
 * routes: the two predicates still differ in shape, isOauthRouterPath being a
 * prefix test and isMcpServicePath an exact one.
 *
 * The known residue is the trailing slash, measured: POST /api/oauth/token/ is
 * served 200 by the token handler and sits inside the MCP bucket (app.use
 * prefix-matches it), but isMcpServicePath returns false, so it ALSO spends the
 * global budget. Accepted rather than closed here - routes/oauth.js carries the
 * matching no-trailing-slash contract on the MCP client side, and the fail
 * direction is the safe one: such a path is double-limited, never un-limited.
 */
const OAUTH_ROUTER_PREFIX = '/api/oauth';

/**
 * Paths the global limiter skips. Limited only because server.js does
 * `app.use(MCP_SERVICE_PATHS, mcpServiceAddressLimiter)` unconditionally,
 * above the global limiter and the 50mb parsers — not in routes/oauth.js
 * (flag-off would leave skip with no replacement). Ticket 34 ingest is in
 * MCP_DATA_PATHS.
 */
const MCP_SERVICE_PATHS = [`${OAUTH_ROUTER_PREFIX}/introspect`, `${OAUTH_ROUTER_PREFIX}/token`];

/**
 * MCP-only data routes. One egress IP carries every assistant user, so the
 * global 1000/15min would cap the whole population. Same mount rule as
 * MCP_SERVICE_PATHS: server.js, unconditional, above the global limiter and
 * parsers. A path-only carve-out is safe because only the MCP server calls these
 * (mcp_upstream credential only, contract §8.4).
 *
 * The global 50mb parsers skip these paths (isRouteParsedPath), so each route
 * mounts its own small parser; ticket 34's ingest route MUST, or its bodies go
 * unread. /api/mealplan/me joins with ticket 32. Never /api/fooddata/search:
 * the web app calls it too.
 */
const MCP_DATA_PATHS = ['/api/meallog/me', '/api/security-events/mcp'];

/**
 * The meallog router's mount (routes/index.js). Its parser skip covers the WHOLE
 * router: express also serves /api/meallog//me through '/me', a spelling the data
 * bucket does not match, and a global parser reading it would set req._body and
 * make the route's own small parser a no-op.
 */
const MEALLOG_ROUTER_PREFIX = '/api/meallog';

/**
 * Express 4's router is case-INSENSITIVE unless `case sensitive routing` is
 * set, and server.js never sets it (its only app.set is `trust proxy`). So
 * `/API/OAUTH/token` reaches the oauth router exactly like the lowercase form,
 * and a predicate that compares the raw path does not recognise it.
 *
 * That was a live body-size bypass, measured: with a case-sensitive predicate
 * the global 50mb parser consumed `/API/OAUTH/token` and set req._body, the
 * router's own 16kb parser then saw req._body and called next(), and the
 * handler ran on a 40000-byte body that the lowercase spelling answered 413
 * for. It also double-limited uppercase MCP traffic, because the global
 * limiter's skip returned false for exactly the bucket ticket 45 carved out.
 *
 * Deliberately NOT fixed with app.set('case sensitive routing', true): that
 * changes routing for every router mounted in routes/index.js. Normalise here,
 * where the blast radius is these two predicates. OAUTH_ROUTER_PREFIX and every
 * MCP_SERVICE_PATHS entry are lowercase, so the comparison is well defined.
 */
const normalisePath = (req) => (req.path || '').toLowerCase();

const isMcpServicePath = (req) => {
  const path = normalisePath(req);
  return MCP_SERVICE_PATHS.some((candidate) => path === candidate);
};

/**
 * Matches exactly what `app.use(MCP_DATA_PATHS, …)` matches (case-insensitive,
 * the path or anything below it at a segment boundary), so a spelling is skipped
 * iff it is bucketed. isMcpServicePath is exact and double-limits a trailing slash.
 * Being a prefix, a route mounted BELOW a data path (e.g. /api/meallog/me/history)
 * inherits the data bucket; add one only if it is MCP-only too.
 */
const isMcpDataPath = (req) => {
  const path = normalisePath(req);
  return MCP_DATA_PATHS.some((candidate) => path === candidate || path.startsWith(`${candidate}/`));
};

/**
 * The global limiter's skip. Every clause must have a matching unconditional
 * mount above the global limiter, or its paths go unlimited.
 */
const skipGlobalLimiter = (req) => isMcpServicePath(req) || isMcpDataPath(req);

/** Whole router, not just the two service paths — see skipOauthRouter. */
const isOauthRouterPath = (req) => {
  const path = normalisePath(req);
  return path === OAUTH_ROUTER_PREFIX || path.startsWith(`${OAUTH_ROUTER_PREFIX}/`);
};

/** See MEALLOG_ROUTER_PREFIX: whole router, like isOauthRouterPath. */
const isMealLogRouterPath = (req) => {
  const path = normalisePath(req);
  return path === MEALLOG_ROUTER_PREFIX || path.startsWith(`${MEALLOG_ROUTER_PREFIX}/`);
};

/** Bodies only the route's own parser may read. Adding a data path covers it here too. */
const isRouteParsedPath = (req) =>
  isOauthRouterPath(req) || isMcpDataPath(req) || isMealLogRouterPath(req);

/**
 * Ticket 45 — wraps a global body parser so it does NOT consume `/api/oauth`
 * bodies, leaving the router's own 16kb parser as the first to see them.
 *
 * WHY NOT "MOUNT THE ROUTER ABOVE THE PARSERS", which is the obvious fix and
 * the one the ticket text suggests: the global rate limiter sits above the
 * parsers too, and `/authorize` is deliberately UNDER that bucket (server.js
 * says so where the limiter is built). Hoisting the router would silently take
 * `/authorize` out of it — trading a body-size hole for a rate-limit hole.
 * Skipping the parsers moves nothing.
 *
 * SCOPED TO THE WHOLE ROUTER, not to MCP_SERVICE_PATHS. Only `/introspect`
 * and `/token` read a body today, so the narrow version would work — and would
 * silently put the next `/api/oauth` route back on 50mb, because nothing would
 * fail when it was added.
 *
 * Also skips the data paths and the meallog router (isRouteParsedPath): the data
 * bucket admits 6000/15min per address, each otherwise read at 50mb. The name is
 * kept because server.js and the PR #16 tests pin it.
 *
 * Named function expression on purpose: express reports `fn.name` as the layer
 * name, so the composition suite can assert the wrapper is actually mounted.
 */
const skipOauthRouter = (parser) =>
  function skipOauthRouter(req, res, next) {
    if (isRouteParsedPath(req)) return next();
    return parser(req, res, next);
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
  mcpDataAddressLimiter,
  isMcpServicePath,
  isMcpDataPath,
  skipGlobalLimiter,
  isOauthRouterPath,
  isMealLogRouterPath,
  isRouteParsedPath,
  skipOauthRouter,
  resetAllForTests,
  OAUTH_ROUTER_PREFIX,
  MCP_SERVICE_PATHS,
  MCP_DATA_PATHS,
  MEALLOG_ROUTER_PREFIX,
  AUTHORIZE_WINDOW_MS,
  AUTHORIZE_MAX,
  METADATA_FETCH_WINDOW_MS,
  METADATA_FETCH_MAX,
  MCP_SERVICE_WINDOW_MS,
  MCP_SERVICE_MAX,
  MCP_DATA_WINDOW_MS,
  MCP_DATA_MAX,
  MAX_CLIENT_ID_LENGTH,
  clientKey,
  createMcpServiceLimiter,
  createMcpDataLimiter,
};
