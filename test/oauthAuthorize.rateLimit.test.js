// dbConnection.js calls process.exit(1) at require time when these are unset.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const { expect } = require('chai');
const express = require('express');
const request = require('supertest');

const oauthRateLimiters = require('../middleware/oauthRateLimiters');
const { createOauthRouter } = require('../routes/oauth');

/**
 * Ticket 45, authorize side — a MERGE GATE for ticket 36, not a follow-up.
 *
 * GET /api/oauth/authorize makes this backend fetch a URL a stranger chose,
 * from our single Render egress IP. Ticket 41 bounds each individual fetch
 * (no redirects, size cap, one deadline) and deliberately bounds no RATE.
 * These buckets are that missing bound.
 *
 * Two buckets, stacked, because one cannot do the job:
 *   - per address, so one host cannot spray many victim URLs
 *   - per assistant, so many hosts cannot converge on one victim URL
 * A single composite (address+client) key would hand an attacker a fresh
 * bucket for every client_id they invent.
 *
 * Counts are asserted against the limiter's own exported configuration rather
 * than hard-coded twice, so tuning a number cannot silently disarm a test.
 */

const FRONTEND_ORIGIN = 'https://gonutrihelp.vercel.app';
const ISSUER = 'https://nutrihelp-backend.onrender.com';
const RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const CLIENT_ID = 'https://claude.ai/mcp-client';
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const validQuery = (overrides = {}) => ({
  response_type: 'code',
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  resource: RESOURCE,
  scope: 'mealplan:read',
  code_challenge: CHALLENGE,
  code_challenge_method: 'S256',
  ...overrides,
});

const passthroughDb = () => ({
  from: () => ({
    insert: async (rows) => ({ data: rows, error: null }),
    upsert: async (rows) => ({ data: rows, error: null }),
  }),
});

const silentLog = () => ({
  logOperational: async () => undefined,
  logGrantRefusal: async () => undefined,
});

const metadataFor = (clientId) => ({
  client_id: clientId,
  display_name: 'Claude',
  redirect_uris: [REDIRECT_URI],
});

/**
 * Builds the router with REAL limiters unless a test replaces one, which is
 * how each control is proved load-bearing on its own.
 */
const makeApp = ({ limiterOverrides = {} } = {}) => {
  const deps = {
    supabase: passthroughDb(),
    introspectionLog: silentLog(),
    clientMetadataService: {
      fetchAndValidateClientMetadata: async (clientId) => ({
        ok: true,
        metadata: metadataFor(clientId),
      }),
    },
    oauthRateLimiters: { ...oauthRateLimiters, ...limiterOverrides },
  };

  const app = express();
  // A number, not `true`: express-rate-limit refuses a fully permissive
  // trust-proxy setting because it lets a client spoof its own key.
  app.set('trust proxy', 1);
  app.use('/api/oauth', createOauthRouter(deps));
  return app;
};

const get = (app, { ip, query }) =>
  request(app)
    .get('/api/oauth/authorize')
    .set('X-Forwarded-For', ip)
    .query(query || validQuery());

describe('ticket 45 — rate limits on the authorize and metadata-fetch paths', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = {
      OAUTH_FRONTEND_ORIGIN: process.env.OAUTH_FRONTEND_ORIGIN,
      MCP_AS_ISSUER: process.env.MCP_AS_ISSUER,
      MCP_RESOURCE_IDENTIFIER: process.env.MCP_RESOURCE_IDENTIFIER,
    };
    process.env.OAUTH_FRONTEND_ORIGIN = FRONTEND_ORIGIN;
    process.env.MCP_AS_ISSUER = ISSUER;
    process.env.MCP_RESOURCE_IDENTIFIER = RESOURCE;
    oauthRateLimiters.resetAllForTests();
  });

  afterEach(() => {
    Object.entries(savedEnv).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
    oauthRateLimiters.resetAllForTests();
  });

  describe('the buckets are actually tighter than the global limiter', () => {
    it('caps authorize far below the global 1000 per 15 minutes', () => {
      // server.js's global `limiter`, read directly: windowMs 15*60*1000, max 1000.
      const perMinute =
        oauthRateLimiters.AUTHORIZE_MAX / (oauthRateLimiters.AUTHORIZE_WINDOW_MS / 60000);
      const globalPerMinute = 1000 / 15;
      expect(perMinute).to.be.below(globalPerMinute / 10);
    });

    it('makes the metadata-fetch bucket the tightest of the two', () => {
      const authorizePerMinute =
        oauthRateLimiters.AUTHORIZE_MAX / (oauthRateLimiters.AUTHORIZE_WINDOW_MS / 60000);
      const metadataPerMinute =
        oauthRateLimiters.METADATA_FETCH_MAX / (oauthRateLimiters.METADATA_FETCH_WINDOW_MS / 60000);
      expect(metadataPerMinute).to.be.below(authorizePerMinute);
    });

    it('gives MCP service traffic a HIGHER budget than the global cap', () => {
      // The global limiter treats the whole assistant population as one busy
      // IP (~1.1 req/s from one Render egress address). Leaving that in place
      // for introspection breaks live tool calls.
      const servicePerMinute =
        oauthRateLimiters.MCP_SERVICE_MAX / (oauthRateLimiters.MCP_SERVICE_WINDOW_MS / 60000);
      expect(servicePerMinute).to.be.above(1000 / 15);
    });
  });

  describe('per-address bucket', () => {
    it('allows the configured number of authorize requests from one address', async () => {
      const app = makeApp();
      const ip = '203.0.113.10';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        const res = await get(app, { ip });
        expect(res.status, `request ${i + 1} should not be limited`).to.not.equal(429);
      }
    });

    it('refuses the one after that with 429', async () => {
      const app = makeApp();
      const ip = '203.0.113.11';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, { ip });
      }
      const res = await get(app, { ip });

      expect(res.status).to.equal(429);
    });

    it('does not spend one address’s budget on another address', async () => {
      const app = makeApp();

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, { ip: '203.0.113.12' });
      }
      const res = await get(app, { ip: '203.0.113.13' });

      expect(res.status).to.not.equal(429);
    });

    it('still counts a request that varies client_id every time', async () => {
      // Rotating the attacker-chosen client_id must not buy a fresh bucket.
      const app = makeApp();
      const ip = '203.0.113.14';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, {
          ip,
          query: validQuery({ client_id: `https://victim-${i}.example/client` }),
        });
      }
      const res = await get(app, {
        ip,
        query: validQuery({ client_id: 'https://victim-final.example/client' }),
      });

      expect(res.status).to.equal(429);
    });

    it('answers 429 with a JSON body and no redirect', async () => {
      const app = makeApp();
      const ip = '203.0.113.15';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, { ip });
      }
      const res = await get(app, { ip });

      expect(res.status).to.equal(429);
      expect(res.headers.location).to.equal(undefined);
      expect(res.body).to.be.an('object');
    });

    it('sets standard RateLimit headers rather than the legacy ones', async () => {
      const app = makeApp();
      const res = await get(app, { ip: '203.0.113.16' });

      expect(res.headers).to.have.property('ratelimit-policy');
      expect(res.headers).to.not.have.property('x-ratelimit-limit');
    });
  });

  describe('per-assistant bucket on the metadata-fetching path', () => {
    it('caps one client_id even when the requests come from many addresses', async () => {
      const app = makeApp();

      for (let i = 0; i < oauthRateLimiters.METADATA_FETCH_MAX; i += 1) {
        const res = await get(app, { ip: `198.51.100.${i + 1}` });
        expect(res.status, `request ${i + 1} should not be limited`).to.not.equal(429);
      }
      const res = await get(app, { ip: '198.51.100.200' });

      expect(res.status).to.equal(429);
    });

    it('does not spend one client’s budget on another client', async () => {
      const app = makeApp();

      for (let i = 0; i < oauthRateLimiters.METADATA_FETCH_MAX; i += 1) {
        await get(app, {
          ip: `198.51.100.${i + 1}`,
          query: validQuery({ client_id: 'https://victim-a.example/client' }),
        });
      }
      const res = await get(app, {
        ip: '198.51.100.201',
        query: validQuery({ client_id: 'https://victim-b.example/client' }),
      });

      expect(res.status).to.not.equal(429);
    });

    it('counts a missing client_id under one shared key rather than skipping the bucket', async () => {
      const app = makeApp();
      const query = validQuery();
      delete query.client_id;

      for (let i = 0; i < oauthRateLimiters.METADATA_FETCH_MAX; i += 1) {
        await get(app, { ip: `198.51.100.${i + 1}`, query });
      }
      const res = await get(app, { ip: '198.51.100.202', query });

      expect(res.status).to.equal(429);
    });
  });

  describe('the per-assistant bucket keys on the victim HOST', () => {
    it('caps one host even when the attacker varies the path every time', async () => {
      // The amplification target is the host: every one of these produces a
      // real outbound GET to it. Keying on the full client_id would give each
      // path its own budget and bound nothing.
      const app = makeApp();

      for (let i = 0; i < oauthRateLimiters.METADATA_FETCH_MAX; i += 1) {
        const res = await get(app, {
          ip: `198.51.100.${i + 1}`,
          query: validQuery({ client_id: `https://victim.example/client-${i}` }),
        });
        expect(res.status, `request ${i + 1} should not be limited`).to.not.equal(429);
      }
      const res = await get(app, {
        ip: '198.51.100.220',
        query: validQuery({ client_id: 'https://victim.example/client-final' }),
      });

      expect(res.status).to.equal(429);
    });

    it('treats host casing as the same bucket', () => {
      expect(
        oauthRateLimiters.clientKey({ query: { client_id: 'https://Victim.Example/a' } })
      ).to.equal(oauthRateLimiters.clientKey({ query: { client_id: 'https://victim.example/b' } }));
    });

    it('still separates genuinely different hosts', () => {
      expect(
        oauthRateLimiters.clientKey({ query: { client_id: 'https://a.example/c' } })
      ).to.not.equal(oauthRateLimiters.clientKey({ query: { client_id: 'https://b.example/c' } }));
    });

    it('does not let leading whitespace move a client_id into another bucket', () => {
      // The length check runs after trimming; before the fix, padding a
      // client_id past 512 chars with spaces moved it to a different key while
      // the fetch went ahead on the trimmed value regardless.
      const padded = `${' '.repeat(600)}https://victim.example/a`;
      expect(oauthRateLimiters.clientKey({ query: { client_id: padded } })).to.equal(
        oauthRateLimiters.clientKey({ query: { client_id: 'https://victim.example/a' } })
      );
    });

    it('collapses anything the real parser refuses into one shared bucket', () => {
      const shared = oauthRateLimiters.clientKey({ query: {} });
      ['not a url', 'http://victim.example/a', 'https://victim.example/a?x=1', ''].forEach(
        (value) => {
          expect(
            oauthRateLimiters.clientKey({ query: { client_id: value } }),
            `${value} must share the absent bucket, never skip the limiter`
          ).to.equal(shared);
        }
      );
    });
  });

  describe('each control is load-bearing on its own', () => {
    it('without the address bucket, the same flood is not limited', async () => {
      const app = makeApp({
        limiterOverrides: { authorizeAddressLimiter: (req, res, next) => next() },
      });
      const ip = '203.0.113.30';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, { ip });
      }
      const res = await get(app, { ip });

      // Proves the 429 above came from the address bucket and not from some
      // other refusal that happens to share the status code.
      expect(res.status).to.not.equal(429);
    });

    it('without the client bucket, one client_id from many addresses is not limited', async () => {
      const app = makeApp({
        limiterOverrides: { metadataFetchClientLimiter: (req, res, next) => next() },
      });

      for (let i = 0; i < oauthRateLimiters.METADATA_FETCH_MAX; i += 1) {
        await get(app, { ip: `198.51.100.${i + 1}` });
      }
      const res = await get(app, { ip: '198.51.100.210' });

      expect(res.status).to.not.equal(429);
    });

    it('a limited request never reaches the metadata fetch', async () => {
      // The whole point: the outbound fetch must not happen at flood rate.
      let fetches = 0;
      const deps = {
        supabase: passthroughDb(),
        introspectionLog: silentLog(),
        clientMetadataService: {
          fetchAndValidateClientMetadata: async (clientId) => {
            fetches += 1;
            return { ok: true, metadata: metadataFor(clientId) };
          },
        },
        oauthRateLimiters,
      };
      const app = express();
      app.set('trust proxy', 1);
      app.use('/api/oauth', createOauthRouter(deps));

      const ip = '203.0.113.40';
      const attempts = oauthRateLimiters.AUTHORIZE_MAX + 5;
      for (let i = 0; i < attempts; i += 1) {
        await get(app, { ip });
      }

      expect(fetches).to.be.at.most(oauthRateLimiters.AUTHORIZE_MAX);
      expect(fetches).to.be.below(attempts);
    });
  });

  describe('the limiter module itself', () => {
    it('keys addresses through ipKeyGenerator so IPv6 cannot walk the bucket', async () => {
      const app = makeApp();
      // Two addresses in the same /56 must share a bucket; a bare req.ip key
      // would give every address in a routed prefix its own budget.
      const a = '2001:db8:0:1::1';
      const b = '2001:db8:0:1::2';

      for (let i = 0; i < oauthRateLimiters.AUTHORIZE_MAX; i += 1) {
        await get(app, { ip: a });
      }
      const res = await get(app, { ip: b });

      expect(res.status).to.equal(429);
    });

    it('tells the global limiter to step aside for the MCP service paths only', () => {
      // server.js passes this as `skip`. Getting it wrong in the permissive
      // direction silently unlimits a route, so it is asserted per path.
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/introspect' })).to.equal(true);
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/token' })).to.equal(true);
      // The two lines above are the one hand-written statement of the
      // constant's contents, so REMOVING an entry turns them red. This makes
      // an unpinned ADDITION red too — everything else in this file derives
      // from the constant, and a derived-only suite cannot notice a new entry
      // that nobody wired up.
      expect(oauthRateLimiters.MCP_SERVICE_PATHS).to.have.lengthOf(2);
    });

    it('keeps the global limiter in front of authorize', () => {
      // authorize is anonymous and attacker-reachable; it keeps the global
      // bucket AND gains the two tighter ones.
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/authorize' })).to.equal(false);
    });

    it('does not step aside for a path that merely starts the same way', () => {
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/introspect/extra' })).to.equal(
        false
      );
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/tokenizer' })).to.equal(false);
      expect(oauthRateLimiters.isMcpServicePath({ path: '/api/oauth/grants/abc' })).to.equal(false);
      expect(oauthRateLimiters.isMcpServicePath({})).to.equal(false);
    });

    it('exports every bucket the authorize path relies on', () => {
      expect(oauthRateLimiters.authorizeAddressLimiter).to.be.a('function');
      expect(oauthRateLimiters.metadataFetchClientLimiter).to.be.a('function');
      expect(oauthRateLimiters.mcpServiceAddressLimiter).to.be.a('function');
    });
  });
});
