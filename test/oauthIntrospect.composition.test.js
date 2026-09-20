// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Same guard as
// test/authService.oauthExchange.test.js. Must run before any require below
// that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');
const { execFileSync } = require('child_process');
const path = require('path');

const { expect } = require('chai');
const express = require('express');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const responseContractMiddleware = require('../middleware/responseContract');
const oauthRateLimiters = require('../middleware/oauthRateLimiters');
const { createOauthRouter } = require('../routes/oauth');

/**
 * App assembled like server.js (responseContract → global parsers → router).
 * Bare-express endpoint tests miss the composition entirely, which is the whole
 * reason this file exists: BEFORE ticket 45 the router's 16kb urlencoded was a
 * no-op, because server.js had already parsed at 50mb and set req._body. The
 * skip is what makes it real, and these tests fail without it.
 *
 * WARNING: A NON-FORM body still answers 400 here, NOT 413, and that is correct
 * rather than a hole. With the globals skipped and only urlencoded mounted, an
 * application/json body matches no parser, so body-parser calls next() without
 * ever consuming the stream. Measured on a 40MB JSON POST to /token: the
 * pre-ticket-45 shape grew the heap 1358.5 MB (the global json parser buffered,
 * decoded and tried to parse it - roughly 34x the bytes on the wire); this shape
 * grew it 0.2 MB. So the 50mb cap WAS the exposure, and 400-not-413 is the body
 * never being read. Do NOT "fix" this by mounting express.json beside
 * urlencoded: RFC 7662 and RFC 8693 both require
 * application/x-www-form-urlencoded at these endpoints, so JSON is not a valid
 * content type here and 400 is the spec-correct answer. What the 16kb limit
 * does NOT bound is transmission - a client can still send a large body and
 * hold a socket until the 400. That is a slowloris shape, unchanged by this
 * ticket and not what it was scoped to fix.
 *
 * Global per-IP limiter (~1.1 req/s shared MCP egress): SETTLED by ticket 45,
 * in this file — see the "MCP service paths are limited in server.js
 * composition order" describe at the bottom. It used to say the opposite, and
 * to name a standing gate ("settle before OAUTH_ROUTES_ENABLED=true in any
 * deploy") that is now met: the service paths carry their own bucket, mounted
 * unconditionally at app level above both the global limiter and the parsers.
 * That gate is CLOSED — do not re-raise it or hold a deploy on it.
 */

const MCP_ACCESS_TOKEN_ISSUER = 'https://api.nutrihelp.test';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';

const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const asPem = {
  private: asKey.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: asKey.publicKey.export({ type: 'spki', format: 'pem' }),
};

// The MCP server's own private_key_jwt key pair.
const clientKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const clientPem = {
  private: clientKey.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: clientKey.publicKey.export({ type: 'spki', format: 'pem' }),
};

const ACTIVE_GRANT = {
  grant_id: GRANT_ID,
  user_id: 42,
  client_id: ASSISTANT_CLIENT_ID,
  resource: MCP_RESOURCE,
  scopes: ['nutrition:read'],
  status: 'active',
};

const mintAccessToken = () => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: MCP_ACCESS_TOKEN_ISSUER,
      aud: MCP_RESOURCE,
      sub: '42',
      type: 'mcp_access',
      scope: 'nutrition:read',
      client_id: ASSISTANT_CLIENT_ID,
      grant_id: GRANT_ID,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
    },
    asPem.private,
    { algorithm: 'RS256', keyid: 'as-key-1' }
  );
};

/** A genuine private_key_jwt, signed for real — no authentication double. */
const mintClientAssertion = (overrides = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: MCP_CLIENT_ID,
      sub: MCP_CLIENT_ID,
      aud: INTROSPECTION_URL,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 60,
      ...overrides,
    },
    clientPem.private,
    { algorithm: 'RS256' }
  );
};

/** Supabase double serving every table the FULL path touches. */
const makeDb = ({ grant = ACTIVE_GRANT, seenJtis = new Set() } = {}) => ({
  from(table) {
    if (table === 'oauth_clients') {
      return {
        select: () => ({
          eq: () => ({
            maybeSingle: async () => ({
              data: {
                client_id: MCP_CLIENT_ID,
                client_type: 'service_confidential',
                token_endpoint_auth_method: 'private_key_jwt',
                is_active: true,
              },
              error: null,
            }),
          }),
        }),
      };
    }
    if (table === 'oauth_client_keys') {
      const chain = {
        select: () => chain,
        eq: () => chain,
        lte: () => chain,
        gt: () => chain,
        order: () => chain,
        limit: async () => ({
          data: [{ kid: null, alg: 'RS256', public_key_pem: clientPem.public, slot: 1 }],
          error: null,
        }),
      };
      return chain;
    }
    if (table === 'oauth_client_assertion_jti') {
      return {
        insert: async (rows) => {
          const jti = rows[0].jti;
          if (seenJtis.has(jti)) return { error: { code: '23505' } };
          seenJtis.add(jti);
          return { error: null };
        },
        // PostgREST 12: limit only via order.
        delete: () => ({
          lt: () => ({ order: () => ({ limit: async () => ({ error: null }) }) }),
        }),
      };
    }
    if (table === 'mcp_client_grants') {
      return {
        select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: grant, error: null }) }) }),
      };
    }
    throw new Error(`unexpected table: ${table}`);
  },
});

/** Mirrors server.js's ordering for the middleware that touches this route. */
const makeCompositionDeps = (dbOptions = {}) => ({
  supabase: makeDb(dbOptions),
  asVerificationKeys: {
    getVerificationKeys: () => [{ kid: 'as-key-1', alg: 'RS256', publicKeyPem: asPem.public }],
  },
  oauthConfig: {
    mcpAccessTokenIssuer: () => MCP_ACCESS_TOKEN_ISSUER,
    mcpResourceIdentifier: () => MCP_RESOURCE,
    introspectionAudience: () => INTROSPECTION_URL,
  },
  introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
});

/**
 * @param options.skipOauthBodyParsing  false builds the MUTATION TWIN — the
 *   global parsers mounted UNWRAPPED, exactly as server.js had them before
 *   ticket 45. Every 413 case below must answer 200 against that twin; that is
 *   what proves the skip is the thing doing the work rather than some other
 *   layer refusing large bodies for its own reasons.
 */
const makeProductionShapedApp = (dbOptions = {}, { skipOauthBodyParsing = true } = {}) => {
  const deps = makeCompositionDeps(dbOptions);
  const wrap = skipOauthBodyParsing ? oauthRateLimiters.skipOauthRouter : (parser) => parser;

  const app = express();
  app.use(responseContractMiddleware); // server.js: app.use(responseContractMiddleware)
  app.use(wrap(express.json({ limit: '50mb' }))); // server.js: express.json
  app.use(wrap(express.urlencoded({ limit: '50mb', extended: true }))); // server.js: urlencoded

  // Non-oauth route: proves the 50mb parser still applies everywhere else, so
  // the skip stayed scoped and did not become a global limit change.
  app.post('/api/echo', (req, res) => res.json({ fields: Object.keys(req.body || {}).length }));

  app.use('/api/oauth', createOauthRouter(deps)); // server.js: routesRegistrar(app)
  return app;
};

const send = (app, assertion = mintClientAssertion(), token = mintAccessToken()) =>
  request(app)
    .post('/api/oauth/introspect')
    .type('form')
    .set('x-correlation-id', crypto.randomUUID())
    .send({
      token,
      token_type_hint: 'access_token',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    });

describe('activation flag — the endpoint is dark unless explicitly enabled (ticket 56)', () => {
  // routes/index.js is the real registrar; these drive it directly so the
  // gate is tested where it lives rather than being reasoned about.
  /**
   * Driven in a CHILD NODE PROCESS against the real routes/index.js.
   *
   * Requiring the registrar in-process fails under jest — some transitive
   * route dependency is ESM that jest's transform will not parse — while plain
   * node loads it fine. Rather than test a copy of the three-line gate, or
   * assert on the source text, this runs the actual registrar the way the
   * server does and reads back which layers it mounted.
   *
   * One spawn covers every value: the registrar reads the flag when it is
   * CALLED, not when it is required, so a single child can register several
   * apps under different settings. (In-process cache-busting per value took 22
   * seconds a call, because it re-required every route module in the app.)
   *
   * Detection is on the layer's own pattern SOURCE, not by testing a path
   * against it: `app.use(fn)` with no path compiles to a regexp matching
   * everything, so `layer.regexp.test('/api/oauth')` is true for every
   * path-less middleware and reported the route as mounted even when it was
   * not — a detector that could not return false.
   */
  const probeFlagValues = () => {
    const script = `
      const express = require('express');
      const register = require('./routes');
      const check = (v) => {
        if (v === null) delete process.env.OAUTH_ROUTES_ENABLED;
        else process.env.OAUTH_ROUTES_ENABLED = v;
        const app = express();
        register(app);
        return app._router.stack.some((l) => l.regexp && /oauth/i.test(l.regexp.source));
      };
      const values = [null, 'false', '1', 'TRUE', 'yes', '', 'true'];
      process.stdout.write('__RESULT__' + JSON.stringify(values.map((v) => [v, check(v)])));
    `;
    const out = execFileSync(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      encoding: 'utf8',
      env: {
        ...process.env,
        SUPABASE_URL: 'https://example.supabase.co',
        SUPABASE_ANON_KEY: 'anon-key',
        SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
      },
    });
    // The registrar's own modules print to stdout on load, so the payload is
    // marked rather than assumed to be the whole output.
    return new Map(JSON.parse(out.slice(out.lastIndexOf('__RESULT__') + '__RESULT__'.length)));
  };

  // Memoised rather than run in a hook: `before` is mocha's and `beforeAll` is
  // jest's, and these files are globbed by both runners. A lazy getter needs
  // neither and spawns exactly once.
  let cached = null;
  const mounted = () => {
    if (!cached) cached = probeFlagValues();
    return cached;
  };

  it('does not mount the OAuth routes when the flag is unset', () => {
    expect(mounted().get(null)).to.equal(false);
  });

  it('does not mount them for any value other than the exact string "true"', () => {
    // An unset or misspelled variable must leave the endpoint dark, so the
    // gate tests for the enabling value rather than for the absence of a
    // disabling one. 'false', '1', 'TRUE' and 'yes' all mean off.
    for (const value of ['false', '1', 'TRUE', 'yes', '']) {
      expect(mounted().get(value), `value ${JSON.stringify(value)}`).to.equal(false);
    }
  });

  it('mounts them when the flag is exactly "true"', () => {
    expect(mounted().get('true')).to.equal(true);
  });
});

describe('POST /api/oauth/introspect — assembled as server.js assembles it', () => {
  describe('end to end with a genuine client assertion (nothing doubled but the database)', () => {
    it('authenticates a real private_key_jwt and returns the active answer', async () => {
      const response = await send(makeProductionShapedApp());

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
      expect(response.body.grant_id).to.equal(GRANT_ID);
      expect(response.body.sub).to.equal('42');
      expect(response.body.client_id).to.equal(ASSISTANT_CLIENT_ID);
      expect(response.body.scope).to.equal('nutrition:read');
    });

    it('returns 200 active:false for a revoked grant through the full stack', async () => {
      const app = makeProductionShapedApp({ grant: { ...ACTIVE_GRANT, status: 'revoked' } });

      const response = await send(app);

      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });

    it('rejects a replayed assertion with 401 on the second use of one jti', async () => {
      const app = makeProductionShapedApp();
      const assertion = mintClientAssertion();

      const first = await send(app, assertion);
      const second = await send(app, assertion);

      expect(first.status).to.equal(200);
      expect(second.status).to.equal(401);
      expect(second.body).to.not.have.property('active');
    });

    it('rejects an assertion minted for a sibling endpoint with 401', async () => {
      const wrongAudience = mintClientAssertion({
        aud: 'https://api.nutrihelp.test/api/oauth/token',
      });

      const response = await send(makeProductionShapedApp(), wrongAudience);

      expect(response.status).to.equal(401);
    });
  });

  describe('what the bare-express harness could not see', () => {
    // REWRITTEN BY TICKET 45, NOT ADDED TO. These two used to PIN the
    // no-op: one asserted the global parser preceded the router in the stack,
    // the other POSTed 40 KB and required 200, "proving that limit is not in
    // force". The fix inverts both, so leaving them in place would have left
    // the suite red and looking like a regression.

    it('mounts BOTH wrapped parsers above the oauth router layer', () => {
      // Both global parsers are wrapped, and both sit above the router — if
      // either dropped below it, the router's 16kb parser would run first, set
      // req._body, and the global parser would be the no-op instead. The skip
      // only means anything from above.
      //
      // WARNING: compare against the ROUTER's index, and take lastIndexOf.
      // The predecessor of this case read
      //   indexOf('skipOauthRouter') < layerNames.length - 1
      // which is arithmetically incapable of failing once there are two
      // wrappers: indexOf finds the FIRST, so it is at most length - 2 in
      // every possible stack. It COULD fail when there was one parser layer
      // and "is it last?" was a real question; adding the second wrapper
      // retired it silently, which is the shape this file keeps finding.
      const app = makeProductionShapedApp();
      const layerNames = app._router.stack.map((l) => l.name);

      expect(layerNames.filter((name) => name === 'skipOauthRouter')).to.have.lengthOf(2);

      // express.Router() is a function named `router`; the mounted oauth
      // router is the only one in this app. Asserting there is exactly one
      // keeps the index below unambiguous.
      const routerLayerNames = layerNames.filter((name) => name === 'router');
      expect(routerLayerNames, 'exactly one mounted router layer').to.have.lengthOf(1);

      expect(layerNames.lastIndexOf('skipOauthRouter')).to.be.below(
        layerNames.indexOf('router'),
        'both wrapped global parsers must precede the oauth router'
      );
    });

    it('refuses a body larger than the router 16kb limit with 413', async () => {
      // ~40 KB of padding: over the router's 16 KB, under the global 50mb.
      const app = makeProductionShapedApp();

      const response = await request(app)
        .post('/api/oauth/introspect')
        .type('form')
        .send({
          token: mintAccessToken(),
          token_type_hint: 'access_token',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: mintClientAssertion(),
          padding: 'x'.repeat(40000),
        });

      expect(response.status).to.equal(413);
    });

    it('refuses a 17kb body on /introspect', async () => {
      const response = await request(makeProductionShapedApp())
        .post('/api/oauth/introspect')
        .type('form')
        .send({ token: 'x', padding: 'y'.repeat(17 * 1024) });

      expect(response.status).to.equal(413);
    });

    it('refuses a 17kb body on /token', async () => {
      const response = await request(makeProductionShapedApp())
        .post('/api/oauth/token')
        .type('form')
        .send({ grant_type: 'refresh_token', padding: 'y'.repeat(17 * 1024) });

      expect(response.status).to.equal(413);
    });

    it('still accepts an ordinary body — the 413 cases are not vacuous', async () => {
      // Without this, every 413 above is satisfied by a route that refuses
      // everything, including a correctly sized request.
      const response = await send(makeProductionShapedApp());

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
    });

    it('accepts the same oversized bodies when the parsers are NOT skipped', async () => {
      // The mutation twin. server.js's pre-ticket-45 shape: unwrapped global
      // parsers. If this ever answers 413, something other than the skip is
      // refusing these bodies and the tests above prove nothing.
      const twin = makeProductionShapedApp({}, { skipOauthBodyParsing: false });

      const introspect = await request(twin)
        .post('/api/oauth/introspect')
        .type('form')
        .send({
          token: mintAccessToken(),
          token_type_hint: 'access_token',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: mintClientAssertion(),
          padding: 'x'.repeat(40000),
        });

      expect(introspect.status).to.equal(200);
      expect(introspect.body.active).to.equal(true);

      // /token too. Three 413 cases exist and the promise above is universal;
      // covering only /introspect left it standing on a third of its cases.
      //
      // PIN THE OUTCOME, not merely "not 413". A bare not-413 is satisfied by
      // a 400, a 500 or an unhandled throw, so it proves the request was not
      // refused for its SIZE without proving the oversized body was ever read.
      //
      // 200 is not available here: makeCompositionDeps serves only the tables
      // introspection touches, so a real exchange hits `unexpected table`,
      // and the controller answers 503 server_error — a status that says
      // nothing about whether the body was parsed. So drive the one thing the
      // controller dispatches on. An UNKNOWN grant_type answers 400
      // unsupported_grant_type; an absent or unparsed one answers 400
      // invalid_request. The two are distinguishable, which makes
      // unsupported_grant_type POSITIVE evidence that the 40 KB body was
      // parsed and its fields reached the handler.
      const token = await request(twin)
        .post('/api/oauth/token')
        .type('form')
        .send({
          grant_type: 'urn:nutrihelp:test:not-a-real-grant',
          padding: 'x'.repeat(40000),
        });

      expect(
        token.status,
        'the oversized /token body is NOT refused for its size once the parsers are unskipped'
      ).to.equal(400);
      expect(
        token.body.error,
        'the handler read grant_type OUT of the oversized body — an unread body answers invalid_request'
      ).to.equal('unsupported_grant_type');
    });

    it('wraps BOTH global parsers in the oauth skip in server.js itself', () => {
      // WITHOUT THIS, EVERY 413 TEST ABOVE IS UNFALSIFIABLE. They run
      // against makeProductionShapedApp, which is hand-assembled and uses the
      // wrapper because THIS FILE says to. Deleting the wrap from server.js
      // leaves all of them green while production goes straight back to
      // accepting 50mb from anonymous callers. Measured: that mutation was
      // silent until this assertion existed.
      //
      // Middleware composition is a source-order property and cannot be
      // observed at runtime without booting the listener, so it is asserted
      // against the source — the same approach the service-bucket test below
      // already takes.
      //
      // WARNING: strip comments first and anchor on `app.use(`. Asserting the
      // bare wrapper substring against the raw source was satisfied by a
      // COMMENTED-OUT line — which is the ordinary way someone disables
      // middleware while debugging — so the guard survived the exact mutation
      // it exists to catch, and production went back to 50mb. Same
      // comment-stripping pair the two source tests below already use.
      const source = require('fs').readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
      const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

      expect(code).to.contain(
        "app.use(oauthRateLimiters.skipOauthRouter(express.json({ limit: '50mb' })))"
      );
      expect(code).to.contain(
        "app.use(oauthRateLimiters.skipOauthRouter(express.urlencoded({ limit: '50mb', extended: true })))"
      );
    });

    it('skips the WHOLE oauth prefix, not only the two service paths', () => {
      // Narrowing the skip to MCP_SERVICE_PATHS works today and would put the
      // NEXT /api/oauth route back on 50mb silently. No request-level test can
      // catch that, because the route does not exist yet.
      const { isOauthRouterPath } = oauthRateLimiters;

      expect(isOauthRouterPath({ path: '/api/oauth/introspect' })).to.equal(true);
      expect(isOauthRouterPath({ path: '/api/oauth/token' })).to.equal(true);
      expect(isOauthRouterPath({ path: '/api/oauth/authorize' })).to.equal(true);
      expect(isOauthRouterPath({ path: '/api/oauth/a-route-that-does-not-exist-yet' })).to.equal(
        true
      );

      expect(isOauthRouterPath({ path: '/api/oauthx/token' })).to.equal(false);
      expect(isOauthRouterPath({ path: '/api/meals' })).to.equal(false);
    });

    it('matches the prefix the way express routes it — case-INSENSITIVELY', () => {
      // Express 4 routes case-insensitively unless `case sensitive routing`
      // is set, and server.js never sets it. A case-SENSITIVE predicate
      // therefore steps aside for a spelling the router still serves.
      //
      // Both predicates, in one case, because they are the same bug: the
      // parser carve-out is a body-size bypass, and the limiter carve-out
      // double-limits uppercase MCP traffic under the global bucket that
      // ticket 45 carved it out of.
      const { isOauthRouterPath, isMcpServicePath } = oauthRateLimiters;

      for (const spelling of ['/API/OAUTH/token', '/Api/OAuth/Token', '/api/OAUTH/introspect']) {
        expect(isOauthRouterPath({ path: spelling }), spelling).to.equal(true);
        expect(isMcpServicePath({ path: spelling }), spelling).to.equal(true);
      }

      // Still scoped: case-folding must not widen the prefix itself.
      expect(isOauthRouterPath({ path: '/API/OAUTHX/token' })).to.equal(false);
      expect(isMcpServicePath({ path: '/API/OAUTH/authorize' })).to.equal(false);
    });

    it('refuses a 17kb body on an UPPERCASE oauth path with 413', async () => {
      // THE CASE THAT PINS THE PREDICATE TO EXPRESS RATHER THAN TO THE
      // CONSTANT. The prefix test above feeds it lowercase literals only,
      // which is exactly how a case-sensitive predicate shipped: it agreed
      // with every string the test handed it and disagreed with the router.
      //
      // Measured before the fix, on this app shape: /api/oauth/token answered
      // 413 while /API/OAUTH/token answered 200 on a 40000-byte body. The
      // global 50mb parser consumed it, set req._body, and the router's 16kb
      // parser called next() on sight of req._body.
      const app = makeProductionShapedApp();

      const oversized = await request(app)
        .post('/API/OAUTH/token')
        .type('form')
        .send({ grant_type: 'refresh_token', padding: 'y'.repeat(17 * 1024) });

      expect(oversized.status).to.equal(413);

      // Not vacuous: the uppercase spelling really is routed and served, so
      // the 413 above is the size limit rather than the path 404ing.
      const ordinary = await request(app)
        .post('/API/OAUTH/introspect')
        .type('form')
        .set('x-correlation-id', crypto.randomUUID())
        .send({
          token: mintAccessToken(),
          token_type_hint: 'access_token',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: mintClientAssertion(),
        });

      expect(ordinary.status).to.equal(200);
      expect(ordinary.body.active).to.equal(true);
    });

    it('still parses a body far over 16kb on a non-oauth route', async () => {
      // The skip is a carve-out, not a new global ceiling.
      const response = await request(makeProductionShapedApp())
        .post('/api/echo')
        .type('form')
        .send({ padding: 'z'.repeat(2 * 1024 * 1024) });

      expect(response.status).to.equal(200);
      expect(response.body.fields).to.equal(1);
    });

    it('responseContract does not append _contractWarnings to an RFC 7662 body', async () => {
      // OAuth bodies are specified byte for byte and are read by non-browser
      // clients that treat an unexpected member as malformed.
      const response = await send(makeProductionShapedApp());

      expect(response.body).to.not.have.property('_contractWarnings');
      expect(response.body).to.not.have.property('success');
      expect(Object.keys(response.body)).to.have.members([
        'active',
        'grant_id',
        'sub',
        'client_id',
        'scope',
        'aud',
        'iss',
        'exp',
        'iat',
        'jti',
      ]);
    });

    it('still sets Cache-Control: no-store through the full middleware stack', async () => {
      const response = await send(makeProductionShapedApp());

      expect(response.headers['cache-control']).to.equal('no-store');
    });
  });

  describe('an unexpected throw answers 503 rather than hanging the socket', () => {
    /**
     * ⚠️ THE THROW SITE IS THE TEST, and picking the wrong one makes this pass
     * for the wrong reason. Throwing from the grant lookup proves nothing:
     * introspectionService already wraps that in try/catch and returns
     * `unavailable`, so the 503 comes from ordinary handling and the
     * controller's catch is never entered — a mutation deleting that catch
     * left the suite green.
     *
     * `getVerificationKeys()` is called synchronously by verifyMcpAccessToken,
     * which introspectionService calls OUTSIDE any try. A throw there escapes
     * all the way to the controller, which is the only thing standing between
     * it and a held socket: Express 4 does not route a rejected promise to the
     * error handler, so without the catch there is NO RESPONSE AT ALL — the
     * caller burns its deadline and reports a timeout for something that never
     * timed out.
     */
    const makeAppWithThrowingKeySource = () => {
      const deps = {
        supabase: makeDb(),
        asVerificationKeys: {
          getVerificationKeys: () => {
            throw new TypeError('key source exploded');
          },
        },
        oauthConfig: {
          mcpAccessTokenIssuer: () => MCP_ACCESS_TOKEN_ISSUER,
          mcpResourceIdentifier: () => MCP_RESOURCE,
          introspectionAudience: () => INTROSPECTION_URL,
        },
        introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
      };
      const a = express();
      a.use(express.urlencoded({ limit: '50mb', extended: true }));
      a.use('/api/oauth', createOauthRouter(deps));
      return a;
    };

    it('answers 503 when a collaborator throws outside every inner try', async () => {
      const response = await send(makeAppWithThrowingKeySource());

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
      expect(response.headers['cache-control']).to.equal('no-store');
    });

    it('logs the unexpected throw operationally, carrying only the error name', async () => {
      const seen = [];
      const deps = {
        supabase: makeDb(),
        asVerificationKeys: {
          getVerificationKeys: () => {
            throw new TypeError('key source exploded with a secret: hunter2');
          },
        },
        oauthConfig: {
          mcpAccessTokenIssuer: () => MCP_ACCESS_TOKEN_ISSUER,
          mcpResourceIdentifier: () => MCP_RESOURCE,
          introspectionAudience: () => INTROSPECTION_URL,
        },
        introspectionLog: {
          logOperational: async (ctx) => seen.push(ctx),
          logGrantRefusal: async () => {},
        },
      };
      const app = express();
      app.use(express.urlencoded({ limit: '50mb', extended: true }));
      app.use('/api/oauth', createOauthRouter(deps));

      await send(app);

      const unhandled = seen.filter((s) => s.outcome === 'unhandled_exception');
      expect(unhandled).to.have.lengthOf(1);
      expect(unhandled[0].detail).to.equal('TypeError');
      // The message can carry caller-influenced content; only the name travels.
      expect(JSON.stringify(seen)).to.not.contain('hunter2');
    });
  });
});

/**
 * Ticket 45 — the global limiter's `skip` and its replacement, assembled in
 * server.js's real order.
 *
 * The header at the top of this file used to say the global limiter was "NOT
 * fixed here — owned by ticket 45. Settle before OAUTH_ROUTES_ENABLED=true in
 * any deploy." This is that settlement, tested where that note lives.
 *
 * The bug these cases exist to catch: server.js's `skip` is unconditional,
 * but routes/index.js mounts the oauth router only when OAUTH_ROUTES_ENABLED
 * === 'true'. Put the replacement bucket inside the router and, with the flag
 * off, the global limiter steps aside for something that never mounts and the
 * MCP service paths become completely unlimited. So the mount must be at app
 * level, unconditional, and above the 50mb parsers.
 */
describe('ticket 45 — the MCP service paths are limited in server.js composition order', () => {
  const { rateLimit, ipKeyGenerator, MemoryStore } = require('express-rate-limit');
  const oauthRateLimiters = require('../middleware/oauthRateLimiters');

  const FLOOD_LIMIT = 3;

  /**
   * Assembled exactly as server.js does, including the two things that make
   * this bug possible: the unconditional skip, and the 50mb parsers sitting
   * BELOW the limiters.
   *
   * @param routerMounted  false models OAUTH_ROUTES_ENABLED !== 'true'
   */
  const makeServerOrderApp = ({
    routerMounted,
    serviceLimiter,
    globalLimit = 1000,
    // Models the DEFECT: mount the service bucket below the parsers instead of
    // above them. The ordering case below runs both arms, because a case that
    // cannot fail in the broken arm is not evidence of anything.
    serviceLimiterBelowParsers = false,
  }) => {
    const app = express();
    app.set('trust proxy', 1);
    const probe = { parserRan: false };

    // server.js: app.use(MCP_SERVICE_PATHS, mcpServiceAddressLimiter)
    if (!serviceLimiterBelowParsers) {
      app.use(oauthRateLimiters.MCP_SERVICE_PATHS, serviceLimiter);
    }

    // server.js: the global limiter, with its unconditional skip.
    app.use(
      rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: globalLimit,
        standardHeaders: true,
        legacyHeaders: false,
        store: new MemoryStore(),
        keyGenerator: (req) => ipKeyGenerator(req.ip),
        skip: oauthRateLimiters.isMcpServicePath,
      })
    );

    // server.js: app.use(express.json({ limit: '50mb' })) and the urlencoded
    // sibling, BELOW the limiters — that ordering is the point. Wrapped so a
    // test can assert the parser never ran, rather than inferring it from a
    // status code both arms produce.
    const json50 = express.json({ limit: '50mb' });
    const urlencoded50 = express.urlencoded({ limit: '50mb', extended: true });
    app.use((req, res, next) => {
      probe.parserRan = true;
      json50(req, res, next);
    });
    app.use(urlencoded50);

    if (serviceLimiterBelowParsers) {
      app.use(oauthRateLimiters.MCP_SERVICE_PATHS, serviceLimiter);
    }

    if (routerMounted) app.use('/api/oauth', createOauthRouter(makeCompositionDeps()));
    app.probe = probe;
    return app;
  };

  const flood = async (app, path, times, ip) => {
    let last;
    for (let i = 0; i < times; i += 1) {
      last = await request(app).post(path).type('form').set('X-Forwarded-For', ip).send({});
    }
    return last;
  };

  // Derived from the constant, never a second hand-maintained list: adding an
  // entry to MCP_SERVICE_PATHS without mounting it fails here.
  oauthRateLimiters.MCP_SERVICE_PATHS.forEach((servicePath) => {
    it(`refuses a flood on ${servicePath} with the router MOUNTED`, async () => {
      const app = makeServerOrderApp({
        routerMounted: true,
        serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      });

      const res = await flood(app, servicePath, FLOOD_LIMIT + 1, '203.0.113.90');

      expect(res.status).to.equal(429);
    });

    it(`refuses a flood on ${servicePath} with the router NOT mounted (flag off)`, async () => {
      // This is the case the router-level mount could not cover: with the flag
      // off the request 404s, but it must be counted and refused on the way
      // there rather than running cors/helmet/parsers unlimited.
      const app = makeServerOrderApp({
        routerMounted: false,
        serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      });

      const before = await flood(app, servicePath, FLOOD_LIMIT, '203.0.113.91');
      expect(before.status).to.equal(404);

      const res = await request(app)
        .post(servicePath)
        .type('form')
        .set('X-Forwarded-For', '203.0.113.91')
        .send({});

      expect(res.status).to.equal(429);
    });

    it(`counts ${servicePath} against the REAL bucket, not just a test one`, async () => {
      // The flood cases above use a small-limit instance. This one proves the
      // instance server.js actually mounts is engaged on this path.
      const app = makeServerOrderApp({
        routerMounted: false,
        serviceLimiter: oauthRateLimiters.mcpServiceAddressLimiter,
      });

      const res = await request(app)
        .post(servicePath)
        .type('form')
        .set('X-Forwarded-For', '203.0.113.92')
        .send({});

      expect(res.headers['ratelimit-limit']).to.equal(String(oauthRateLimiters.MCP_SERVICE_MAX));
    });
  });

  it('refuses the flood BEFORE the 50mb body parser reads the request', async () => {
    // Ordering, not just presence: a limiter below the parsers accepts an
    // unbounded body and only then answers 429.
    const app = makeServerOrderApp({
      routerMounted: true,
      serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
    });
    const ip = '203.0.113.93';

    await flood(app, '/api/oauth/introspect', FLOOD_LIMIT, ip);

    // Assert the PARSER NEVER RAN, not the status code. 200 kB is far under
    // the 50mb cap, so a limiter mounted BELOW the parsers answers 429 too —
    // the status is identical in both arms and separates nothing. Only "the
    // body was never read" distinguishes them.
    app.probe.parserRan = false;
    const res = await request(app)
      .post('/api/oauth/introspect')
      .type('form')
      .set('X-Forwarded-For', ip)
      .send({ token: 'x'.repeat(200000) });

    expect(res.status).to.equal(429);
    expect(app.probe.parserRan, 'the 429 must be answered above the body parser').to.equal(false);
  });

  it('and the same case goes red when the bucket is moved below the parsers', async () => {
    // The defective arm, run explicitly. Without it, parserRan === false could
    // be true for some reason unrelated to mount position and the case above
    // would be another proof that cannot fail — which is the exact defect this
    // round of review found in its predecessor.
    const app = makeServerOrderApp({
      routerMounted: true,
      serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      serviceLimiterBelowParsers: true,
    });
    const ip = '203.0.113.94';

    await flood(app, '/api/oauth/introspect', FLOOD_LIMIT, ip);

    app.probe.parserRan = false;
    const res = await request(app)
      .post('/api/oauth/introspect')
      .type('form')
      .set('X-Forwarded-For', ip)
      .send({ token: 'x'.repeat(200000) });

    // Identical status — which is precisely why asserting on it proved nothing.
    expect(res.status).to.equal(429);
    // Different in the only way that matters: the body was read first.
    expect(app.probe.parserRan, 'the defective arm must read the body').to.equal(true);
  });

  it('mounts the service bucket in server.js above the global limiter, the parsers AND the routes', () => {
    // Every case above assembles its own app, so they prove the SHAPE of the fix and not
    // that server.js uses it. Middleware order is a source-order property, so it is asserted
    // against the source; comments are stripped first and every anchor carries its `app.use(`,
    // because a commented-out mount would otherwise satisfy a bare anchor.
    //
    // THE ROUTER ANCHOR IS WHY THIS PINS PRODUCTION RATHER THAN A FIXTURE. Until it existed,
    // `routesRegistrar` appeared in this file once, in a comment - so the mount could be hoisted
    // above the global limiter with every gate green, pulling /authorize out of that bucket.
    const source = require('fs').readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

    const mount = code.indexOf('app.use(oauthRateLimiters.MCP_SERVICE_PATHS');
    const globalLimiter = code.indexOf('app.use(limiter)');
    const jsonParser = code.indexOf(
      "app.use(oauthRateLimiters.skipOauthRouter(express.json({ limit: '50mb' })))"
    );
    const urlencodedParser = code.indexOf(
      "app.use(oauthRateLimiters.skipOauthRouter(express.urlencoded({ limit: '50mb', extended: true })))"
    );
    // The call, not the require: `const routesRegistrar = require('./routes')`
    // is a different line and pinning it would pin nothing about order.
    const routesMounted = code.indexOf('routesRegistrar(app)');

    // The predicates normalise case because express matches mounts case-insensitively by
    // DEFAULT. Setting `case sensitive routing` inverts the pair: the skip still fires on
    // /API/OAUTH/token while the mounts no longer match it, so the path is skipped from the
    // global limiter AND absent from the MCP bucket - unlimited, then 404. Measured.
    // The uppercase flood case cannot catch this: it assembles its own app, so a flag set
    // HERE leaves it green. Same reason the router anchor above exists.
    expect(
      code,
      'server.js must not set `case sensitive routing` - it would leave uppercase oauth paths unlimited'
    ).to.not.match(/app\.set\(\s*['"`]case sensitive routing['"`]/);

    expect(mount, 'server.js must mount the MCP service bucket at app level').to.be.greaterThan(-1);
    expect(globalLimiter).to.be.greaterThan(-1);
    expect(jsonParser).to.be.greaterThan(-1);
    expect(urlencodedParser).to.be.greaterThan(-1);
    // Asserted so a rename cannot turn every ordering check below into -1 < n.
    expect(routesMounted, 'server.js must register the routers via routesRegistrar(app)').to.be.greaterThan(-1);

    // Above the global limiter, or the skip fires with no replacement.
    expect(mount).to.be.lessThan(globalLimiter);
    // Above the parsers, or a flood is body-parsed at 50mb before the 429.
    expect(mount).to.be.lessThan(jsonParser);

    // The router stays BELOW both: above the limiter takes /authorize out of its bucket;
    // above the parsers makes the skip a no-op, the router's 16kb parser seeing the body first.
    expect(globalLimiter, 'the global limiter must precede routesRegistrar(app)').to.be.lessThan(
      routesMounted
    );
    expect(jsonParser, 'the wrapped json parser must precede routesRegistrar(app)').to.be.lessThan(
      routesMounted
    );
    expect(
      urlencodedParser,
      'the wrapped urlencoded parser must precede routesRegistrar(app)'
    ).to.be.lessThan(routesMounted);
  });

  it('never conditions the MCP service mount on the route flag', () => {
    // POSITION is what the indexes above pin. C1's root cause was
    // CONDITIONALITY, and all three of those assertions still hold if someone
    // wraps the mount in `if (process.env.OAUTH_ROUTES_ENABLED === 'true')`,
    // which reintroduces the original bug exactly. The flag-off composition
    // cases cannot catch it either — they build their own app and are handed
    // the limiter directly.
    //
    // Comments are stripped first: server.js legitimately discusses the flag
    // in prose, and a test that forbids naming a thing forbids documenting it.
    const source = require('fs').readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

    expect(code, 'the MCP service mount must not be conditioned on the route flag').to.not.contain(
      'OAUTH_ROUTES_ENABLED'
    );
  });

  it('does not put the service bucket back inside the router', () => {
    // Two mounts sharing one store halve the 6000 budget to 3000, and a
    // router-level mount is invisible whenever OAUTH_ROUTES_ENABLED is off.
    //
    // Matches the BARE NAME after stripping comments, not a USE form. Guarding
    // `limiters.mcpServiceAddressLimiter` alone missed three spellings,
    // including `defaultOauthRateLimiters.mcpServiceAddressLimiter` — which is
    // the name routes/oauth.js already binds the module to, so it is the one
    // anyone adding a mount there would reach for first.
    //
    // Comment-stripping is what lets this be strict: the file documents why
    // the limiter is deliberately absent, and a test that forbids naming a
    // thing would forbid documenting it.
    const source = require('fs').readFileSync(
      path.join(__dirname, '..', 'routes', 'oauth.js'),
      'utf8'
    );
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

    expect(code, 'the service bucket must not be re-mounted in the router').to.not.contain(
      'mcpServiceAddressLimiter'
    );
  });

  it('still applies the GLOBAL bucket to a non-service oauth path', async () => {
    // Exercised, not asserted on the predicate. The claim is that /authorize
    // stays INSIDE the global bucket — so flood it through the real
    // composition with the global limit parameterised down, and watch the
    // global bucket answer. The predicate returning false is the mechanism;
    // the 429 is the property.
    const app = makeServerOrderApp({
      routerMounted: false,
      serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      globalLimit: FLOOD_LIMIT,
    });
    const ip = '203.0.113.95';

    for (let i = 0; i < FLOOD_LIMIT; i += 1) {
      const res = await request(app).get('/api/oauth/authorize').set('X-Forwarded-For', ip);
      expect(res.status, `request ${i + 1} should not be limited`).to.not.equal(429);
    }
    const res = await request(app).get('/api/oauth/authorize').set('X-Forwarded-For', ip);

    expect(res.status).to.equal(429);
  });

  it('does not spend the global budget on a path that IS skipped', async () => {
    // The other half of the same claim: a skipped path must not consume the
    // global bucket, or heavy MCP traffic would exhaust it for everyone else.
    const app = makeServerOrderApp({
      routerMounted: false,
      serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: 10000 }),
      globalLimit: FLOOD_LIMIT,
    });
    const ip = '203.0.113.96';

    for (let i = 0; i < FLOOD_LIMIT * 3; i += 1) {
      await request(app).post('/api/oauth/introspect').set('X-Forwarded-For', ip).send({});
    }
    const res = await request(app).get('/api/oauth/authorize').set('X-Forwarded-For', ip);

    expect(res.status).to.not.equal(429);
  });

  it('buckets an UPPERCASE service path the way express mounts it, and still skips it', async () => {
    // THE CASE THAT PINS THE LIMITER HALF TO EXPRESS RATHER THAN TO LITERALS.
    // Lowercasing isMcpServicePath is only SAFE because `app.use(pathArray, mw)`
    // matches case-insensitively. Nothing else asserted that: the predicate case
    // above hands literals to the predicate, which is the same shape as this
    // ticket's original mutation failure — a control pinned by what the test
    // invents rather than by the framework's behaviour.
    //
    // If app.use ever stops matching case-insensitively — and the middleware's
    // own comment names `app.set('case sensitive routing', true)` as the
    // alternative someone might reach for — the skip and the bucket INVERT:
    // /API/OAUTH/token becomes skipped from the global limiter AND absent from
    // the MCP bucket, i.e. completely unlimited. Measured on this app shape:
    // with that flag set the uppercase flood answers 404,404,404,404 — no 429
    // from either bucket.
    //
    // The two arms fail on different mutations, which is why both are here:
    //   arm 1 goes red if app.use stops matching case-insensitively
    //          (nothing limits the uppercase path at all)
    //   arm 2 goes red if normalisePath is de-normalised
    //          (the bucket still engages, but the global budget is spent too)
    const [servicePath] = oauthRateLimiters.MCP_SERVICE_PATHS;
    const upperPath = servicePath.toUpperCase();
    // Non-vacuity: an all-uppercase constant would make this case test nothing.
    expect(upperPath, 'MCP_SERVICE_PATHS must be lowercase for this to mean anything').to.not.equal(
      servicePath
    );

    // globalLimit === FLOOD_LIMIT is load-bearing for arm 2. The service bucket
    // lets exactly FLOOD_LIMIT requests through before it answers 429, so those
    // are the only ones that can ever reach the global limiter. Sizing the
    // global bucket any larger leaves budget over and arm 2 cannot fail.
    const app = makeServerOrderApp({
      routerMounted: false,
      serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      globalLimit: FLOOD_LIMIT,
    });
    const ip = '203.0.113.97';

    // ARM 1 — the MCP bucket engaged on the uppercase spelling.
    for (let i = 0; i < FLOOD_LIMIT; i += 1) {
      const allowed = await request(app)
        .post(upperPath)
        .type('form')
        .set('X-Forwarded-For', ip)
        .send({});
      // Not vacuous: the refusal below must be the limit engaging, not a
      // blanket refusal of the uppercase spelling. 404 here — the router is
      // deliberately unmounted, so the limiters are the only thing under test.
      expect(allowed.status, `uppercase request ${i + 1} should not be limited`).to.not.equal(429);
    }
    const limited = await request(app)
      .post(upperPath)
      .type('form')
      .set('X-Forwarded-For', ip)
      .send({});

    expect(limited.status, `${upperPath} must be inside the MCP bucket`).to.equal(429);

    // ARM 2 — and the global bucket was NOT spent on it. With the skip
    // de-normalised the FLOOD_LIMIT allowed requests above fall through to the
    // global limiter, exhaust it exactly, and this answers 429 instead.
    const other = await request(app).get('/api/oauth/authorize').set('X-Forwarded-For', ip);

    expect(other.status, 'the global budget must not have been spent on the uppercase path').to.not.equal(
      429
    );
  });
});
