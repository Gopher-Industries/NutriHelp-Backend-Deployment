// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Same guard as
// test/authService.oauthExchange.test.js. Must run before any require below
// that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const express = require('express');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { createOauthRouter } = require('../routes/oauth');

/**
 * POST /api/oauth/introspect wire contract. Always assert status, not body
 * alone — body-only passes against 401, and 401-on-inactive is the failure
 * this endpoint exists to prevent. Real router/controller/service/verifier;
 * only DB, keys, config, and logs are doubled via deps.
 */

const MCP_ACCESS_TOKEN_ISSUER = 'https://api.nutrihelp.test';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';

// Stands in for ticket 40's published signing key. Ticket 39 is NOT built
// here: these tokens are minted by the test, not by any code under test.
const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const asPem = {
  private: asKey.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: asKey.publicKey.export({ type: 'spki', format: 'pem' }),
};

const ACTIVE_GRANT = {
  grant_id: GRANT_ID,
  user_id: 42,
  client_id: ASSISTANT_CLIENT_ID,
  resource: MCP_RESOURCE,
  scopes: ['nutrition:read', 'mealplan:read'],
  status: 'active',
};

/**
 * `omit` must be able to drop claims: jwt.sign rejects exp:undefined and
 * auto-adds iat unless noTimestamp — without omit, missing-exp was untestable.
 */
const mintAccessToken = (overrides = {}, key = asPem.private, omit = []) => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: MCP_ACCESS_TOKEN_ISSUER,
    aud: MCP_RESOURCE,
    sub: '42',
    type: 'mcp_access',
    scope: 'nutrition:read mealplan:read',
    client_id: ASSISTANT_CLIENT_ID,
    grant_id: GRANT_ID,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 300,
    ...overrides,
  };
  omit.forEach((claim) => delete payload[claim]);

  return jwt.sign(payload, key, {
    algorithm: 'RS256',
    keyid: 'as-key-1',
    // jwt.sign re-adds iat unless told not to, which would defeat omit('iat').
    noTimestamp: omit.includes('iat'),
  });
};

const makeGrantDb = (grant = ACTIVE_GRANT) => {
  const calls = { grantLookups: 0 };
  return {
    calls,
    from(table) {
      if (table !== 'mcp_client_grants') throw new Error(`unexpected table: ${table}`);
      return {
        select: () => ({
          eq: () => ({
            maybeSingle: async () => {
              calls.grantLookups += 1;
              return { data: typeof grant === 'function' ? grant() : grant, error: null };
            },
          }),
        }),
      };
    },
  };
};

const makeApp = ({
  db = makeGrantDb(),
  keys = [{ kid: 'as-key-1', alg: 'RS256', publicKeyPem: asPem.public }],
  authentication = { ok: true, clientId: MCP_CLIENT_ID },
  log,
} = {}) => {
  const deps = {
    supabase: db,
    clientAssertionVerifier: { verifyClientAssertion: async () => authentication },
    asVerificationKeys: { getVerificationKeys: () => keys },
    oauthConfig: {
      mcpAccessTokenIssuer: () => MCP_ACCESS_TOKEN_ISSUER,
      mcpResourceIdentifier: () => MCP_RESOURCE,
      introspectionAudience: () => 'https://api.nutrihelp.test/api/oauth/introspect',
    },
    introspectionLog: log || { logOperational: async () => {}, logGrantRefusal: async () => {} },
  };

  const app = express();
  app.use('/api/oauth', createOauthRouter(deps));
  return app;
};

const form = (token = mintAccessToken()) => ({
  token,
  token_type_hint: 'access_token',
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_assertion: 'verified-by-the-authentication-double',
});

const post = (app, body = form(), path = '/api/oauth/introspect') =>
  request(app).post(path).type('form').send(body);

describe('POST /api/oauth/introspect', () => {
  describe('the branch the ticket says to get right', () => {
    it('answers 200 — not 401 — for a revoked grant', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }) });

      const response = await post(app);

      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });

    it('answers 200 for a replaced grant', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'replaced' }) });

      const response = await post(app);

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers 200 for a grant that does not exist', async () => {
      const app = makeApp({ db: makeGrantDb(null) });

      const response = await post(app);

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('returns active as a real JSON boolean, not a string or a number', async () => {
      const response = await post(makeApp());

      expect(response.body.active).to.be.a('boolean');
      expect(JSON.parse(response.text).active).to.equal(true);
    });

    it('returns active:false as a real JSON boolean too', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }) });

      const response = await post(app);

      expect(response.body.active).to.be.a('boolean');
      expect(JSON.parse(response.text).active).to.equal(false);
    });

    it('logs an inactive grant as a security event, not as an operational error', async () => {
      const seen = { operational: [], security: [] };
      const log = {
        logOperational: async (ctx) => seen.operational.push(ctx),
        logGrantRefusal: async (ctx) => seen.security.push(ctx),
      };
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }), log });

      await request(app)
        .post('/api/oauth/introspect')
        .type('form')
        .set('x-correlation-id', 'corr-abc-123')
        .send(form());

      expect(seen.security).to.have.lengthOf(1);
      expect(seen.operational).to.have.lengthOf(0);
      expect(seen.security[0].correlationId).to.equal('corr-abc-123');
      expect(seen.security[0].requestId).to.be.a('string');
    });

    it('never writes the token value or the assertion into any log record, across every outcome', async () => {
      // The earlier version of this test could not fail: it used the harness's
      // literal placeholder as the assertion and exercised one of five log
      // call sites. Now every outcome path is driven, with values distinctive
      // enough that a substring search is meaningful.
      const marker = crypto.randomUUID();
      const seen = [];
      const log = {
        logOperational: async (ctx) => seen.push(ctx),
        logGrantRefusal: async (ctx) => seen.push(ctx),
      };

      const body = () => ({
        ...form(mintAccessToken({ jti: `tok-${marker}` })),
        client_assertion: `assertion-${marker}`,
      });

      // 401 client authentication, 400 no token, 503 unavailable, 200 inactive.
      await post(
        makeApp({
          log,
          authentication: { ok: false, httpStatus: 401, reason: 'invalid_client', detail: 'x' },
        }),
        body()
      );
      const noToken = body();
      delete noToken.token;
      await post(makeApp({ log }), noToken);
      await post(makeApp({ log, keys: [] }), body());
      await post(makeApp({ log, db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }) }), body());

      expect(seen.length).to.be.at.least(4);
      const serialised = JSON.stringify(seen);
      expect(serialised).to.not.contain(marker);
      expect(serialised).to.not.contain('assertion-');
      expect(serialised).to.not.contain('eyJ'); // no JWT of any kind
    });

    it('the real log sink is handed no request object, which is what keeps credentials out', async () => {
      // The structural fact behind the test above. introspectionLog calls
      // errorLogService.logError WITHOUT `req`, so the unified logger has no
      // headers and no body to sweep into the record. If someone "improves"
      // these calls by passing `req` for richer context, credentials start
      // being logged and the substring test above would still pass whenever
      // the placeholder happens not to appear.
      const introspectionLog = require('../services/oauth/introspectionLog');
      const errorCalls = [];
      const securityCalls = [];

      await introspectionLog.logOperational(
        { correlationId: 'c', requestId: 'r', outcome: 'o', detail: 'd', httpStatus: 503 },
        { errorLogService: { logError: async (a) => errorCalls.push(a) } }
      );
      await introspectionLog.logGrantRefusal(
        { correlationId: 'c', requestId: 'r', detail: 'd', userId: 42 },
        { securityEventService: { logSecurityEvent: async (a) => securityCalls.push(a) } }
      );

      expect(errorCalls).to.have.lengthOf(1);
      expect(errorCalls[0]).to.not.have.property('req');
      expect(errorCalls[0]).to.not.have.property('res');
      expect(errorCalls[0].category).to.equal('critical');
      expect(Object.keys(errorCalls[0].additionalContext)).to.have.members([
        'endpoint',
        'correlation_id',
        'request_id',
        'outcome',
        'detail',
        'http_status',
        'client_id',
      ]);

      expect(securityCalls).to.have.lengthOf(1);
      expect(securityCalls[0].user_id).to.equal(42);
    });

    it('carries the grant user id on the security record', async () => {
      // L5. This event is about one user's disconnection; a always-null
      // user_id made the record far less useful than it looked.
      const seen = [];
      const log = {
        logOperational: async () => {},
        logGrantRefusal: async (ctx) => seen.push(ctx),
      };
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }), log });

      await post(app);

      expect(seen).to.have.lengthOf(1);
      expect(seen[0].userId).to.equal(42);
    });
  });

  describe('the active answer', () => {
    it('returns every field the client requires, all non-empty strings', async () => {
      const response = await post(makeApp());

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
      for (const field of ['grant_id', 'sub', 'client_id']) {
        expect(response.body[field], field).to.be.a('string');
        expect(response.body[field], field).to.not.equal('');
      }
      expect(response.body.grant_id).to.equal(GRANT_ID);
      expect(response.body.sub).to.equal('42');
      expect(response.body.client_id).to.equal(ASSISTANT_CLIENT_ID);
    });

    it('echoes the ACCESS TOKEN claims back, not this endpoint own identifiers', async () => {
      const token = mintAccessToken();
      const claims = jwt.decode(token);

      const response = await post(makeApp(), form(token));

      expect(response.body.iss).to.equal(claims.iss);
      expect(response.body.aud).to.equal(MCP_RESOURCE);
      expect(response.body.jti).to.equal(claims.jti);
      expect(response.body.iat).to.equal(claims.iat);
      expect(response.body.exp).to.equal(claims.exp);
    });

    it('returns scope space-delimited', async () => {
      const response = await post(makeApp());

      expect(response.body.scope).to.equal('nutrition:read mealplan:read');
    });

    it('intersects scope so a narrowed grant binds immediately', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, scopes: ['nutrition:read'] }) });

      const response = await post(app);

      expect(response.body.scope).to.equal('nutrition:read');
    });

    it('never widens scope when the grant was later widened', async () => {
      const app = makeApp({
        db: makeGrantDb({
          ...ACTIVE_GRANT,
          scopes: ['nutrition:read', 'mealplan:read', 'mealplan:write'],
        }),
      });

      const response = await post(app);

      expect(response.body.scope).to.equal('nutrition:read mealplan:read');
    });

    it('returns an empty scope rather than implying all scopes', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, scopes: [] }) });

      const response = await post(app);

      expect(response.body.active).to.equal(true);
      expect(response.body.scope).to.equal('');
    });

    it('sets Cache-Control: no-store on the active answer', async () => {
      const response = await post(makeApp());

      expect(response.headers['cache-control']).to.equal('no-store');
    });

    it('sets Cache-Control: no-store on the inactive answer too', async () => {
      const app = makeApp({ db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }) });

      const response = await post(app);

      expect(response.headers['cache-control']).to.equal('no-store');
    });
  });

  describe('cross-checking the token against its grant (closes MCP-side P28)', () => {
    it('answers active:false when the token subject disagrees with the grant', async () => {
      const response = await post(makeApp(), form(mintAccessToken({ sub: '999' })));

      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });

    it('answers active:false when the token resource disagrees with the grant', async () => {
      // The token's aud is checked against MCP_RESOURCE_IDENTIFIER during
      // verification, which cannot distinguish two of our own resources. This
      // is the grant-row half. Both sides of the app are configured for the
      // same resource here, so the disagreement is made on the grant row.
      const app = makeApp({
        db: makeGrantDb({ ...ACTIVE_GRANT, resource: 'https://mcp.nutrihelp.test/other' }),
      });

      const response = await post(app);

      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });

    it('answers active:false when the token client disagrees with the grant', async () => {
      const response = await post(
        makeApp(),
        form(mintAccessToken({ client_id: 'https://other.example/client' }))
      );

      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });
  });

  describe('token profile discipline', () => {
    it('answers active:false for a platform access token, not an MCP one', async () => {
      const response = await post(makeApp(), form(mintAccessToken({ type: 'access' })));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers active:false for a token signed by the wrong key', async () => {
      const foreign = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const token = mintAccessToken(
        {},
        foreign.privateKey.export({ type: 'pkcs8', format: 'pem' })
      );

      const response = await post(makeApp(), form(token));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers active:false for a token whose audience is not the MCP resource', async () => {
      const response = await post(
        makeApp(),
        form(mintAccessToken({ aud: 'https://elsewhere.test' }))
      );

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers active:false for a correctly signed token carrying NO exp', async () => {
      // ⚠️ THE CRITICAL. jsonwebtoken validates `exp` only when it is present,
      // so this token verifies with `exp: undefined` and used to pass the
      // presence gate, which checked only string claims. It would then read
      // active:true forever — and for this credential live introspection is
      // the ONLY expiry backstop, so "forever" is literal.
      const noExpiry = mintAccessToken({}, asPem.private, ['exp']);
      expect(jwt.decode(noExpiry).exp).to.equal(undefined);

      const response = await post(makeApp(), form(noExpiry));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers active:false for a correctly signed token carrying NO iat', async () => {
      const noIssuedAt = mintAccessToken({}, asPem.private, ['iat']);
      expect(jwt.decode(noIssuedAt).iat).to.equal(undefined);

      const response = await post(makeApp(), form(noIssuedAt));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('emits token_missing_scope_claim when a verified token carries no scope, without changing the answer', async () => {
      // The diagnostic cost of not requiring `scope`: an issuer bug and a
      // genuinely scope-less grant look identical at the MCP server (both are
      // "insufficient scope"), so without this signal an ISSUANCE defect gets
      // investigated as a CONSENT problem, in the wrong repository.
      const seen = [];
      const log = {
        logOperational: async (ctx) => seen.push(ctx),
        logGrantRefusal: async () => {},
      };
      const noScope = mintAccessToken({}, asPem.private, ['scope']);

      const response = await post(makeApp({ log }), form(noScope));

      const notices = seen.filter((s) => s.outcome === 'token_missing_scope_claim');
      expect(notices).to.have.lengthOf(1);
      expect(notices[0].detail).to.equal('token_diagnostic');
      expect(notices[0].correlationId).to.equal(undefined);
      // ⚠️ The answer is unchanged. A diagnostic that alters the response is
      // not a diagnostic.
      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
    });

    it('does not emit the notice for a token whose scope is present but empty', async () => {
      // An explicit empty scope is a legitimate zero-scope grant, not a defect.
      const seen = [];
      const log = {
        logOperational: async (ctx) => seen.push(ctx),
        logGrantRefusal: async () => {},
      };

      const response = await post(makeApp({ log }), form(mintAccessToken({ scope: '' })));

      expect(seen.filter((s) => s.outcome === 'token_missing_scope_claim')).to.have.lengthOf(0);
      expect(response.body.active).to.equal(true);
      expect(response.body.scope).to.equal('');
    });

    it('does not emit the notice for an ordinary token', async () => {
      const seen = [];
      const log = {
        logOperational: async (ctx) => seen.push(ctx),
        logGrantRefusal: async () => {},
      };

      await post(makeApp({ log }));

      expect(seen.filter((s) => s.outcome === 'token_missing_scope_claim')).to.have.lengthOf(0);
    });

    it('still emits the notice when the grant is inactive, since the issuer defect is real either way', async () => {
      const seen = [];
      const log = {
        logOperational: async (ctx) => seen.push(ctx),
        logGrantRefusal: async () => {},
      };
      const app = makeApp({ log, db: makeGrantDb({ ...ACTIVE_GRANT, status: 'revoked' }) });

      const response = await post(app, form(mintAccessToken({}, asPem.private, ['scope'])));

      expect(seen.filter((s) => s.outcome === 'token_missing_scope_claim')).to.have.lengthOf(1);
      expect(response.status).to.equal(200);
      expect(response.body).to.deep.equal({ active: false });
    });

    it('stays active for a token with no scope, refusing on authorization rather than identity', async () => {
      // `scope` is in the token profile but is deliberately not a presence
      // requirement: absent means NO scopes, so the call is refused for lack
      // of scope. Requiring it would answer active:false, which the MCP server
      // reads as a REVOCATION and reports to the user as a disconnection. The
      // two failure modes are not equally bad.
      const noScope = mintAccessToken({}, asPem.private, ['scope']);

      const response = await post(makeApp(), form(noScope));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
      expect(response.body.scope).to.equal('');
    });

    it('answers active:false for an expired token', async () => {
      const past = Math.floor(Date.now() / 1000) - 3600;
      const response = await post(makeApp(), form(mintAccessToken({ iat: past, exp: past + 300 })));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });
  });

  describe('503 — could not establish an answer, never rendered as active:false', () => {
    it('answers 503 when no verification key is configured', async () => {
      // The seam is empty until ticket 40 fills it. Answering active:false
      // here would report every token on the platform as revoked at once.
      const response = await post(makeApp({ keys: [] }));

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('answers 503 when no configured key matches the token kid', async () => {
      // Regression, C1. This returned 200 {"active": false} — a mass
      // disconnect reported as a revocation for a condition never
      // established. "No key survived the kid filter" is "no verification
      // material for this token", which is the unconfigured case one step
      // later, not a verified negative.
      const app = makeApp({
        keys: [{ kid: 'some-other-key', alg: 'RS256', publicKeyPem: asPem.public }],
      });

      const response = await post(app);

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('answers 503 when MCP_AS_KEY_ID is unset but the token carries a kid', async () => {
      // The reachability path that needs no bad token and no attacker:
      // asVerificationKeys returns kid: null when MCP_AS_KEY_ID is absent, so
      // `null === 'as-key-1'` is false and the candidate set empties for
      // EVERY token the issuer signs. Ticket 40 publishes keys with a kid, so
      // tokens will carry one — this is the steady state, not an edge case.
      const app = makeApp({ keys: [{ kid: null, alg: 'RS256', publicKeyPem: asPem.public }] });

      const response = await post(app);

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('answers 503 during a rotation window where the published key is not yet configured', async () => {
      // Ticket 40 rotates to key B while this server's configuration still
      // names key A. Platform-wide for the length of the window, and every
      // affected user would otherwise be told their grant was revoked.
      const rotated = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const tokenFromNewKey = jwt.sign(
        { ...jwt.decode(mintAccessToken()) },
        rotated.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        { algorithm: 'RS256', keyid: 'as-key-2' }
      );
      const app = makeApp({
        keys: [{ kid: 'as-key-1', alg: 'RS256', publicKeyPem: asPem.public }],
      });

      const response = await post(app, form(tokenFromNewKey));

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('still answers active:false for a token that matched a key and failed verification', async () => {
      // The boundary the C1 fix must not blur: reaching a key and having it
      // reject the token IS a verified negative and stays 200 active:false.
      // If this ever turns into a 503, the fix has over-reached and real
      // revocations would stop being reported.
      const foreign = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const token = mintAccessToken(
        {},
        foreign.privateKey.export({ type: 'pkcs8', format: 'pem' })
      );

      const response = await post(makeApp(), form(token));

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(false);
    });

    it('answers 503 when the grant lookup fails', async () => {
      const db = {
        from: () => ({
          select: () => ({
            eq: () => ({
              maybeSingle: async () => ({ data: null, error: { message: 'connection refused' } }),
            }),
          }),
        }),
      };

      const response = await post(makeApp({ db }));

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('answers 503 when the grant lookup throws', async () => {
      const db = {
        from: () => {
          throw new Error('socket hang up');
        },
      };

      const response = await post(makeApp({ db }));

      expect(response.status).to.equal(503);
      expect(response.body).to.not.have.property('active');
    });

    it('logs a 503 operationally, never as a grant refusal', async () => {
      const seen = { operational: [], security: [] };
      const log = {
        logOperational: async (ctx) => seen.operational.push(ctx),
        logGrantRefusal: async (ctx) => seen.security.push(ctx),
      };

      await post(makeApp({ keys: [], log }));

      expect(seen.operational).to.have.lengthOf(1);
      expect(seen.security).to.have.lengthOf(0);
      expect(seen.operational[0].httpStatus).to.equal(503);
    });
  });

  describe('client authentication', () => {
    it('answers 401 when the client assertion fails', async () => {
      const app = makeApp({
        authentication: {
          ok: false,
          httpStatus: 401,
          reason: 'invalid_client',
          detail: 'assertion_replayed',
        },
      });

      const response = await post(app);

      expect(response.status).to.equal(401);
      expect(response.body).to.not.have.property('active');
    });

    it('answers 400 for a malformed request', async () => {
      const app = makeApp({
        authentication: {
          ok: false,
          httpStatus: 400,
          reason: 'invalid_request',
          detail: 'client_assertion_absent',
        },
      });

      const response = await post(app);

      expect(response.status).to.equal(400);
    });

    it('answers 400 when the token parameter is absent', async () => {
      const response = await post(makeApp(), { token_type_hint: 'access_token' });

      expect(response.status).to.equal(400);
      expect(response.body).to.not.have.property('active');
    });

    it('never reaches the grant lookup when authentication fails', async () => {
      const db = makeGrantDb();
      const app = makeApp({
        db,
        authentication: {
          ok: false,
          httpStatus: 401,
          reason: 'invalid_client',
          detail: 'no_key_in_window',
        },
      });

      await post(app);

      expect(db.calls.grantLookups).to.equal(0);
    });
  });

  describe('transport', () => {
    it('never redirects — the caller sets redirect:error, so a 3xx is a hard failure', async () => {
      const response = await request(makeApp())
        .post('/api/oauth/introspect/')
        .type('form')
        .send(form())
        .redirects(0);

      expect(response.status).to.be.below(300);
      expect(response.status).to.equal(200);
    });

    it('answers application/json', async () => {
      const response = await post(makeApp());

      expect(response.headers['content-type']).to.match(/application\/json/);
    });

    it('needs no Authorization header — the assertion is the only credential', async () => {
      const response = await post(makeApp());

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
    });
  });

  describe('no caching — a cached positive answer is why this endpoint exists', () => {
    it('queries the grant on every call', async () => {
      const db = makeGrantDb();
      const app = makeApp({ db });

      await post(app);
      await post(app);
      await post(app);

      expect(db.calls.grantLookups).to.equal(3);
    });

    it('sees a revocation on the very next call with the same token value', async () => {
      // The acceptance test in miniature: the same token that was active a
      // moment ago must answer false as soon as the grant flips.
      let grant = { ...ACTIVE_GRANT };
      const app = makeApp({ db: makeGrantDb(() => grant) });
      const token = mintAccessToken();

      const before = await post(app, form(token));
      grant = { ...ACTIVE_GRANT, status: 'revoked' };
      const after = await post(app, form(token));

      expect(before.status).to.equal(200);
      expect(before.body.active).to.equal(true);
      expect(after.status).to.equal(200);
      expect(after.body.active).to.equal(false);
    });
  });
});
