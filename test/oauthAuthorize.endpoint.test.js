// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Same guard as
// test/oauthDisconnect.test.js. Must run before any require below.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const express = require('express');
const request = require('supertest');

const { createOauthRouter } = require('../routes/oauth');
const authorizeTransactionService = require('../services/oauth/authorizeTransactionService');

/**
 * GET /api/oauth/authorize (ticket 36). Real router/controller/service, with
 * doubles for Supabase, the CIMD fetch and the log sinks.
 *
 * The redirect_uri comparison is deliberately NOT doubled: the real
 * services/oauth/redirectUriMatcher runs, so "ticket 36 grew a second matcher"
 * fails here rather than in production.
 *
 * Two rules drive most of these cases:
 *   1. A failure may only be redirected to redirect_uri once the client AND
 *      that exact redirect_uri are proven. Everything before that is a direct
 *      4xx, or this endpoint is an open redirector.
 *   2. Nothing that identifies the user may reach a URL. The browser arrives
 *      here with no credential and leaves carrying only an opaque reference.
 */

const FRONTEND_ORIGIN = 'https://gonutrihelp.vercel.app';
const ISSUER = 'https://nutrihelp-backend.onrender.com';
const RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const CLIENT_ID = 'https://claude.ai/mcp-client';
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const OTHER_REDIRECT_URI = 'https://claude.ai/api/mcp/other_callback';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const STATE = 'opaque-client-state-123';

const CLIENT_METADATA = {
  client_id: CLIENT_ID,
  display_name: 'Claude',
  redirect_uris: [REDIRECT_URI, OTHER_REDIRECT_URI],
};

/** Minimal query that must succeed; individual tests override one key. */
const validQuery = (overrides = {}) => ({
  response_type: 'code',
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  resource: RESOURCE,
  scope: 'mealplan:read meallog:write',
  code_challenge: CHALLENGE,
  code_challenge_method: 'S256',
  state: STATE,
  ...overrides,
});

/**
 * Supabase double, modelling oauth_clients as an actual keyed table rather
 * than a write sink.
 *
 * It has to, because the property under test is what happens when a row for
 * this client_id ALREADY EXISTS as something else. A permissive double that
 * just records writes goes green for code that overwrites the MCP server's own
 * confidential client into an assistant public one.
 *
 * So the conditional write is simulated faithfully:
 *   update(...).eq(client_id).eq(client_type) matches only when BOTH match
 *   insert(...) on an occupied primary key returns Postgres 23505
 * and a test can seed an existing row of any client_type.
 *
 * @param existingClient  a row already in oauth_clients, or null
 */
const makeDb = ({
  insertError = null,
  clientWriteError = null,
  existingClient = null,
  // Models a CONCURRENT first-sight request that inserted the row between our
  // UPDATE and our INSERT: the insert collides, and the row it collided with
  // is an ordinary assistant row that a re-run UPDATE will match.
  concurrentInsertWins = null,
} = {}) => {
  const calls = { transactionInserts: [], clientUpdates: [], clientInserts: [] };
  // Clone so a test's seed object is never mutated across cases.
  const clients = existingClient ? [{ ...existingClient }] : [];

  return {
    calls,
    clients,
    from(table) {
      if (table === 'oauth_authorization_transactions') {
        return {
          insert: async (rows) => {
            calls.transactionInserts.push(...rows);
            if (insertError) return { data: null, error: insertError };
            return { data: rows, error: null };
          },
        };
      }

      if (table === 'oauth_clients') {
        const filters = [];
        const chain = {
          update: (row) => {
            chain.__pending = { op: 'update', row };
            return chain;
          },
          insert: async (rows) => {
            calls.clientInserts.push(...rows);
            if (clientWriteError) return { data: null, error: clientWriteError };
            if (concurrentInsertWins && clients.length === 0) {
              clients.push({ ...concurrentInsertWins });
              return { data: null, error: { code: '23505', message: 'duplicate key' } };
            }
            const clash = clients.find((c) => c.client_id === rows[0].client_id);
            // Primary key on client_id.
            if (clash) return { data: null, error: { code: '23505', message: 'duplicate key' } };
            clients.push({ ...rows[0] });
            return { data: rows, error: null };
          },
          eq: (column, value) => {
            filters.push([column, value]);
            return chain;
          },
          select: async () => {
            if (clientWriteError) return { data: null, error: clientWriteError };
            const matched = clients.filter((row) =>
              filters.every(([column, value]) => row[column] === value)
            );
            matched.forEach((row) => Object.assign(row, chain.__pending.row));
            calls.clientUpdates.push({ filters: filters.slice(), matched: matched.length });
            return { data: matched.map((r) => ({ client_id: r.client_id })), error: null };
          },
        };
        return chain;
      }

      throw new Error(`unexpected table: ${table}`);
    },
  };
};

const silentLog = () => ({
  logOperational: async () => undefined,
  logGrantRefusal: async () => undefined,
});

/**
 * @param metadata  what the CIMD layer resolves the client to, or a failure
 */
const makeApp = ({ metadata = CLIENT_METADATA, metadataFailure = null, db, log } = {}) => {
  const deps = {
    supabase: db || makeDb(),
    introspectionLog: log || silentLog(),
    clientMetadataService: {
      fetchAndValidateClientMetadata: async () =>
        metadataFailure ? { ok: false, reason: metadataFailure } : { ok: true, metadata },
    },
    // Rate limiting is proved separately in oauthAuthorize.rateLimit.test.js;
    // an active bucket here would make these cases order-dependent.
    oauthRateLimiters: {
      authorizeAddressLimiter: (req, res, next) => next(),
      metadataFetchClientLimiter: (req, res, next) => next(),
      mcpServiceAddressLimiter: (req, res, next) => next(),
    },
  };

  const app = express();
  app.use('/api/oauth', createOauthRouter(deps));
  return { app, deps };
};

const queryOf = (location) => new URL(location).searchParams;

describe('GET /api/oauth/authorize — ticket 36', () => {
  let savedEnv;

  beforeEach(() => {
    savedEnv = {
      OAUTH_FRONTEND_ORIGIN: process.env.OAUTH_FRONTEND_ORIGIN,
      MCP_AS_ISSUER: process.env.MCP_AS_ISSUER,
      MCP_RESOURCE_IDENTIFIER: process.env.MCP_RESOURCE_IDENTIFIER,
      OAUTH_FRONTEND_LOGIN_PATH: process.env.OAUTH_FRONTEND_LOGIN_PATH,
    };
    process.env.OAUTH_FRONTEND_ORIGIN = FRONTEND_ORIGIN;
    process.env.MCP_AS_ISSUER = ISSUER;
    process.env.MCP_RESOURCE_IDENTIFIER = RESOURCE;
    delete process.env.OAUTH_FRONTEND_LOGIN_PATH;
  });

  afterEach(() => {
    Object.entries(savedEnv).forEach(([key, value]) => {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    });
  });

  describe('the happy path', () => {
    it('redirects the browser to the frontend login page', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(res.headers.location).to.be.a('string');
      expect(new URL(res.headers.location).origin).to.equal(FRONTEND_ORIGIN);
    });

    it('carries ONLY the transaction reference to the frontend', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      // The contract says "carrying only the opaque identifier". A second
      // parameter here is how request details start leaking into browser
      // history and Referer.
      expect([...queryOf(res.headers.location).keys()]).to.deep.equal(['transaction']);
    });

    it('stores the HASH of the reference, never the reference itself', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      const reference = queryOf(res.headers.location).get('transaction');
      const [row] = db.calls.transactionInserts;
      const expected = crypto.createHash('sha256').update(reference).digest('hex');

      expect(row.transaction_hash).to.equal(expected);
      expect(row.transaction_hash).to.not.equal(reference);
      expect(JSON.stringify(row)).to.not.contain(reference);
    });

    it('issues a reference with at least 128 bits of entropy', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());
      const reference = queryOf(res.headers.location).get('transaction');

      // base64url of 32 bytes. Guessing a pending transaction must not be
      // cheaper than guessing the authorization code it leads to.
      expect(reference).to.match(/^[A-Za-z0-9_-]{43}$/);
    });

    it('issues a different reference every time', async () => {
      const { app } = makeApp();

      const first = await request(app).get('/api/oauth/authorize').query(validQuery());
      const second = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(queryOf(first.headers.location).get('transaction')).to.not.equal(
        queryOf(second.headers.location).get('transaction')
      );
    });

    it('persists the whole request on the transaction row', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      const [row] = db.calls.transactionInserts;
      expect(row.client_id).to.equal(CLIENT_ID);
      expect(row.redirect_uri).to.equal(REDIRECT_URI);
      expect(row.resource).to.equal(RESOURCE);
      expect(row.scopes).to.deep.equal(['mealplan:read', 'meallog:write']);
      expect(row.code_challenge).to.equal(CHALLENGE);
      expect(row.code_challenge_method).to.equal('S256');
      expect(row.state).to.equal(STATE);
    });

    it('writes client_type assistant_public so the composite FK refuses anything else', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.calls.transactionInserts[0].client_type).to.equal('assistant_public');
    });

    it('leaves the transaction unbound, unconsumed and undecided', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      // The two CHECK constraints in migration 002 both key off these.
      const [row] = db.calls.transactionInserts;
      expect(row.bound_user_id === null || row.bound_user_id === undefined).to.equal(true);
      expect(row.consumed_at === null || row.consumed_at === undefined).to.equal(true);
      expect(row.decision === null || row.decision === undefined).to.equal(true);
    });

    it('sets a short expiry in the future', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      const before = Date.now();
      await request(app).get('/api/oauth/authorize').query(validQuery());

      const expires = new Date(db.calls.transactionInserts[0].expires_at).getTime();
      expect(expires).to.be.greaterThan(before);
      // Long enough for a human to log in, short enough to bound a stolen ref.
      expect(expires - before).to.be.at.most(
        authorizeTransactionService.TRANSACTION_TTL_SECONDS * 1000 + 5000
      );
      expect(expires - before).to.be.at.least(60 * 1000);
    });

    it('never mints a csrf_token_hash — ticket 37 owns that', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      const [row] = db.calls.transactionInserts;
      expect(row.csrf_token_hash === null || row.csrf_token_hash === undefined).to.equal(true);
    });

    it('registers the resolved client so the transaction FK resolves', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      const [row] = db.calls.clientInserts;
      expect(row.client_id).to.equal(CLIENT_ID);
      expect(row.client_type).to.equal('assistant_public');
      expect(row.token_endpoint_auth_method).to.equal('none');
      expect(row.display_name).to.equal('Claude');
      expect(row.redirect_uris).to.deep.equal([REDIRECT_URI, OTHER_REDIRECT_URI]);
    });

    it('sets Cache-Control: no-store on the redirect', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.headers['cache-control']).to.contain('no-store');
    });

    it('accepts a request with no state', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });
      const query = validQuery();
      delete query.state;

      const res = await request(app).get('/api/oauth/authorize').query(query);

      expect(res.status).to.equal(302);
      expect(db.calls.transactionInserts[0].state === null).to.equal(true);
    });

    it('accepts the repeated-key array form of scope', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: undefined }))
        .query('scope=mealplan:read&scope=meallog:write');

      expect(db.calls.transactionInserts[0].scopes).to.deep.equal([
        'mealplan:read',
        'meallog:write',
      ]);
    });
  });

  describe('no token, ever, in a URL', () => {
    it('ignores an Authorization header rather than putting anything in the redirect', async () => {
      const { app } = makeApp();

      const res = await request(app)
        .get('/api/oauth/authorize')
        .set('Authorization', 'Bearer platform.access.token')
        .query(validQuery());

      expect(res.status).to.equal(302);
      expect(res.headers.location).to.not.contain('platform.access.token');
      expect(res.headers.location).to.not.contain('Bearer');
    });

    it('never writes a bearer token onto the transaction row', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app)
        .get('/api/oauth/authorize')
        .set('Authorization', 'Bearer platform.access.token')
        .query(validQuery());

      expect(JSON.stringify(db.calls.transactionInserts[0])).to.not.contain(
        'platform.access.token'
      );
    });

    it('infers no user — the row is written with no bound user', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app)
        .get('/api/oauth/authorize')
        .set('Authorization', 'Bearer platform.access.token')
        .query(validQuery());

      expect(db.calls.transactionInserts[0].bound_user_id == null).to.equal(true);
    });
  });

  describe('failures that must NOT be redirected to the client', () => {
    it('refuses an unresolvable client with a direct 400', async () => {
      const { app } = makeApp({ metadataFailure: 'document_not_json' });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(400);
      expect(res.headers.location).to.equal(undefined);
      // invalid_request, not invalid_client: the latter is RFC 6749 §5.2, a
      // TOKEN-endpoint code, and does not belong in an authorization response.
      expect(res.body.error).to.equal('invalid_request');
    });

    it('refuses a redirect_uri the client did not register, with a direct 400', async () => {
      const { app } = makeApp();

      const res = await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: 'https://attacker.example/steal' }));

      // Redirecting here would make this endpoint an open redirector, and
      // would hand the attacker the error response.
      expect(res.status).to.equal(400);
      expect(res.headers.location).to.equal(undefined);
      expect(res.body.error).to.equal('invalid_request');
    });

    it('refuses a redirect_uri that only differs by trailing slash', async () => {
      const { app } = makeApp();

      const res = await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: `${REDIRECT_URI}/` }));

      expect(res.status).to.equal(400);
      expect(res.headers.location).to.equal(undefined);
    });

    it('refuses a missing redirect_uri with a direct 400', async () => {
      const { app } = makeApp();
      const query = validQuery();
      delete query.redirect_uri;

      const res = await request(app).get('/api/oauth/authorize').query(query);

      expect(res.status).to.equal(400);
      expect(res.headers.location).to.equal(undefined);
    });

    it('refuses a missing client_id with a direct 400', async () => {
      const { app } = makeApp();
      const query = validQuery();
      delete query.client_id;

      const res = await request(app).get('/api/oauth/authorize').query(query);

      expect(res.status).to.equal(400);
      expect(res.headers.location).to.equal(undefined);
      expect(res.body.error).to.equal('invalid_request');
    });

    it('never writes a transaction for a refused client', async () => {
      const db = makeDb();
      const { app } = makeApp({ db, metadataFailure: 'client_type_not_dereferenceable' });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.calls.transactionInserts).to.have.length(0);
    });

    it('refuses the MCP server’s own confidential id at the door', async () => {
      // clientMetadataService refuses to dereference service_confidential;
      // ticket 36 must not paper over that with its own lookup.
      const { app } = makeApp({ metadataFailure: 'client_type_not_dereferenceable' });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('invalid_request');
    });
  });

  describe('failures that are redirected to the validated redirect_uri', () => {
    const redirectedError = async (overrides) => {
      const { app } = makeApp();
      const res = await request(app).get('/api/oauth/authorize').query(validQuery(overrides));
      expect(res.status).to.equal(302);
      const location = new URL(res.headers.location);
      expect(location.origin + location.pathname).to.equal(REDIRECT_URI);
      return location.searchParams;
    };

    it('reports a resource-independent server failure as server_error', async () => {
      // Blocker 2: past the redirect_uri proof, even OUR failures are the
      // client's business. A JSON 503 here strands the user with the assistant
      // told nothing.
      const db = makeDb({ insertError: { message: 'insert exploded' } });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      const params = new URL(res.headers.location).searchParams;
      expect(params.get('error')).to.equal('server_error');
      expect(params.get('state')).to.equal(STATE);
      expect(params.get('iss')).to.equal(ISSUER);
    });

    it('reports an unknown scope as invalid_scope', async () => {
      const params = await redirectedError({ scope: 'mealplan:read admin:everything' });
      expect(params.get('error')).to.equal('invalid_scope');
    });

    it('reports an absent scope as invalid_scope', async () => {
      const params = await redirectedError({ scope: undefined });
      expect(params.get('error')).to.equal('invalid_scope');
    });

    it('reports a resource this server will not issue for as invalid_target', async () => {
      const params = await redirectedError({ resource: 'https://elsewhere.example/mcp' });
      expect(params.get('error')).to.equal('invalid_target');
    });

    it('reports a missing resource as invalid_target', async () => {
      const params = await redirectedError({ resource: undefined });
      expect(params.get('error')).to.equal('invalid_target');
    });

    it('echoes state back unchanged', async () => {
      const params = await redirectedError({ scope: 'nope:nope' });
      expect(params.get('state')).to.equal(STATE);
    });

    it('omits state entirely when the request carried none', async () => {
      const params = await redirectedError({ scope: 'nope:nope', state: undefined });
      expect(params.has('state')).to.equal(false);
    });

    it('carries the RFC 9207 iss parameter', async () => {
      const params = await redirectedError({ scope: 'nope:nope' });
      expect(params.get('iss')).to.equal(ISSUER);
    });

    it('writes no transaction row for a redirected failure', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: 'nope:nope' }));

      expect(db.calls.transactionInserts).to.have.length(0);
    });

    it('preserves a query string already present on the registered redirect_uri', async () => {
      const withQuery = 'https://claude.ai/api/mcp/auth_callback?tenant=acme';
      const { app } = makeApp({
        metadata: { ...CLIENT_METADATA, redirect_uris: [withQuery] },
      });

      const res = await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: withQuery, scope: 'nope:nope' }));

      const params = new URL(res.headers.location).searchParams;
      expect(params.get('tenant')).to.equal('acme');
      expect(params.get('error')).to.equal('invalid_scope');
    });
  });

  describe('configuration and storage failures', () => {
    it('answers 503 rather than redirecting when the issuer is unset', async () => {
      delete process.env.MCP_AS_ISSUER;
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(503);
      expect(res.headers.location).to.equal(undefined);
    });

    it('redirects server_error when the frontend origin is unset', async () => {
      // Was a JSON 503. It is an env-derived, deterministic, our-side
      // misconfiguration — exactly the class the resource-identifier case ten
      // lines below already redirected. Two tests in one file pinning opposite
      // treatments of one class is how the inconsistency stayed invisible.
      delete process.env.OAUTH_FRONTEND_ORIGIN;
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      const params = new URL(res.headers.location).searchParams;
      expect(params.get('error')).to.equal('server_error');
      expect(params.get('iss')).to.equal(ISSUER);
      expect(params.get('state')).to.equal(STATE);
    });

    it('still answers 503 when the ISSUER is unset, because no error is deliverable', async () => {
      // The one config value that must be resolved first: every
      // client-directed response carries RFC 9207 iss, so with no issuer there
      // is no compliant error to deliver and 503 is the honest answer.
      delete process.env.MCP_AS_ISSUER;
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(503);
      expect(res.headers.location).to.equal(undefined);
    });

    it('delivers a refusal even when the frontend origin is unset', async () => {
      // The actual harm: an ordinary invalid_scope from a correctly registered
      // client used to become a JSON 503 purely because OUR success-path
      // config was broken.
      delete process.env.OAUTH_FRONTEND_ORIGIN;
      const { app } = makeApp();

      const res = await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: 'nope:nope' }));

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('invalid_scope');
    });

    it('redirects server_error when the resource identifier is unset, never accept-anything', async () => {
      // Still refused — but past the redirect_uri proof it is refused TO THE
      // CLIENT. Never accept-anything, and never a silent 503 either.
      delete process.env.MCP_RESOURCE_IDENTIFIER;
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
    });

    it('redirects server_error when the transaction insert fails', async () => {
      const db = makeDb({ insertError: { message: 'insert exploded' } });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
    });

    it('redirects server_error when the client write fails, rather than orphaning the FK', async () => {
      const db = makeDb({ clientWriteError: { message: 'write exploded' } });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
      expect(db.calls.transactionInserts).to.have.length(0);
    });

    it('does not leak the database error text to the browser', async () => {
      const db = makeDb({ insertError: { message: 'relation oauth_x does not exist' } });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(JSON.stringify(res.body)).to.not.contain('relation oauth_x');
    });
  });

  describe('each control is load-bearing on its own', () => {
    // A control is load-bearing when removing it — and nothing else — changes
    // the answer. The rate buckets get the same treatment in
    // test/oauthAuthorize.rateLimit.test.js.

    it('the redirect_uri check: the registered list is what decides', async () => {
      const attacker = 'https://attacker.example/steal';

      const refused = await request(makeApp().app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: attacker }));
      expect(refused.status).to.equal(400);

      // Same request, same code path, one difference: the client now
      // registers that URI. If this still 400s the check is not reading the
      // list; if the first one had passed the check does nothing.
      const allowed = await request(
        makeApp({ metadata: { ...CLIENT_METADATA, redirect_uris: [attacker] } }).app
      )
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: attacker }));
      expect(allowed.status).to.equal(302);
      expect(new URL(allowed.headers.location).origin).to.equal(FRONTEND_ORIGIN);
    });

    it('the client_type refusal: ticket 36 has no second gate of its own', async () => {
      // clientMetadataService is the ONLY thing refusing service_confidential
      // before the database. Removing it must let the request through — if it
      // does not, some duplicate check has grown here and the two will drift.
      const refused = await request(
        makeApp({ metadataFailure: 'client_type_not_dereferenceable' }).app
      )
        .get('/api/oauth/authorize')
        .query(validQuery());
      expect(refused.status).to.equal(400);

      const allowed = await request(makeApp().app).get('/api/oauth/authorize').query(validQuery());
      expect(allowed.status).to.equal(302);
    });

    it('the schema is the backstop: every row is written as assistant_public', async () => {
      // Because the refusal above lives in another module, the composite FK in
      // migration 002 is what makes "no confidential client reaches a
      // transaction" true regardless. This asserts ticket 36 always presents
      // the pair that FK checks.
      const db = makeDb();
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.calls.transactionInserts[0].client_type).to.equal('assistant_public');
      expect(db.calls.clientInserts[0].client_type).to.equal('assistant_public');
    });

    it('the S256 pin: only the exact string is accepted', async () => {
      const refused = await request(makeApp().app)
        .get('/api/oauth/authorize')
        .query(validQuery({ code_challenge_method: 's256' }));
      // Direct 400 now — this check moved above the fetch (see the deviation
      // note in authorizeTransactionService).
      expect(refused.status).to.equal(400);
      expect(refused.body.error).to.equal('invalid_request');

      const allowed = await request(makeApp().app)
        .get('/api/oauth/authorize')
        .query(validQuery({ code_challenge_method: 'S256' }));
      expect(new URL(allowed.headers.location).origin).to.equal(FRONTEND_ORIGIN);
    });
  });

  describe('the client row write never overwrites a non-assistant client', () => {
    const CONFIDENTIAL_ROW = {
      client_id: CLIENT_ID,
      client_type: 'service_confidential',
      token_endpoint_auth_method: 'private_key_jwt',
      display_name: 'NutriHelp MCP server',
      redirect_uris: null,
    };

    it('leaves an existing service_confidential row completely UNCHANGED', async () => {
      // The bug this replaces: an unconditional upsert on client_id turned the
      // MCP server's own confidential client into an assistant public client
      // with auth method 'none', silently breaking private_key_jwt.
      //
      // The CIMD confidential refusal does not defend this. That inspects the
      // fetched DOCUMENT; this is about the DATABASE ROW already stored under
      // the same key. Two different objects.
      const db = makeDb({ existingClient: CONFIDENTIAL_ROW });
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.clients).to.have.lengthOf(1);
      expect(db.clients[0]).to.deep.equal(CONFIDENTIAL_ROW);
    });

    it('refuses the request rather than proceeding on the conflicting row', async () => {
      const db = makeDb({ existingClient: CONFIDENTIAL_ROW });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
    });

    it('writes no transaction when the client row conflicts', async () => {
      const db = makeDb({ existingClient: CONFIDENTIAL_ROW });
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.calls.transactionInserts).to.have.length(0);
    });

    it('raises a security event for the conflict', async () => {
      const security = [];
      const db = makeDb({ existingClient: CONFIDENTIAL_ROW });
      const { app } = makeApp({
        db,
        log: {
          logOperational: async () => undefined,
          logGrantRefusal: async (ctx) => security.push(ctx),
        },
      });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(security).to.have.lengthOf(1);
      expect(security[0].detail).to.equal('client_conflicts_with_non_assistant_row');
    });

    it('filters the UPDATE on client_type, not just client_id', async () => {
      // The filter IS the control. A single .eq('client_id') would match the
      // confidential row and overwrite it.
      const db = makeDb({ existingClient: CONFIDENTIAL_ROW });
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      const [update] = db.calls.clientUpdates;
      expect(update.filters).to.deep.include(['client_id', CLIENT_ID]);
      expect(update.filters).to.deep.include(['client_type', 'assistant_public']);
    });

    it('UPDATES an existing assistant row in place rather than inserting', async () => {
      // The ordinary repeat-visit path: same client, already registered.
      const db = makeDb({
        existingClient: {
          client_id: CLIENT_ID,
          client_type: 'assistant_public',
          token_endpoint_auth_method: 'none',
          display_name: 'Stale Name',
          redirect_uris: ['https://claude.ai/old'],
        },
      });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(db.calls.clientInserts).to.have.length(0);
      expect(db.clients[0].display_name).to.equal('Claude');
      expect(db.clients[0].client_type).to.equal('assistant_public');
    });
  });

  describe('a concurrent first-sight insert is not mistaken for a conflict', () => {
    // 23505 means only "the client_id primary key is now occupied". It does
    // NOT say by whom. Two concurrent requests for the same brand-new
    // assistant both find nothing to update; one inserts, the other collides
    // with a row that is perfectly legitimately its own.
    const RACED_ROW = {
      client_id: CLIENT_ID,
      client_type: 'assistant_public',
      token_endpoint_auth_method: 'none',
      display_name: 'Claude',
      redirect_uris: [REDIRECT_URI, OTHER_REDIRECT_URI],
    };

    it('proceeds to the frontend instead of refusing the loser of the race', async () => {
      const db = makeDb({ concurrentInsertWins: RACED_ROW });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).origin).to.equal(FRONTEND_ORIGIN);
      expect([...queryOf(res.headers.location).keys()]).to.deep.equal(['transaction']);
    });

    it('raises NO security event for the race', async () => {
      // The sharp end: without the retry this writes a record asserting the
      // caller named a client id belonging to something else. A false positive
      // in the one sink that exists to flag real attack shapes.
      const security = [];
      const db = makeDb({ concurrentInsertWins: RACED_ROW });
      const { app } = makeApp({
        db,
        log: {
          logOperational: async () => undefined,
          logGrantRefusal: async (ctx) => security.push(ctx),
        },
      });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(security).to.have.lengthOf(0);
    });

    it('still writes the transaction after losing the race', async () => {
      const db = makeDb({ concurrentInsertWins: RACED_ROW });
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(db.calls.transactionInserts).to.have.length(1);
    });

    it('re-runs the UPDATE exactly once, never in a loop', async () => {
      const db = makeDb({ concurrentInsertWins: RACED_ROW });
      const { app } = makeApp({ db });

      await request(app).get('/api/oauth/authorize').query(validQuery());

      // One speculative update, one insert, one retry update.
      expect(db.calls.clientUpdates).to.have.lengthOf(2);
      expect(db.calls.clientInserts).to.have.lengthOf(1);
    });

    it('still refuses when the retry finds a genuinely non-assistant row', async () => {
      // Same 23505, different occupant — the retry is what tells them apart.
      const db = makeDb({
        concurrentInsertWins: {
          client_id: CLIENT_ID,
          client_type: 'service_confidential',
          token_endpoint_auth_method: 'private_key_jwt',
          display_name: 'NutriHelp MCP server',
          redirect_uris: null,
        },
      });
      const { app } = makeApp({ db });

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
      expect(db.calls.transactionInserts).to.have.length(0);
    });
  });

  describe('exactly one security event per attempt, across layers', () => {
    // Every other security-event case in this file doubles clientMetadataService
    // out entirely, so it only ever counts the CONTROLLER's emissions. That
    // cannot see a duplicate raised by the CIMD layer — which is precisely the
    // bug the ownership rule was introduced to fix. This case wires the REAL
    // clientMetadataService so the fix is actually pinned.
    const realClientMetadataService = require('../services/oauth/clientMetadataService');

    const confidentialLookupDb = () => ({
      from(table) {
        if (table === 'oauth_clients') {
          return {
            select: () => ({
              eq: () => ({
                maybeSingle: async () => ({
                  data: {
                    client_id: CLIENT_ID,
                    client_type: 'service_confidential',
                    is_active: true,
                  },
                  error: null,
                }),
              }),
            }),
          };
        }
        throw new Error(`unexpected table: ${table}`);
      },
    });

    it('writes ONE record when the CIMD layer refuses a confidential client', async () => {
      const security = [];
      const log = {
        logOperational: async () => undefined,
        logGrantRefusal: async (ctx) => security.push(ctx),
      };
      const deps = {
        supabase: confidentialLookupDb(),
        introspectionLog: log,
        clientMetadataService: realClientMetadataService,
        // Never reached — the client_type refusal precedes any fetch — but
        // stubbed so a regression makes a test fail rather than a real request.
        // fetchDocument ONLY. clientMetadataService calls parseClientIdUrl on
        // the module directly and routes just fetchDocument through deps, so a
        // parseClientIdUrl key here would never be consulted — and a later
        // test written to drive a parse rejection through it would silently
        // get the real parser and could go green for the wrong reason.
        safeMetadataFetch: {
          fetchDocument: async () => {
            throw new Error('the fetch must not be reached for a confidential client');
          },
        },
        oauthRateLimiters: {
          authorizeAddressLimiter: (req, res, next) => next(),
          metadataFetchClientLimiter: (req, res, next) => next(),
          mcpServiceAddressLimiter: (req, res, next) => next(),
        },
      };
      const app = express();
      app.use('/api/oauth', createOauthRouter(deps));

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(400);
      expect(security).to.have.lengthOf(1);
      expect(security[0].eventType).to.equal('mcp_client_metadata_dereference_refused');
    });
  });

  describe('state is bounded', () => {
    it('accepts a state at the cap', async () => {
      const { app } = makeApp();
      const state = 'a'.repeat(authorizeTransactionService.MAX_STATE_LENGTH);

      const res = await request(app).get('/api/oauth/authorize').query(validQuery({ state }));

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).origin).to.equal(FRONTEND_ORIGIN);
    });

    it('refuses a state over the cap with a direct 400', async () => {
      // Above the fetch, by the same taxonomy as response_type: state is the
      // client's OWN nonce, so an over-long one is a broken client.
      const { app } = makeApp();
      const state = 'a'.repeat(authorizeTransactionService.MAX_STATE_LENGTH + 1);

      const res = await request(app).get('/api/oauth/authorize').query(validQuery({ state }));

      expect(res.status).to.equal(400);
      expect(res.body.error).to.equal('invalid_request');
    });

    it('does not reflect the oversized state anywhere in the response', async () => {
      // Refused, not truncated — a silently shortened state fails the client's
      // own comparison. And redirecting it was futile anyway: the error could
      // not carry the offending state, and a client receiving an error with no
      // state cannot match it to a pending request and must drop it.
      const { app } = makeApp();
      const state = 'a'.repeat(authorizeTransactionService.MAX_STATE_LENGTH + 1);

      const res = await request(app).get('/api/oauth/authorize').query(validQuery({ state }));

      expect(res.headers.location).to.equal(undefined);
      expect(JSON.stringify(res.body)).to.not.contain('aaaa');
    });

    it('writes no transaction for an oversized state', async () => {
      const db = makeDb();
      const { app } = makeApp({ db });
      const state = 'a'.repeat(authorizeTransactionService.MAX_STATE_LENGTH + 1);

      await request(app).get('/api/oauth/authorize').query(validQuery({ state }));

      expect(db.calls.transactionInserts).to.have.length(0);
    });
  });

  describe('the outbound CIMD fetch is not paid for a malformed request', () => {
    // Blocker 3. These checks sit ABOVE the fetch deliberately, and answer 400
    // rather than redirecting, because delivering them as redirects would
    // require dereferencing a stranger-chosen URL first.
    const countingApp = () => {
      let fetches = 0;
      const deps = {
        supabase: makeDb(),
        introspectionLog: silentLog(),
        clientMetadataService: {
          fetchAndValidateClientMetadata: async () => {
            fetches += 1;
            return { ok: true, metadata: CLIENT_METADATA };
          },
        },
        oauthRateLimiters: {
          authorizeAddressLimiter: (req, res, next) => next(),
          metadataFetchClientLimiter: (req, res, next) => next(),
          mcpServiceAddressLimiter: (req, res, next) => next(),
        },
      };
      const app = express();
      app.use('/api/oauth', createOauthRouter(deps));
      return { app, fetchCount: () => fetches };
    };

    // Third element is the RFC 6749 §4.1.2.1 code. Asserting it is what makes
    // the absent-vs-unsupported response_type split observable: without it,
    // collapsing the two back into one branch would stay green.
    const MALFORMED = [
      ['a response_type that is not code', { response_type: 'token' }, 'unsupported_response_type'],
      ['an absent response_type', { response_type: undefined }, 'invalid_request'],
      ['an absent client_id', { client_id: undefined }, 'invalid_request'],
      ['an absent redirect_uri', { redirect_uri: undefined }, 'invalid_request'],
      ['an over-long state', { state: 'a'.repeat(4096) }, 'invalid_request'],
      ['a missing code_challenge', { code_challenge: undefined }, 'invalid_request'],
      ['a malformed code_challenge', { code_challenge: 'too short' }, 'invalid_request'],
      ['a downgraded code_challenge_method', { code_challenge_method: 'plain' }, 'invalid_request'],
      ['a missing code_challenge_method', { code_challenge_method: undefined }, 'invalid_request'],
    ];

    MALFORMED.forEach(([label, override, expectedError]) => {
      it(`makes no outbound fetch for ${label}`, async () => {
        const { app, fetchCount } = countingApp();

        const res = await request(app).get('/api/oauth/authorize').query(validQuery(override));

        expect(res.status).to.equal(400);
        expect(res.headers.location).to.equal(undefined);
        expect(res.body.error, `${label} must answer ${expectedError}`).to.equal(expectedError);
        expect(fetchCount(), 'a malformed request must cost no outbound fetch').to.equal(0);
      });
    });

    it('still fetches for a well-formed request', async () => {
      // The control: without this, "no fetch" could be true because nothing
      // ever fetches.
      const { app, fetchCount } = countingApp();

      await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(fetchCount()).to.equal(1);
    });

    it('still fetches for an error that must be DELIVERED to the client', async () => {
      // A bad scope is a working client asking for something we do not offer.
      // It stays below the boundary and costs a fetch, because the client has
      // to receive invalid_scope at its redirect_uri to act on it.
      const { app, fetchCount } = countingApp();

      const res = await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: 'nope:nope' }));

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('invalid_scope');
      expect(fetchCount()).to.equal(1);
    });
  });

  describe('telemetry actually reaches the sinks', () => {
    const makeSpyLog = () => {
      const operational = [];
      const security = [];
      return {
        operational,
        security,
        log: {
          logOperational: async (ctx) => {
            operational.push(ctx);
          },
          logGrantRefusal: async (ctx) => {
            security.push(ctx);
          },
        },
      };
    };

    it('writes a SECURITY record for an unregistered redirect_uri', async () => {
      // logOperational writes to the error log and drops eventType/resource
      // entirely, so naming a security event without calling the security sink
      // produces a constant that reads as though it works and records nothing.
      const spy = makeSpyLog();
      const { app } = makeApp({ log: spy.log });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: 'https://attacker.example/steal' }));

      expect(spy.security).to.have.lengthOf(1);
      expect(spy.security[0].eventType).to.equal('mcp_authorize_request_refused');
      expect(spy.security[0].detail).to.equal('redirect_uri_not_registered');
    });

    it('records the attempted client_id on the security record', async () => {
      // Under the amplification attack these buckets exist to bound, the
      // abused client_id is the most useful field there is.
      const spy = makeSpyLog();
      const { app } = makeApp({ log: spy.log });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ redirect_uri: 'https://attacker.example/steal' }));

      expect(spy.security[0].clientId).to.equal(CLIENT_ID);
    });

    it('records the attempted client_id on ordinary operational lines too', async () => {
      const spy = makeSpyLog();
      const { app } = makeApp({ log: spy.log });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: 'nope:nope' }));

      expect(spy.operational).to.have.length.greaterThan(0);
      expect(spy.operational[0].clientId).to.equal(CLIENT_ID);
    });

    it('does NOT raise a security event for an ordinary protocol error', async () => {
      // A bad scope from a client we already proved is not attack-shaped;
      // raising security events for those is how a sink becomes noise.
      const spy = makeSpyLog();
      const { app } = makeApp({ log: spy.log });

      await request(app)
        .get('/api/oauth/authorize')
        .query(validQuery({ scope: 'nope:nope' }));

      expect(spy.security).to.have.lengthOf(0);
    });

    it('passes correlationId and requestId down to the CIMD layer', async () => {
      // Without this the metadata_fetch_refused line carries correlation_id:
      // null and cannot be joined to the authorize refusal that caused it.
      let seenDeps = null;
      const correlationId = 'corr-abc-123';
      const deps = {
        supabase: makeDb(),
        introspectionLog: silentLog(),
        clientMetadataService: {
          fetchAndValidateClientMetadata: async (clientId, d) => {
            seenDeps = d;
            return { ok: true, metadata: CLIENT_METADATA };
          },
        },
        oauthRateLimiters: {
          authorizeAddressLimiter: (req, res, next) => next(),
          metadataFetchClientLimiter: (req, res, next) => next(),
          mcpServiceAddressLimiter: (req, res, next) => next(),
        },
      };
      const app = express();
      app.use('/api/oauth', createOauthRouter(deps));

      await request(app)
        .get('/api/oauth/authorize')
        .set('x-correlation-id', correlationId)
        .query(validQuery());

      expect(seenDeps).to.be.an('object');
      expect(seenDeps.correlationId).to.equal(correlationId);
      expect(seenDeps.requestId).to.be.a('string');
    });
  });

  describe('the frontend login path', () => {
    it('defaults to /login', async () => {
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(new URL(res.headers.location).pathname).to.equal('/login');
    });

    it('honours OAUTH_FRONTEND_LOGIN_PATH when set', async () => {
      process.env.OAUTH_FRONTEND_LOGIN_PATH = '/connect/consent';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(new URL(res.headers.location).pathname).to.equal('/connect/consent');
    });

    it('refuses a login path carrying a query, which would ride along in the redirect', async () => {
      // '/login?next=/x' would produce '?next=/x&transaction=...', breaking the
      // one property this redirect has to keep.
      process.env.OAUTH_FRONTEND_LOGIN_PATH = '/login?next=/x';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
    });

    it('refuses a login path carrying a fragment', async () => {
      process.env.OAUTH_FRONTEND_LOGIN_PATH = '/login#frag';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      expect(new URL(res.headers.location).searchParams.get('error')).to.equal('server_error');
    });

    it('keeps the single-key guarantee under a configured path', async () => {
      process.env.OAUTH_FRONTEND_LOGIN_PATH = '/connect/consent';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect([...queryOf(res.headers.location).keys()]).to.deep.equal(['transaction']);
    });

    it('refuses a protocol-relative login path', async () => {
      process.env.OAUTH_FRONTEND_LOGIN_PATH = '//attacker.example';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      expect(res.status).to.equal(302);
      const location = new URL(res.headers.location);
      expect(location.origin).to.equal('https://claude.ai');
      expect(location.searchParams.get('error')).to.equal('server_error');
    });

    // Tab, newline and carriage return are the three characters WHATWG URL
    // parsing strips out before parsing. Built from char codes, not written as
    // escapes: an escape that silently becomes a real line break on its way
    // through an editor or a patch turns this into a different, passing test.
    const CONTROL_CHARS = [
      ['tab', String.fromCharCode(9)],
      ['newline', String.fromCharCode(10)],
      ['carriage return', String.fromCharCode(13)],
    ];

    CONTROL_CHARS.forEach(([name, ch]) => {
      it(`refuses a login path made protocol-relative by an embedded ${name}`, async () => {
        // Measured: the value survives trim(), is not ? or #, and does not
        // start with '//', so readLoginPath RETURNS it — then new URL() strips
        // the control character and reads the result as protocol-relative,
        // resolving to https://attacker.example.
        //
        // So this pins the ORIGIN CHECK in the controller, not readLoginPath.
        // That check is the only thing refusing this input, and untested it
        // reads as redundant with readLoginPath — the obvious thing to delete
        // in a tidy-up, at which point the endpoint redirects off-origin.
        process.env.OAUTH_FRONTEND_LOGIN_PATH = `/${ch}/attacker.example`;
        const { app } = makeApp();

        const res = await request(app).get('/api/oauth/authorize').query(validQuery());

        // Delivered to the client, and crucially NOT to attacker.example.
        expect(res.status).to.equal(302);
        const location = new URL(res.headers.location);
        expect(location.origin).to.equal('https://claude.ai');
        expect(location.searchParams.get('error')).to.equal('server_error');
      });
    });

    it('confirms readLoginPath alone would NOT catch those', () => {
      // Says why the cases above are not redundant: readLoginPath returns the
      // value happily. If this ever starts returning null, the origin check is
      // no longer the thing under test and those comments have gone stale.
      const controller = require('../controller/oauthAuthorizeController');
      CONTROL_CHARS.forEach(([name, ch]) => {
        process.env.OAUTH_FRONTEND_LOGIN_PATH = `/${ch}/attacker.example`;
        expect(
          controller.readLoginPath(),
          `${name} is filtered by the origin check, not by readLoginPath`
        ).to.not.equal(null);
      });
    });

    it('refuses an absolute OAUTH_FRONTEND_LOGIN_PATH rather than redirecting off-origin', async () => {
      process.env.OAUTH_FRONTEND_LOGIN_PATH = 'https://attacker.example/login';
      const { app } = makeApp();

      const res = await request(app).get('/api/oauth/authorize').query(validQuery());

      // Refused, and now refused TO THE CLIENT — but never to attacker.example.
      expect(res.status).to.equal(302);
      const location = new URL(res.headers.location);
      expect(location.origin).to.equal('https://claude.ai');
      expect(location.searchParams.get('error')).to.equal('server_error');
    });
  });
});
