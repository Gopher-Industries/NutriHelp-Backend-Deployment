// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const express = require('express');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { createOauthRouter } = require('../routes/oauth');
const clientAssertionVerifier = require('../services/oauth/clientAssertionVerifier');

/** POST /api/oauth/token - RFC 8693 exchange (ticket 39a). Assert status, not body alone. */

const ISSUER = 'https://api.nutrihelp.test';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const BACKEND_API_AUDIENCE = 'https://api.nutrihelp.test/api';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';
const USER_ID = 42;

const EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const asPem = {
  private: asKey.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: asKey.publicKey.export({ type: 'spki', format: 'pem' }),
};

const mcpKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const mcpPem = {
  private: mcpKey.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: mcpKey.publicKey.export({ type: 'spki', format: 'pem' }),
};

const foreignKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const FOREIGN_PRIVATE_PEM = foreignKey.privateKey.export({ type: 'pkcs8', format: 'pem' });

const ACTIVE_GRANT = {
  grant_id: GRANT_ID,
  user_id: USER_ID,
  client_id: ASSISTANT_CLIENT_ID,
  resource: MCP_RESOURCE,
  scopes: 'nutrition:read mealplan:read',
  status: 'active',
};

/** No role_name default — the fail-closed case needs its absence to be real. */
const USER_WITH_ROLE = { user_id: USER_ID, role_id: 7, user_roles: { role_name: 'user' } };

const mintAccessToken = (overrides = {}, key = asPem.private) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: ISSUER,
      aud: MCP_RESOURCE,
      sub: String(USER_ID),
      type: 'mcp_access',
      scope: 'nutrition:read mealplan:read',
      client_id: ASSISTANT_CLIENT_ID,
      grant_id: GRANT_ID,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
      ...overrides,
    },
    key,
    { algorithm: 'RS256', keyid: 'as-key-1' }
  );
};

const makeDb = ({
  grant = ACTIVE_GRANT,
  user = USER_WITH_ROLE,
  clientKeyPem = mcpPem.public,
} = {}) => {
  const calls = { grantLookups: 0, userLookups: 0, jtiInserts: 0 };

  return {
    calls,
    from(table) {
      if (table === 'mcp_client_grants') {
        return {
          select: () => ({
            eq: () => ({
              maybeSingle: async () => {
                calls.grantLookups += 1;
                return { data: grant, error: null };
              },
            }),
          }),
        };
      }

      if (table === 'users') {
        return {
          select: () => ({
            eq: () => ({
              maybeSingle: async () => {
                calls.userLookups += 1;
                return { data: user, error: null };
              },
            }),
          }),
        };
      }

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
            data: [{ kid: null, alg: 'RS256', public_key_pem: clientKeyPem, slot: 1 }],
            error: null,
          }),
        };
        return chain;
      }

      if (table === 'oauth_client_assertion_jti') {
        return {
          insert: async () => {
            calls.jtiInserts += 1;
            return { error: null };
          },
          delete: () => ({
            lt: () => ({ order: () => ({ limit: async () => ({ error: null }) }) }),
          }),
        };
      }

      throw new Error(`unexpected table: ${table}`);
    },
  };
};

const configDouble = (overrides = {}) => ({
  mcpAccessTokenIssuer: () => ISSUER,
  mcpResourceIdentifier: () => MCP_RESOURCE,
  backendApiAudience: () => BACKEND_API_AUDIENCE,
  tokenEndpointAudience: () => TOKEN_URL,
  introspectionAudience: () => INTROSPECTION_URL,
  frontendOrigin: () => 'https://app.nutrihelp.test',
  ...overrides,
});

const silentLog = () => ({ logOperational: async () => {}, logGrantRefusal: async () => {} });

const makeApp = ({
  db = makeDb(),
  config = {},
  authentication = { ok: true, clientId: MCP_CLIENT_ID },
  assertionVerifier,
  log,
  signingKey,
} = {}) => {
  const deps = {
    supabase: db,
    clientAssertionVerifier: assertionVerifier || {
      verifyClientAssertion: async () => authentication,
    },
    asVerificationKeys: {
      getVerificationKeys: () => [{ kid: 'as-key-1', alg: 'RS256', publicKeyPem: asPem.public }],
    },
    asSigningKey: signingKey || {
      getSigningKey: () => ({
        ok: true,
        key: {
          kid: 'as-key-1',
          alg: 'RS256',
          privateKeyPem: asPem.private,
          publicKeyPem: asPem.public,
        },
      }),
    },
    oauthConfig: configDouble(config),
    introspectionLog: log || silentLog(),
  };

  const app = express();
  app.use('/api/oauth', createOauthRouter(deps));
  return app;
};

const exchangeForm = (overrides = {}) => ({
  grant_type: EXCHANGE_GRANT_TYPE,
  subject_token: mintAccessToken(),
  subject_token_type: ACCESS_TOKEN_TYPE,
  client_assertion_type: ASSERTION_TYPE,
  client_assertion: 'verified-by-the-authentication-double',
  ...overrides,
});

const post = (app, body = exchangeForm()) =>
  request(app).post('/api/oauth/token').type('form').send(body);

const credentialClaims = (response) =>
  jwt.verify(response.body.access_token, asPem.public, {
    algorithms: ['RS256'],
    issuer: ISSUER,
    audience: BACKEND_API_AUDIENCE,
  });

describe('POST /api/oauth/token', () => {
  describe('grant type dispatch', () => {
    it('exchanges on the RFC 8693 grant type', async () => {
      const response = await post(makeApp());

      expect(response.status).to.equal(200);
      expect(response.body.access_token).to.be.a('string');
    });

    it('answers 400 unsupported_grant_type for an unknown grant type', async () => {
      const response = await post(makeApp(), exchangeForm({ grant_type: 'client_credentials' }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('unsupported_grant_type');
    });

    it('answers 400 unsupported_grant_type for authorization_code — ticket 39b', async () => {
      const response = await post(makeApp(), exchangeForm({ grant_type: 'authorization_code' }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('unsupported_grant_type');
    });

    it('answers 400 unsupported_grant_type for refresh_token — ticket 39b', async () => {
      const response = await post(makeApp(), exchangeForm({ grant_type: 'refresh_token' }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('unsupported_grant_type');
    });

    it('answers 400 invalid_request for an absent grant type', async () => {
      const response = await post(makeApp(), exchangeForm({ grant_type: undefined }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('does not authenticate the client before knowing the grant type is supported', async () => {
      const db = makeDb();
      await post(makeApp({ db }), exchangeForm({ grant_type: 'client_credentials' }));

      expect(db.calls.jtiInserts).to.equal(0);
    });
  });

  describe('the successful response (RFC 8693 §2.2.1)', () => {
    it('returns the credential as access_token with a Bearer token_type', async () => {
      const response = await post(makeApp());

      expect(response.status).to.equal(200);
      expect(response.body.token_type).to.equal('Bearer');
    });

    it('names the issued token type', async () => {
      const response = await post(makeApp());

      expect(response.body.issued_token_type).to.equal(ACCESS_TOKEN_TYPE);
    });

    it('reports a 120 second expires_in', async () => {
      const response = await post(makeApp());

      expect(response.body.expires_in).to.equal(120);
    });

    it('returns the granted scope', async () => {
      const response = await post(makeApp());

      expect(response.body.scope).to.equal('nutrition:read mealplan:read');
    });

    it('issues a credential this deployment can verify', async () => {
      const response = await post(makeApp());

      expect(() => credentialClaims(response)).to.not.throw();
      expect(credentialClaims(response).type).to.equal('mcp_upstream');
    });

    it('carries the live role, the grant id and the actor', async () => {
      const claims = credentialClaims(await post(makeApp()));

      expect(claims.role).to.equal('user');
      expect(claims.grant_id).to.equal(GRANT_ID);
      expect(claims.act.sub).to.equal(MCP_CLIENT_ID);
    });

    it('sets Cache-Control: no-store (RFC 6749 §5.1)', async () => {
      const response = await post(makeApp());

      expect(response.headers['cache-control']).to.contain('no-store');
    });

    it('answers application/json', async () => {
      const response = await post(makeApp());

      expect(response.headers['content-type']).to.match(/application\/json/);
    });

    it('never redirects — the caller sets redirect:error, so any 3xx hard-fails', async () => {
      const response = await request(makeApp())
        .post('/api/oauth/token/')
        .type('form')
        .send(exchangeForm());

      expect(response.status).to.not.be.within(300, 399);
    });
  });

  describe('client authentication — 401 invalid_client', () => {
    it('answers 401 invalid_client when the private_key_jwt fails', async () => {
      const app = makeApp({
        authentication: { ok: false, httpStatus: 401, reason: 'invalid_client', detail: 'x' },
      });

      const response = await post(app);

      expect(response.status).to.equal(401);
      expect(response.body.error).to.equal('invalid_client');
    });

    it('never mints when client authentication failed', async () => {
      const db = makeDb();
      const app = makeApp({
        db,
        authentication: { ok: false, httpStatus: 401, reason: 'invalid_client', detail: 'x' },
      });

      await post(app);

      expect(db.calls.grantLookups).to.equal(0);
      expect(db.calls.userLookups).to.equal(0);
    });

    it('answers 503 when client authentication could not be established', async () => {
      const app = makeApp({
        authentication: { ok: false, httpStatus: 503, reason: 'server_error', detail: 'x' },
      });

      const response = await post(app);

      expect(response.status).to.equal(503);
    });
  });

  describe('token endpoint error vocabulary — RFC 6749 §5.2 plus invalid_target', () => {
    it('answers 400 invalid_grant for a revoked grant — NOT 200 active:false', async () => {
      const app = makeApp({ db: makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } }) });

      const response = await post(app);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
      expect(response.body).to.not.have.property('active');
    });

    it('answers 400 invalid_grant for an unknown grant', async () => {
      const app = makeApp({ db: makeDb({ grant: null }) });

      const response = await post(app);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('answers 400 invalid_grant for a forged subject token', async () => {
      const response = await post(
        makeApp(),
        exchangeForm({ subject_token: mintAccessToken({}, FOREIGN_PRIVATE_PEM) })
      );

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('answers 400 invalid_grant — not 500 — when the role does not resolve', async () => {
      const app = makeApp({ db: makeDb({ user: { user_id: USER_ID, role_id: 7 } }) });

      const response = await post(app);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('answers 400 invalid_request for a malformed request', async () => {
      const response = await post(makeApp(), exchangeForm({ subject_token: undefined }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('answers 400 invalid_scope when the requested scope exceeds the grant', async () => {
      const response = await post(makeApp(), exchangeForm({ scope: 'meallog:write' }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_scope');
    });

    it('never answers 403 insufficient_scope', async () => {
      const response = await post(makeApp(), exchangeForm({ scope: 'meallog:write' }));

      expect(response.status).to.not.equal(403);
      expect(response.body.error).to.not.equal('insufficient_scope');
    });

    it('answers 400 invalid_scope for a REPEATED scope parameter exceeding the grant', async () => {
      // On the wire, not through an object: express.urlencoded({extended:false})
      const body = [
        `grant_type=${encodeURIComponent(EXCHANGE_GRANT_TYPE)}`,
        `subject_token=${encodeURIComponent(mintAccessToken())}`,
        `subject_token_type=${encodeURIComponent(ACCESS_TOKEN_TYPE)}`,
        `client_assertion_type=${encodeURIComponent(ASSERTION_TYPE)}`,
        'client_assertion=verified-by-the-authentication-double',
        'scope=nutrition%3Aread',
        'scope=meallog%3Awrite',
      ].join('&');

      const response = await request(makeApp()).post('/api/oauth/token').type('form').send(body);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_scope');
      expect(response.body.access_token).to.equal(undefined);
    });

    it('answers 400 invalid_target for a resource this server will not issue for', async () => {
      const response = await post(
        makeApp(),
        exchangeForm({ resource: 'https://elsewhere.example/api' })
      );

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_target');
    });

    it('answers 503 when the signing key is unavailable', async () => {
      const app = makeApp({
        signingKey: { getSigningKey: () => ({ ok: false, detail: 'signing_key_unconfigured' }) },
      });

      const response = await post(app);

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('never puts a credential in an error response', async () => {
      const app = makeApp({ db: makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } }) });

      const response = await post(app);

      expect(response.body.access_token).to.equal(undefined);
    });

    it('sets no-store on error responses too', async () => {
      const app = makeApp({ db: makeDb({ grant: null }) });

      const response = await post(app);

      expect(response.headers['cache-control']).to.contain('no-store');
    });
  });

  describe('the security anomaly', () => {
    it('logs an anomaly when a token signed by OUR key is still refused', async () => {
      const events = [];
      const app = makeApp({
        db: makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } }),
        log: { logOperational: async () => {}, logGrantRefusal: async (c) => events.push(c) },
      });

      await post(app);

      expect(events).to.have.lengthOf(1);
      expect(events[0].userId).to.equal(USER_ID);
    });

    it('does NOT log an anomaly for a forged subject token', async () => {
      const events = [];
      const app = makeApp({
        log: { logOperational: async () => {}, logGrantRefusal: async (c) => events.push(c) },
      });

      await post(app, exchangeForm({ subject_token: mintAccessToken({}, FOREIGN_PRIVATE_PEM) }));

      expect(events).to.have.lengthOf(0);
    });

    it('carries the token endpoint as the security record resource', async () => {
      const events = [];
      const app = makeApp({
        db: makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } }),
        log: { logOperational: async () => {}, logGrantRefusal: async (c) => events.push(c) },
      });

      await post(app);

      expect(events[0].resource).to.equal('POST /api/oauth/token');
      expect(events[0].eventType).to.not.equal('mcp_introspection_grant_inactive');
    });

    it('carries the token endpoint identity on operational records', async () => {
      const records = [];
      const app = makeApp({
        db: makeDb({ grant: null }),
        log: { logOperational: async (c) => records.push(c), logGrantRefusal: async () => {} },
      });

      await post(app);

      expect(records.length).to.be.greaterThan(0);
      expect(records[0].endpoint).to.equal('POST /api/oauth/token');
      expect(records[0].errorPrefix).to.equal('oauth_token');
    });

    it('never logs the subject token or the client assertion', async () => {
      const records = [];
      const app = makeApp({
        db: makeDb({ grant: null }),
        log: {
          logOperational: async (c) => records.push(c),
          logGrantRefusal: async (c) => records.push(c),
        },
      });
      const body = exchangeForm();

      await post(app, body);

      const serialised = JSON.stringify(records);
      expect(serialised).to.not.contain(body.subject_token);
      expect(serialised).to.not.contain(body.client_assertion);
    });
  });

  describe('composition — the real assertion verifier is wired to THIS endpoint', () => {
    const signAssertion = (overrides = {}) => {
      const now = Math.floor(Date.now() / 1000);
      return jwt.sign(
        {
          iss: MCP_CLIENT_ID,
          sub: MCP_CLIENT_ID,
          aud: TOKEN_URL,
          jti: crypto.randomUUID(),
          iat: now,
          exp: now + 60,
          ...overrides,
        },
        mcpPem.private,
        { algorithm: 'RS256' }
      );
    };

    const realApp = (options = {}) =>
      makeApp({ ...options, assertionVerifier: clientAssertionVerifier });

    it('accepts an assertion minted for the token endpoint', async () => {
      const response = await post(realApp(), exchangeForm({ client_assertion: signAssertion() }));

      expect(response.status).to.equal(200);
    });

    it('REFUSES an assertion minted for the sibling introspection endpoint', async () => {
      const response = await post(
        realApp(),
        exchangeForm({ client_assertion: signAssertion({ aud: INTROSPECTION_URL }) })
      );

      expect(response.status).to.equal(401);
      expect(response.body.error).to.equal('invalid_client');
    });

    it('answers 503 when the token endpoint audience is unconfigured', async () => {
      const response = await post(
        realApp({ config: { tokenEndpointAudience: () => null } }),
        exchangeForm({ client_assertion: signAssertion() })
      );

      expect(response.status).to.equal(503);
    });

    it('does not accept introspection assertions when its own audience is unset', async () => {
      const response = await post(
        realApp({ config: { tokenEndpointAudience: () => null } }),
        exchangeForm({ client_assertion: signAssertion({ aud: INTROSPECTION_URL }) })
      );

      expect(response.status).to.not.equal(200);
    });

    it('writes the jti to the shared replay store', async () => {
      const db = makeDb();

      await post(realApp({ db }), exchangeForm({ client_assertion: signAssertion() }));

      expect(db.calls.jtiInserts).to.equal(1);
    });

    it('refuses the exchange grant from a caller that presented no assertion', async () => {
      const db = makeDb();

      const response = await post(realApp({ db }), exchangeForm({ client_assertion: undefined }));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
      // Nothing minted, and nothing about the subject token was even looked up.
      expect(response.body.access_token).to.equal(undefined);
      expect(db.calls.grantLookups).to.equal(0);
      expect(db.calls.userLookups).to.equal(0);
      expect(db.calls.jtiInserts).to.equal(0);
    });

    it('refuses the exchange grant when the assertion is signed by the wrong key', async () => {
      const db = makeDb();
      const forged = jwt.sign(
        {
          iss: MCP_CLIENT_ID,
          sub: MCP_CLIENT_ID,
          aud: TOKEN_URL,
          jti: crypto.randomUUID(),
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 60,
        },
        FOREIGN_PRIVATE_PEM,
        { algorithm: 'RS256' }
      );

      const response = await post(realApp({ db }), exchangeForm({ client_assertion: forged }));

      expect(response.status).to.equal(401);
      expect(response.body.error).to.equal('invalid_client');
      expect(response.body.access_token).to.equal(undefined);
      expect(db.calls.grantLookups).to.equal(0);
    });
  });

  describe('the introspection endpoint still works beside it', () => {
    it('leaves POST /api/oauth/introspect mounted', async () => {
      const response = await request(makeApp()).post('/api/oauth/introspect').type('form').send({
        token: mintAccessToken(),
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: 'verified-by-the-authentication-double',
      });

      expect(response.status).to.equal(200);
      expect(response.body.active).to.equal(true);
    });
  });
});
