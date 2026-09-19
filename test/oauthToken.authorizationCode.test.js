// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const { createOauthRouter } = require('../routes/oauth');
const mcpAccessTokenVerifier = require('../services/oauth/mcpAccessTokenVerifier');
const { makeDb } = require('./helpers/oauthGrantTablesDouble');

/**
 * POST /api/oauth/token — authorization_code + PKCE (ticket 39b).
 * Public client: no client_assertion; PKCE is the proof.
 */

const express = require('express');

const ISSUER = 'https://api.nutrihelp.test';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const BACKEND_API_AUDIENCE = 'https://api.nutrihelp.test/api';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';
const USER_ID = 42;

const AUTHORIZATION_CODE_GRANT_TYPE = 'authorization_code';

const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const AS_PRIVATE_PEM = asKey.privateKey.export({ type: 'pkcs8', format: 'pem' });
const AS_PUBLIC_PEM = asKey.publicKey.export({ type: 'spki', format: 'pem' });
const AS_KID = 'as-key-1';

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
const base64Url = (buffer) => buffer.toString('base64url');
const s256Challenge = (verifier) =>
  base64Url(crypto.createHash('sha256').update(verifier).digest());

const RAW_CODE = 'a'.repeat(32) + 'b'.repeat(32);
const CODE_VERIFIER = 'VerifierThatIsLongEnoughForRfc7636-abcdefghijklmnop';

const secondsFromNow = (seconds) => new Date(Date.now() + seconds * 1000).toISOString();

const codeRow = (overrides = {}) => ({
  id: 501,
  code_hash: sha256Hex(RAW_CODE),
  grant_id: GRANT_ID,
  client_id: ASSISTANT_CLIENT_ID,
  client_type: 'assistant_public',
  user_id: USER_ID,
  redirect_uri: REDIRECT_URI,
  resource: MCP_RESOURCE,
  scopes: ['nutrition:read', 'mealplan:read'],
  code_challenge: s256Challenge(CODE_VERIFIER),
  consumed_at: null,
  expires_at: secondsFromNow(60),
  created_at: new Date().toISOString(),
  ...overrides,
});

const grantRow = (overrides = {}) => ({
  grant_id: GRANT_ID,
  user_id: USER_ID,
  client_id: ASSISTANT_CLIENT_ID,
  resource: MCP_RESOURCE,
  scopes: ['nutrition:read', 'mealplan:read'],
  status: 'active',
  ...overrides,
});

const configDouble = (overrides = {}) => ({
  mcpAccessTokenIssuer: () => ISSUER,
  mcpResourceIdentifier: () => MCP_RESOURCE,
  backendApiAudience: () => BACKEND_API_AUDIENCE,
  tokenEndpointAudience: () => TOKEN_URL,
  introspectionAudience: () => INTROSPECTION_URL,
  frontendOrigin: () => 'https://app.nutrihelp.test',
  ...overrides,
});

const signingKeyDouble = {
  getSigningKey: () => ({ ok: true, key: { kid: AS_KID, privateKeyPem: AS_PRIVATE_PEM } }),
};

const verificationKeysDouble = {
  getVerificationKeys: () => [{ kid: AS_KID, publicKeyPem: AS_PUBLIC_PEM, alg: 'RS256' }],
};

const buildApp = (db, configOverrides = {}) => {
  const app = express();
  app.use(
    '/api/oauth',
    createOauthRouter({
      supabase: db,
      oauthConfig: configDouble(configOverrides),
      asSigningKey: signingKeyDouble,
      asVerificationKeys: verificationKeysDouble,
      introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
      oauthRateLimiters: {
        authorizeAddressLimiter: (req, res, next) => next(),
        metadataFetchClientLimiter: (req, res, next) => next(),
      },
    })
  );
  return app;
};

const postCode = (app, body = {}) =>
  request(app)
    .post('/api/oauth/token')
    .type('form')
    .send({
      grant_type: AUTHORIZATION_CODE_GRANT_TYPE,
      code: RAW_CODE,
      code_verifier: CODE_VERIFIER,
      redirect_uri: REDIRECT_URI,
      client_id: ASSISTANT_CLIENT_ID,
      ...body,
    });

describe('POST /api/oauth/token — authorization_code + PKCE (ticket 39b)', () => {
  describe('the happy path', () => {
    it('issues an access token and a refresh token for a valid code and verifier', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(200);
      expect(response.body.token_type).to.equal('Bearer');
      expect(response.body.access_token).to.be.a('string');
      expect(response.body.refresh_token).to.be.a('string');
      expect(response.body.expires_in).to.be.a('number');
      expect(response.body.scope).to.equal('nutrition:read mealplan:read');
    });

    it('issues an access token the real MCP verifier accepts', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db));

      // Verifier over real output is the claim-set assertion.
      const verified = mcpAccessTokenVerifier.verifyMcpAccessToken(response.body.access_token, {
        asVerificationKeys: verificationKeysDouble,
        oauthConfig: configDouble(),
      });

      expect(verified.ok, verified.detail).to.equal(true);
      expect(verified.claims.type).to.equal('mcp_access');
      expect(verified.claims.sub).to.equal(String(USER_ID));
      expect(verified.claims.grant_id).to.equal(GRANT_ID);
      expect(verified.claims.client_id).to.equal(ASSISTANT_CLIENT_ID);
      expect(verified.claims.jti).to.be.a('string');
    });

    it('sets the access token aud from the code row, not from configuration', async () => {
      // aud from code row, not config — wrong resource must not be rewritten.
      const otherResource = 'https://other.nutrihelp.test/mcp';
      const db = makeDb({
        codes: [codeRow({ resource: otherResource })],
        grants: [grantRow({ resource: otherResource })],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(200);
      expect(jwt.decode(response.body.access_token).aud).to.equal(otherResource);
    });

    it('answers with Cache-Control no-store', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db));

      expect(response.headers['cache-control']).to.equal('no-store');
    });

    it('ignores a client_assertion instead of requiring one', async () => {
      // Junk assertion proves IGNORED (undefined would be dropped by supertest).
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), {
        client_assertion: 'not.a.jwt',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      });

      expect(response.status).to.equal(200);
    });
  });

  describe('single use', () => {
    it('marks the code consumed', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      await postCode(buildApp(db));

      expect(db.tables.oauth_authorization_codes[0].consumed_at).to.be.a('string');
    });

    it('refuses a code that was already consumed', async () => {
      const db = makeDb({
        codes: [codeRow({ consumed_at: new Date().toISOString() })],
        grants: [grantRow()],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses the second presentation of one code', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const app = buildApp(db);

      const first = await postCode(app);
      const second = await postCode(app);

      expect(first.status).to.equal(200);
      expect(second.status).to.equal(400);
      expect(second.body.error).to.equal('invalid_grant');
    });

    it('refuses when another request consumes the code between our read and our write', async () => {
      // Concurrent consume between read and write — only conditional update notices.
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        consumeCodeAfterRead: true,
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(0);
    });

    it('revokes the grant when a consumed code is replayed', async () => {
      // RFC 6749 §4.1.2 — same primitive as refresh reuse.
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const app = buildApp(db);

      await postCode(app);
      await postCode(app);

      expect(db.tables.mcp_client_grants[0].status).to.equal('revoked');
    });

    it('does not revoke when a consumed code is replayed with bindings that do not match', async () => {
      // Unauthentic replay must not revoke (forced-disconnect if it did).
      const db = makeDb({
        codes: [codeRow({ consumed_at: new Date().toISOString() })],
        grants: [grantRow()],
      });
      const response = await postCode(buildApp(db), {
        code_verifier: 'Q'.repeat(43),
        client_id: 'https://evil.test/client',
        redirect_uri: 'https://evil.test/callback',
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
    });

    it('does not revoke when a consumed code is replayed with a wrong verifier', async () => {
      // Wrong verifier with matching client/redirect is still unauthentic.
      const db = makeDb({
        codes: [codeRow({ consumed_at: new Date().toISOString() })],
        grants: [grantRow()],
      });
      const response = await postCode(buildApp(db), {
        code_verifier: 'AnotherVerifierLongEnoughForRfc7636-abcdefghijklmn',
      });

      expect(response.status).to.equal(400);
      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
    });

    it('answers 503 when an authentic replay cannot be revoked', async () => {
      // Failed revoke → 503, not invalid_grant (tokens may still be live).
      const db = makeDb({
        codes: [codeRow({ consumed_at: new Date().toISOString() })],
        grants: [grantRow()],
        failures: { 'mcp_client_grants.update': { code: '08006' } },
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('revokes the refresh family issued by a code that is then replayed', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const app = buildApp(db);

      await postCode(app);
      await postCode(app);

      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(1);
      expect(db.tables.oauth_refresh_tokens[0].revoked_at).to.be.a('string');
    });
  });

  describe('re-consent supersedes the previous families', () => {
    it('revokes refresh tokens issued by an earlier consent', async () => {
      // Re-consent upserts same grant — prior families must be swept (Backend Lead).
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const app = buildApp(db);

      const first = await postCode(app);
      expect(first.status).to.equal(200);

      // Fresh code, same grant_id.
      db.tables.oauth_authorization_codes.push(codeRow({ id: 502 }));
      db.tables.oauth_authorization_codes[0].consumed_at = null;
      db.tables.oauth_authorization_codes.shift();
      const second = await postCode(app);

      expect(second.status).to.equal(200);
      const [older, newer] = db.tables.oauth_refresh_tokens;
      expect(older.revoked_at).to.be.a('string');
      expect(older.revoke_reason).to.equal('superseded_by_reconsent');
      expect(newer.revoked_at === null || newer.revoked_at === undefined).to.equal(true);
    });

    it('leaves the grant active — re-consent is not revocation', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const app = buildApp(db);

      await postCode(app);
      db.tables.oauth_authorization_codes.push(codeRow({ id: 502 }));
      db.tables.oauth_authorization_codes.shift();
      await postCode(app);

      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
    });

    it('issues nothing when the previous families cannot be revoked', async () => {
      // Sweep failure must not leave old + new families both live.
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        failures: { 'oauth_refresh_tokens.update': { code: '08006' } },
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(503);
      expect(response.body.access_token).to.equal(undefined);
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(0);
    });
  });

  describe('PKCE', () => {
    it('refuses a verifier that does not hash to the stored challenge', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), {
        code_verifier: 'WrongVerifierButStillLongEnoughForRfc7636-abcdefgh',
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a plain code_verifier match — S256 is the only method', async () => {
      // S256 only — challenge == verifier is what method=plain would store.
      const db = makeDb({
        codes: [codeRow({ code_challenge: CODE_VERIFIER })],
        grants: [grantRow()],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a code_verifier shorter than RFC 7636 allows', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), { code_verifier: 'tooshort' });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('refuses a code_verifier outside the RFC 7636 character set', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), {
        code_verifier: `bad chars here${'x'.repeat(40)}`,
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('refuses a request with no code_verifier at all', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), { code_verifier: '' });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });
  });

  describe('binding checks', () => {
    it('refuses an unknown code', async () => {
      const db = makeDb({ codes: [], grants: [grantRow()] });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses an expired code', async () => {
      const db = makeDb({
        codes: [codeRow({ expires_at: secondsFromNow(-1) })],
        grants: [grantRow()],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a redirect_uri that differs from the one bound to the code', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), {
        redirect_uri: 'https://claude.ai/api/mcp/other_callback',
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a client_id that differs from the one bound to the code', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), { client_id: 'https://evil.test/client' });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses when the grant behind the code is no longer active', async () => {
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow({ status: 'revoked' })],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses when the grant and the code disagree about the user', async () => {
      // Schema does not bind code↔grant user/client/resource.
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow({ user_id: 999 })],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses when the grant and the code disagree about the resource', async () => {
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow({ resource: 'https://other.nutrihelp.test/mcp' })],
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a request with no code', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db), { code: '' });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });
  });

  describe('the first refresh family', () => {
    it('opens a family whose root has no parent', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      await postCode(buildApp(db));

      const [root] = db.tables.oauth_refresh_tokens;
      expect(root.parent_id === null || root.parent_id === undefined).to.equal(true);
      expect(root.family_id).to.be.a('string');
    });

    it('copies the code row bindings onto the refresh token', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      await postCode(buildApp(db));

      const [root] = db.tables.oauth_refresh_tokens;
      expect(root.grant_id).to.equal(GRANT_ID);
      expect(root.user_id).to.equal(USER_ID);
      expect(root.client_id).to.equal(ASSISTANT_CLIENT_ID);
      expect(root.resource).to.equal(MCP_RESOURCE);
    });

    it('stores the refresh token hashed, never in the clear', async () => {
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
      const response = await postCode(buildApp(db));

      const [root] = db.tables.oauth_refresh_tokens;
      const raw = response.body.refresh_token;
      expect(root.token_hash).to.be.a('string');
      expect(root.token_hash).to.not.equal(raw);
      expect(root.lookup_hash).to.not.equal(raw);
      // lookup_hash ≠ token_hash (domain separation).
      expect(root.token_hash).to.not.equal(root.lookup_hash);
      expect(JSON.stringify(db.tables.oauth_refresh_tokens)).to.not.contain(raw);
    });
  });

  describe('database failure', () => {
    it('answers 503 server_error when the code lookup fails', async () => {
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        failures: { 'oauth_authorization_codes.select': { code: '08006' } },
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('issues nothing when the refresh token insert fails', async () => {
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        failures: { 'oauth_refresh_tokens.insert': { code: '08006' } },
      });
      const response = await postCode(buildApp(db));

      expect(response.status).to.equal(503);
      expect(response.body.access_token).to.equal(undefined);
    });
  });
});
