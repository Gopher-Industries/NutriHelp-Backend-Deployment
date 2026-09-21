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
const mcpAccessTokenVerifier = require('../services/oauth/mcpAccessTokenVerifier');
const refreshTokenStore = require('../services/oauth/refreshTokenStore');
const { makeDb } = require('./helpers/oauthGrantTablesDouble');

/**
 * POST /api/oauth/token — rotating refresh_token (ticket 39b).
 *
 * Families built via the real endpoint (code then rotate) — no hand-built
 * hashed rows. Fixtures use three generations; reuse presents the middle token
 * so a sweep must reach ancestors, not just the presented row + child.
 */

const ISSUER = 'https://api.nutrihelp.test';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const BACKEND_API_AUDIENCE = 'https://api.nutrihelp.test/api';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';
const USER_ID = 42;

const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const AS_PRIVATE_PEM = asKey.privateKey.export({ type: 'pkcs8', format: 'pem' });
const AS_PUBLIC_PEM = asKey.publicKey.export({ type: 'spki', format: 'pem' });
const AS_KID = 'as-key-1';

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
const s256Challenge = (verifier) =>
  crypto.createHash('sha256').update(verifier).digest().toString('base64url');

const RAW_CODE = 'c'.repeat(32) + 'd'.repeat(32);
const CODE_VERIFIER = 'VerifierThatIsLongEnoughForRfc7636-abcdefghijklmnop';

const secondsFromNow = (seconds) => new Date(Date.now() + seconds * 1000).toISOString();

const codeRow = () => ({
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

const buildApp = (db, extraDeps = {}) => {
  const app = express();
  app.use(
    '/api/oauth',
    createOauthRouter({
      ...extraDeps,
      supabase: db,
      oauthConfig: configDouble(),
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

const redeemCode = (app) =>
  request(app).post('/api/oauth/token').type('form').send({
    grant_type: 'authorization_code',
    code: RAW_CODE,
    code_verifier: CODE_VERIFIER,
    redirect_uri: REDIRECT_URI,
    client_id: ASSISTANT_CLIENT_ID,
  });

const presentRefresh = (app, refreshToken, extra = {}) =>
  request(app)
    .post('/api/oauth/token')
    .type('form')
    .send({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: ASSISTANT_CLIENT_ID,
      ...extra,
    });

/**
 * Raw urlencoded body so a key can repeat (`scope=a&scope=b`).
 * Object form would send scope[0]=… — different wire shape.
 */
const presentRefreshRaw = (app, rawBody) =>
  request(app).post('/api/oauth/token').type('form').send(rawBody);

const form = (pairs) =>
  pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');

/**
 * Drives the real endpoint to build a family of `generations` live tokens.
 * Returns the raw tokens oldest first: [root, child1, child2, ...].
 */
const establishFamily = async (app, generations = 3) => {
  const first = await redeemCode(app);
  expect(first.status, JSON.stringify(first.body)).to.equal(200);

  const tokens = [first.body.refresh_token];
  for (let i = 1; i < generations; i += 1) {
    const rotated = await presentRefresh(app, tokens[tokens.length - 1]);
    expect(rotated.status, JSON.stringify(rotated.body)).to.equal(200);
    tokens.push(rotated.body.refresh_token);
  }
  return tokens;
};

const freshFamily = async (generations = 3) => {
  const db = makeDb({ codes: [codeRow()], grants: [grantRow()] });
  const app = buildApp(db);
  const tokens = await establishFamily(app, generations);
  return { db, app, tokens };
};

describe('POST /api/oauth/token — rotating refresh_token (ticket 39b)', () => {
  describe('rotation', () => {
    it('returns a new access token and a new refresh token', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(200);
      expect(response.body.access_token).to.be.a('string');
      expect(response.body.refresh_token).to.be.a('string');
      expect(response.body.refresh_token).to.not.equal(tokens[0]);
      expect(response.body.token_type).to.equal('Bearer');
    });

    it('issues an access token the real MCP verifier accepts', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0]);

      const verified = mcpAccessTokenVerifier.verifyMcpAccessToken(response.body.access_token, {
        asVerificationKeys: verificationKeysDouble,
        oauthConfig: configDouble(),
      });

      expect(verified.ok, verified.detail).to.equal(true);
      expect(verified.claims.grant_id).to.equal(GRANT_ID);
      expect(verified.claims.sub).to.equal(String(USER_ID));
    });

    it('marks the presented token used', async () => {
      const { db, app, tokens } = await freshFamily(1);
      await presentRefresh(app, tokens[0]);

      const root = db.tables.oauth_refresh_tokens[0];
      expect(root.used_at).to.be.a('string');
    });

    it('links the presented token to exactly one child', async () => {
      const { db, app, tokens } = await freshFamily(1);
      await presentRefresh(app, tokens[0]);

      const [root, child] = db.tables.oauth_refresh_tokens;
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(2);
      expect(child.parent_id).to.equal(root.id);
      expect(root.replaced_by_id).to.equal(child.id);
    });

    it('keeps the child in the same family as its parent', async () => {
      const { db, app, tokens } = await freshFamily(1);
      await presentRefresh(app, tokens[0]);

      const [root, child] = db.tables.oauth_refresh_tokens;
      expect(child.family_id).to.equal(root.family_id);
      expect(child.grant_id).to.equal(root.grant_id);
      expect(child.user_id).to.equal(root.user_id);
      expect(child.client_id).to.equal(root.client_id);
      expect(child.resource).to.equal(root.resource);
    });

    it('answers with Cache-Control no-store', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0]);

      expect(response.headers['cache-control']).to.equal('no-store');
    });
  });

  describe('reuse kills the family', () => {
    it('refuses a token that was already rotated away', async () => {
      const { app, tokens } = await freshFamily(3);
      const response = await presentRefresh(app, tokens[1]);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('revokes every generation of the family, ancestors included', async () => {
      const { db, app, tokens } = await freshFamily(3);
      await presentRefresh(app, tokens[1]);

      const rows = db.tables.oauth_refresh_tokens;
      expect(rows).to.have.lengthOf(3);
      rows.forEach((row) => {
        expect(row.revoked_at, `generation ${row.id} survived the sweep`).to.be.a('string');
      });
    });

    it('revokes the grant behind the family', async () => {
      const { db, app, tokens } = await freshFamily(3);
      await presentRefresh(app, tokens[1]);

      expect(db.tables.mcp_client_grants[0].status).to.equal('revoked');
      expect(db.tables.mcp_client_grants[0].revoked_at).to.be.a('string');
    });

    it('answers 503 when a detected reuse cannot be swept', async () => {
      // An unperformed security response is an OUTAGE, not a refusal:
      // invalid_grant would report the reuse was handled while the stolen
      // family is still live. The code path takes the same position.
      const { db, app, tokens } = await freshFamily(3);
      db.failures['mcp_client_grants.update'] = { code: '08006' };

      const response = await presentRefresh(app, tokens[1]);

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('answers 503 when a concurrent rotation cannot be swept', async () => {
      // Second of three `if (!swept.ok)` sites: the claim-race branch. The row
      // reads back unused and is claimed by somebody else before our own
      // conditional claim lands, which is reuse by definition.
      const db = makeDb({ codes: [codeRow()], grants: [grantRow()], claimTokenAfterRead: true });
      const app = buildApp(db);
      const [rootToken] = await establishFamily(app, 1);
      db.failures['mcp_client_grants.update'] = { code: '08006' };

      const response = await presentRefresh(app, rootToken);

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('answers 503 when a forked family cannot be swept', async () => {
      // Third site: UNIQUE (parent_id) rejects a second child of one parent.
      // Clearing the parent's used_at and replaced_by_id is how a parent that
      // already HAS a child still reaches the insert.
      const { db, app, tokens } = await freshFamily(2);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = null;
      root.replaced_by_id = null;
      db.failures['mcp_client_grants.update'] = { code: '08006' };

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });

    it('refuses the still-live newest token once the family is dead', async () => {
      const { app, tokens } = await freshFamily(3);
      await presentRefresh(app, tokens[1]);

      // child2 unused — only a family sweep stops it.
      const response = await presentRefresh(app, tokens[2]);
      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('treats a revoked but never-used token as reuse', async () => {
      // used_at null + revoked_at set must still count as reuse.
      const { db, app, tokens } = await freshFamily(1);
      db.tables.oauth_refresh_tokens[0].revoked_at = new Date().toISOString();

      const response = await presentRefresh(app, tokens[0]);
      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('treats a replaced but never-used token as reuse', async () => {
      // replaced_by_id set + used_at cleared (partial rotation) is reuse.
      const { db, app, tokens } = await freshFamily(2);
      db.tables.oauth_refresh_tokens[0].used_at = null;

      const response = await presentRefresh(app, tokens[0]);
      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });
  });

  describe('the grant status guard', () => {
    it('refuses refresh when the grant is no longer active', async () => {
      // Required by grantRevocationService: refuse when grant ≠ active.
      const { db, app, tokens } = await freshFamily(1);
      db.tables.mcp_client_grants[0].status = 'revoked';

      const response = await presentRefresh(app, tokens[0]);
      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('issues no access token when the grant is inactive', async () => {
      const { db, app, tokens } = await freshFamily(1);
      db.tables.mcp_client_grants[0].status = 'revoked';

      const response = await presentRefresh(app, tokens[0]);
      expect(response.body.access_token).to.equal(undefined);
    });

    it('survives a revoke that the refresh sweep missed', async () => {
      // Grant flipped, refresh rows left live — must still refuse.
      const { db, app, tokens } = await freshFamily(1);
      db.tables.mcp_client_grants[0].status = 'revoked';
      db.tables.oauth_refresh_tokens.forEach((row) => {
        row.revoked_at = null;
      });

      const response = await presentRefresh(app, tokens[0]);
      expect(response.status).to.equal(400);
    });
  });

  describe('binding and validity checks', () => {
    it('refuses an unknown refresh token', async () => {
      const { app } = await freshFamily(1);
      const response = await presentRefresh(app, 'e'.repeat(64));

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a request with no refresh_token', async () => {
      const { app } = await freshFamily(1);
      const response = await presentRefresh(app, '');

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('refuses an expired refresh token', async () => {
      const { db, app, tokens } = await freshFamily(1);
      db.tables.oauth_refresh_tokens[0].expires_at = secondsFromNow(-1);

      const response = await presentRefresh(app, tokens[0]);
      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('does not kill the family for ordinary expiry', async () => {
      // Expiry is not theft — do not sweep.
      const { db, app, tokens } = await freshFamily(1);
      db.tables.oauth_refresh_tokens[0].expires_at = secondsFromNow(-1);

      await presentRefresh(app, tokens[0]);
      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
    });

    it('refuses a client_id that differs from the one bound to the token', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0], {
        client_id: 'https://evil.test/client',
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('refuses a request with no client_id at all', async () => {
      // client_id required — omitting it must not skip the binding check.
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefreshRaw(
        app,
        form([
          ['grant_type', 'refresh_token'],
          ['refresh_token', tokens[0]],
        ])
      );

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('refuses a REPEATED client_id', async () => {
      // Repeated client_id → Array; must not skip the string check.
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefreshRaw(
        app,
        `${form([
          ['grant_type', 'refresh_token'],
          ['refresh_token', tokens[0]],
        ])}&client_id=${encodeURIComponent(ASSISTANT_CLIENT_ID)}&client_id=${encodeURIComponent(
          'https://evil.test/client'
        )}`
      );

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_request');
    });

    it('refuses when the grant and the token disagree about the user', async () => {
      const { db, app, tokens } = await freshFamily(1);
      db.tables.mcp_client_grants[0].user_id = 999;

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });

    it('treats a token with no expiry as expired rather than as eternal', async () => {
      // Null expires_at fails closed (unreachable under mig 002 NOT NULL).
      const { db, app, tokens } = await freshFamily(1);
      db.tables.oauth_refresh_tokens[0].expires_at = null;

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
    });
  });

  describe('scope', () => {
    it('carries the parent scopes forward when none are requested', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0]);

      expect(response.body.scope).to.equal('nutrition:read mealplan:read');
    });

    it('allows a narrower scope', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0], { scope: 'nutrition:read' });

      expect(response.status).to.equal(200);
      expect(response.body.scope).to.equal('nutrition:read');
      expect(jwt.decode(response.body.access_token).scope).to.equal('nutrition:read');
    });

    it('refuses a scope the parent token does not carry', async () => {
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefresh(app, tokens[0], {
        scope: 'nutrition:read nutrition:write',
      });

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_scope');
    });

    it('refuses a REPEATED scope parameter that exceeds the parent token', async () => {
      // Repeated scope= → Array; must still refuse widening (not skip downscope).
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefreshRaw(
        app,
        `${form([
          ['grant_type', 'refresh_token'],
          ['client_id', ASSISTANT_CLIENT_ID],
          ['refresh_token', tokens[0]],
        ])}&scope=nutrition%3Aread&scope=nutrition%3Awrite`
      );

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_scope');
    });

    it('honours a REPEATED scope parameter that stays inside the parent', async () => {
      // Opposite order to parent — proves response came from the request.
      const { app, tokens } = await freshFamily(1);
      const response = await presentRefreshRaw(
        app,
        `${form([
          ['grant_type', 'refresh_token'],
          ['client_id', ASSISTANT_CLIENT_ID],
          ['refresh_token', tokens[0]],
        ])}&scope=mealplan%3Aread&scope=nutrition%3Aread`
      );

      expect(response.status).to.equal(200);
      expect(response.body.scope).to.equal('mealplan:read nutrition:read');
    });
  });

  describe('a failed rotation must not look like theft', () => {
    it('does not claim the token when minting the access token fails', async () => {
      // Mint before claim — signing failure must leave used_at null.
      const { db, tokens } = await freshFamily(1);
      const broken = buildApp(db, {
        mcpAccessTokenIssuer: {
          issueMcpAccessToken: () => ({ ok: false, detail: 'issuer_unconfigured' }),
        },
      });

      const response = await presentRefresh(broken, tokens[0]);

      expect(response.status).to.equal(503);
      const root = db.tables.oauth_refresh_tokens[0];
      expect(root.used_at === null || root.used_at === undefined).to.equal(true);
    });

    it('leaves the token usable after a mint failure', async () => {
      const { db, app, tokens } = await freshFamily(1);
      const broken = buildApp(db, {
        mcpAccessTokenIssuer: {
          issueMcpAccessToken: () => ({ ok: false, detail: 'issuer_unconfigured' }),
        },
      });

      await presentRefresh(broken, tokens[0]);
      const retry = await presentRefresh(app, tokens[0]);

      expect(retry.status, JSON.stringify(retry.body)).to.equal(200);
      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
    });

    it('does not release the claim when the child insert committed anyway', async () => {
      // Timeout after commit: child landed — do not release claim (false theft).
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        insertCommitsThenFails: true,
      });
      const app = buildApp(db);
      const first = await redeemCode(app);
      expect(first.status).to.equal(200);

      const attempt = await presentRefresh(app, first.body.refresh_token);
      expect(attempt.status).to.equal(503);

      // Parent stays claimed and linked to the landed child.
      const [root, child] = db.tables.oauth_refresh_tokens;
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(2);
      expect(root.used_at).to.be.a('string');
      expect(root.replaced_by_id).to.equal(child.id);
    });

    it('never attempts a second child when the first one committed', async () => {
      // Retry must not attempt a second child of the same parent.
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        insertCommitsThenFails: true,
      });
      const app = buildApp(db);
      const first = await redeemCode(app);
      await presentRefresh(app, first.body.refresh_token);

      const attemptsBefore = db.calls.insertAttempts.length;
      await presentRefresh(app, first.body.refresh_token);

      expect(db.calls.insertAttempts.length).to.equal(attemptsBefore);
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(2);
    });

    it('does not revoke anything when the child insert fails', async () => {
      // True insert failure: release claim so retry is not swept as reuse.
      const { db, app, tokens } = await freshFamily(1);
      db.failures['oauth_refresh_tokens.insert'] = { code: '08006' };

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(503);
      expect(db.tables.mcp_client_grants[0].status).to.equal('active');
      db.tables.oauth_refresh_tokens.forEach((row) => {
        expect(row.revoked_at === null || row.revoked_at === undefined).to.equal(true);
      });
    });

    // Clean pre-commit failure: the probe finds no child, so releasing is
    // correct BECAUSE THE PROBE CHECKED — not because failure implies absence.
    it('leaves the presented token usable after a failed child insert', async () => {
      // Probe found no child — claim released; retry must succeed.
      const { db, app, tokens } = await freshFamily(1);
      db.failures['oauth_refresh_tokens.insert'] = { code: '08006' };
      await presentRefresh(app, tokens[0]);
      delete db.failures['oauth_refresh_tokens.insert'];

      const retry = await presentRefresh(app, tokens[0]);

      expect(retry.status, JSON.stringify(retry.body)).to.equal(200);
      expect(retry.body.refresh_token).to.be.a('string');
    });
  });

  // Mutation-proven, one at a time, each red in this file: child-found branch removed;
  // lease removed; used_at alone treated as reuse again; takeover CAS made
  // unconditional, or its replaced_by_id/revoked_at guard dropped; claim
  // release made unconditional; revoked_at alone no longer reuse; child-probe
  // failure read as "no child".
  describe('a stranded claim is recovered, not read as theft (ticket 88)', () => {
    const PAST_LEASE = new Date(Date.now() - refreshTokenStore.RETRY_LEASE_MS - 5000).toISOString();
    const grantOf = (db) => db.tables.mcp_client_grants[0];

    // Fails only the compensating release (used_at back to NULL).
    const failClaimRelease = ({ patch }) =>
      patch && patch.used_at === null ? { code: '08006' } : null;

    it('recovers when the insert AND the release fail: 503 inside the lease, 200 after', async () => {
      const { db, app, tokens } = await freshFamily(1);
      db.failures['oauth_refresh_tokens.insert'] = { code: '08006' };
      db.failures['oauth_refresh_tokens.update'] = failClaimRelease;

      expect((await presentRefresh(app, tokens[0])).status).to.equal(503);
      const root = db.tables.oauth_refresh_tokens[0];
      expect(root.used_at, 'the release failed, so the claim is stranded').to.be.a('string');
      delete db.failures['oauth_refresh_tokens.insert'];
      delete db.failures['oauth_refresh_tokens.update'];

      const inFlight = await presentRefresh(app, tokens[0]);
      expect(inFlight.status, 'inside the lease a rotation may be in flight').to.equal(503);
      expect(grantOf(db).status).to.equal('active');

      root.used_at = PAST_LEASE;
      const retry = await presentRefresh(app, tokens[0]);

      expect(retry.status, JSON.stringify(retry.body)).to.equal(200);
      expect(grantOf(db).status).to.equal('active');
      expect(db.tables.oauth_refresh_tokens).to.have.lengthOf(2);
      expect(root.replaced_by_id).to.equal(db.tables.oauth_refresh_tokens[1].id);
    });

    [
      ['inside the lease', () => new Date().toISOString()],
      ['past the lease', () => PAST_LEASE],
    ].forEach(([label, usedAt]) => {
      it(`still revokes a genuine reuse ${label}: used, unlinked, but a child exists`, async () => {
        // The link failed after the child landed. The child probe is the proof:
        // it must revoke at once (not 503 in flight), link the child, and never
        // reach a second-child insert that UNIQUE(parent_id) would catch later.
        const { db, app, tokens } = await freshFamily(2);
        const [root, child] = db.tables.oauth_refresh_tokens;
        root.replaced_by_id = null;
        root.used_at = usedAt();
        const insertsBefore = db.calls.insertAttempts.length;

        const response = await presentRefresh(app, tokens[0]);

        expect(response.status).to.equal(400);
        expect(response.body.error).to.equal('invalid_grant');
        expect(grantOf(db).status).to.equal('revoked');
        expect(root.replaced_by_id).to.equal(child.id);
        expect(db.calls.insertAttempts.length).to.equal(insertsBefore);
      });
    });

    it('revokes when another presentation wins the takeover', async () => {
      const { db, app, tokens } = await freshFamily(1);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = PAST_LEASE;
      db.failures['oauth_refresh_tokens.update'] = ({ filters }) => {
        if (filters.some(([op, column]) => op === 'eq' && column === 'used_at')) {
          root.used_at = new Date().toISOString();
        }
        return null;
      };

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('invalid_grant');
      expect(grantOf(db).status).to.equal('revoked');
    });

    it('answers 503 when the child probe fails, and neither takes over nor inserts', async () => {
      const { db, app, tokens } = await freshFamily(1);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = PAST_LEASE;
      const insertsBefore = db.calls.insertAttempts.length;
      db.failures['oauth_refresh_tokens.select'] = ({ filters }) =>
        filters.some(([, column]) => column === 'parent_id') ? { code: '08006' } : null;

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(503);
      expect(grantOf(db).status).to.equal('active');
      expect(root.used_at, 'no takeover').to.equal(PAST_LEASE);
      expect(db.calls.insertAttempts.length).to.equal(insertsBefore);
    });

    it('does not take over a claim that was replaced between the read and the CAS', async () => {
      // The takeover CAS also requires replaced_by_id and revoked_at to be NULL:
      // a rotation that completed meanwhile is reuse, not a stranded claim.
      const { db, app, tokens } = await freshFamily(1);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = PAST_LEASE;
      const insertsBefore = db.calls.insertAttempts.length;
      db.failures['oauth_refresh_tokens.update'] = ({ filters }) => {
        if (filters.some(([op, column]) => op === 'eq' && column === 'used_at')) {
          root.replaced_by_id = 999999;
        }
        return null;
      };

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(400);
      expect(grantOf(db).status).to.equal('revoked');
      expect(root.used_at, 'the CAS must not have landed').to.equal(PAST_LEASE);
      expect(db.calls.insertAttempts.length).to.equal(insertsBefore);
    });

    it('refuses an expired stranded token without revoking', async () => {
      const { db, app, tokens } = await freshFamily(1);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = PAST_LEASE;
      root.expires_at = secondsFromNow(-1);

      const response = await presentRefresh(app, tokens[0]);

      expect(response.status).to.equal(400);
      expect(grantOf(db).status).to.equal('active');
    });

    it('releases only its own claim, never a value another request wrote', async () => {
      const { db } = await freshFamily(1);
      const root = db.tables.oauth_refresh_tokens[0];
      root.used_at = new Date().toISOString();

      const released = await refreshTokenStore.releaseClaimIfNoChild(
        root.id,
        { supabase: db },
        PAST_LEASE
      );

      expect(released.ok).to.equal(true);
      expect(root.used_at, 'someone else holds this claim').to.not.equal(null);
    });
  });

  describe('database failure', () => {
    it('answers 503 server_error when the refresh lookup fails', async () => {
      const db = makeDb({
        codes: [codeRow()],
        grants: [grantRow()],
        failures: { 'oauth_refresh_tokens.select': { code: '08006' } },
      });
      const response = await presentRefresh(buildApp(db), 'f'.repeat(64));

      expect(response.status).to.equal(503);
      expect(response.body.error).to.equal('server_error');
    });
  });
});
