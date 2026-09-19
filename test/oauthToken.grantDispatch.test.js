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

/**
 * grant_type dispatch + aud scalar check (ticket 39b).
 * Null-prototype map required — object literal makes grant_type=constructor hang.
 */

const ISSUER = 'https://api.nutrihelp.test';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const GRANT_ID = '3f1b6a52-6d1e-4a1e-9f1c-0b2f5d7c8e90';
const USER_ID = 42;

const asKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const AS_PRIVATE_PEM = asKey.privateKey.export({ type: 'pkcs8', format: 'pem' });
const AS_PUBLIC_PEM = asKey.publicKey.export({ type: 'spki', format: 'pem' });
const AS_KID = 'as-key-1';

const configDouble = () => ({
  mcpAccessTokenIssuer: () => ISSUER,
  mcpResourceIdentifier: () => MCP_RESOURCE,
  backendApiAudience: () => 'https://api.nutrihelp.test/api',
  tokenEndpointAudience: () => 'https://api.nutrihelp.test/api/oauth/token',
  introspectionAudience: () => 'https://api.nutrihelp.test/api/oauth/introspect',
  frontendOrigin: () => 'https://app.nutrihelp.test',
});

const verificationKeysDouble = {
  getVerificationKeys: () => [{ kid: AS_KID, publicKeyPem: AS_PUBLIC_PEM, alg: 'RS256' }],
};

/** Throws on ANY table, so reaching the database at all fails the test. */
const hostileDb = {
  from: (table) => {
    throw new Error(`database touched for an unsupported grant_type: ${table}`);
  },
};

const buildApp = () => {
  const app = express();
  app.use(
    '/api/oauth',
    createOauthRouter({
      supabase: hostileDb,
      oauthConfig: configDouble(),
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

const postGrantType = (grantType) =>
  request(buildApp()).post('/api/oauth/token').type('form').send({ grant_type: grantType });

const mintAccessToken = (overrides = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: ISSUER,
      aud: MCP_RESOURCE,
      sub: String(USER_ID),
      type: 'mcp_access',
      scope: 'nutrition:read',
      client_id: ASSISTANT_CLIENT_ID,
      grant_id: GRANT_ID,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
      ...overrides,
    },
    AS_PRIVATE_PEM,
    { algorithm: 'RS256', keyid: AS_KID }
  );
};

describe('POST /api/oauth/token — grant_type dispatch', () => {
  // Prototype members that were handlers on an object-literal map (hang or 503).
  ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'].forEach((grantType) => {
    it(`refuses grant_type=${grantType} as unsupported`, async () => {
      const response = await postGrantType(grantType);

      expect(response.status).to.equal(400);
      expect(response.body.error).to.equal('unsupported_grant_type');
    });
  });

  it('refuses an ordinary unknown grant_type as unsupported', async () => {
    const response = await postGrantType('client_credentials');

    expect(response.status).to.equal(400);
    expect(response.body.error).to.equal('unsupported_grant_type');
  });

  it('refuses a missing grant_type as an invalid request', async () => {
    const response = await request(buildApp()).post('/api/oauth/token').type('form').send({});

    expect(response.status).to.equal(400);
    expect(response.body.error).to.equal('invalid_request');
  });

  it('advertises the three grants it implements', async () => {
    const { createTokenController } = require('../controller/oauthTokenController');
    expect(createTokenController).to.be.a('function');

    const controller = require('../controller/oauthTokenController');
    expect(controller.AUTHORIZATION_CODE_GRANT_TYPE).to.equal('authorization_code');
    expect(controller.REFRESH_TOKEN_GRANT_TYPE).to.equal('refresh_token');
    expect(controller.EXCHANGE_GRANT_TYPE).to.equal(
      'urn:ietf:params:oauth:grant-type:token-exchange'
    );
  });
});

describe('mcpAccessTokenVerifier — aud must be a scalar', () => {
  it('accepts a token whose aud is the configured resource', () => {
    const verified = mcpAccessTokenVerifier.verifyMcpAccessToken(mintAccessToken(), {
      asVerificationKeys: verificationKeysDouble,
      oauthConfig: configDouble(),
    });

    expect(verified.ok, verified.detail).to.equal(true);
  });

  it('refuses a token whose aud is an array containing the resource', () => {
    // jwt.verify accepts any array element as audience — must refuse non-scalar.
    const verified = mcpAccessTokenVerifier.verifyMcpAccessToken(
      mintAccessToken({ aud: ['https://elsewhere.test/mcp', MCP_RESOURCE] }),
      { asVerificationKeys: verificationKeysDouble, oauthConfig: configDouble() }
    );

    expect(verified.ok).to.equal(false);
    expect(verified.reason).to.equal('invalid');
  });
});
