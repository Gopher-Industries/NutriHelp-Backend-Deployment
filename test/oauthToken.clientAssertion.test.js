// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const jwt = require('jsonwebtoken');

const clientAssertionVerifier = require('../services/oauth/clientAssertionVerifier');
const oauthConfig = require('../services/oauth/oauthConfig');

/** Q16a: token-endpoint audience isolation for the shared clientAssertionVerifier. */

const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const INGEST_URL = 'https://api.nutrihelp.test/api/security-events/mcp';
const ISSUER_IDENTIFIER = 'https://api.nutrihelp.test';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPem = {
  private: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: rsa.publicKey.export({ type: 'spki', format: 'pem' }),
};

const CONFIDENTIAL_CLIENT = {
  client_id: MCP_CLIENT_ID,
  client_type: 'service_confidential',
  token_endpoint_auth_method: 'private_key_jwt',
  is_active: true,
};

/** Records which table the replay row landed in - one store, not one per endpoint. */
const makeDb = ({ insertError = null } = {}) => {
  const calls = { insertedInto: [], insertedRows: [] };

  return {
    calls,
    from(table) {
      if (table === 'oauth_clients') {
        return {
          select: () => ({
            eq: () => ({ maybeSingle: async () => ({ data: CONFIDENTIAL_CLIENT, error: null }) }),
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
            data: [{ kid: null, alg: 'RS256', public_key_pem: rsaPem.public, slot: 1 }],
            error: null,
          }),
        };
        return chain;
      }

      if (table === 'oauth_client_assertion_jti') {
        return {
          insert: async (rows) => {
            calls.insertedInto.push(table);
            calls.insertedRows.push(rows[0]);
            return { error: insertError };
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
  introspectionAudience: () => INTROSPECTION_URL,
  tokenEndpointAudience: () => TOKEN_URL,
  mcpAccessTokenIssuer: () => ISSUER_IDENTIFIER,
  mcpResourceIdentifier: () => 'https://mcp.nutrihelp.test/mcp',
  ...overrides,
});

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
    rsaPem.private,
    { algorithm: 'RS256' }
  );
};

const request = (assertion) => ({
  client_assertion: assertion,
  client_assertion_type: clientAssertionVerifier.ASSERTION_TYPE,
});

/** Never sampled: purge randomness must not decide whether a test passes. */
const verifyAtTokenEndpoint = (assertion, { db = makeDb(), config = {} } = {}) =>
  clientAssertionVerifier.verifyClientAssertion(request(assertion), {
    supabase: db,
    oauthConfig: configDouble(config),
    assertionAudience: clientAssertionVerifier.AUDIENCE_TOKEN_ENDPOINT,
    random: () => 0.99,
  });

describe('oauth token endpoint - client assertion audience (Q16a)', () => {
  describe('oauthConfig.tokenEndpointAudience', () => {
    const TOUCHED = ['MCP_TOKEN_ENDPOINT_URL', 'MCP_INTROSPECTION_URL'];
    let saved;

    beforeEach(() => {
      saved = TOUCHED.map((name) => [name, process.env[name]]);
    });

    afterEach(() => {
      saved.forEach(([name, value]) => {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      });
    });

    it('normalises the configured URL the way the MCP side does', () => {
      process.env.MCP_TOKEN_ENDPOINT_URL = 'https://api.nutrihelp.test:443/api/oauth/token';

      expect(oauthConfig.tokenEndpointAudience()).to.equal(TOKEN_URL);
    });

    it('is null when unset', () => {
      delete process.env.MCP_TOKEN_ENDPOINT_URL;

      expect(oauthConfig.tokenEndpointAudience()).to.equal(null);
    });

    it('is null when set to something that is not a URL', () => {
      process.env.MCP_TOKEN_ENDPOINT_URL = 'not-a-url';

      expect(oauthConfig.tokenEndpointAudience()).to.equal(null);
    });

    it('does not fall back to the introspection URL', () => {
      delete process.env.MCP_TOKEN_ENDPOINT_URL;
      process.env.MCP_INTROSPECTION_URL = INTROSPECTION_URL;

      expect(oauthConfig.tokenEndpointAudience()).to.equal(null);
    });
  });

  describe('this endpoint accepts only its own absolute URL', () => {
    it('accepts an assertion minted for the token endpoint', () => {
      return verifyAtTokenEndpoint(signAssertion()).then((result) => {
        expect(result.ok).to.equal(true);
        expect(result.clientId).to.equal(MCP_CLIENT_ID);
      });
    });

    it('REFUSES an assertion minted for the sibling introspection endpoint', async () => {
      const result = await verifyAtTokenEndpoint(signAssertion({ aud: INTROSPECTION_URL }));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.reason).to.equal('invalid_client');
    });

    it('REFUSES an assertion minted for the audit ingest endpoint', async () => {
      const result = await verifyAtTokenEndpoint(signAssertion({ aud: INGEST_URL }));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
    });

    it('REFUSES the issuer identifier presented as aud', async () => {
      const result = await verifyAtTokenEndpoint(signAssertion({ aud: ISSUER_IDENTIFIER }));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
    });

    it('REFUSES an aud array that merely contains this endpoint', async () => {
      const result = await verifyAtTokenEndpoint(
        signAssertion({ aud: [TOKEN_URL, INTROSPECTION_URL] })
      );

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
    });

    it('answers 503 - not 401, and never acceptance - when its audience is unconfigured', async () => {
      const result = await verifyAtTokenEndpoint(signAssertion(), {
        config: { tokenEndpointAudience: () => null },
      });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(503);
      expect(result.detail).to.equal('token_endpoint_audience_unconfigured');
    });

    it('does not accept introspection assertions when its own audience is unconfigured', async () => {
      const result = await verifyAtTokenEndpoint(signAssertion({ aud: INTROSPECTION_URL }), {
        config: { tokenEndpointAudience: () => null },
      });

      expect(result.ok).to.equal(false);
    });
  });

  describe('the default is still introspection - ticket 42 is untouched', () => {
    it('uses the introspection audience when no audience is passed', async () => {
      const result = await clientAssertionVerifier.verifyClientAssertion(
        request(signAssertion({ aud: INTROSPECTION_URL })),
        { supabase: makeDb(), oauthConfig: configDouble(), random: () => 0.99 }
      );

      expect(result.ok).to.equal(true);
    });

    it('refuses a token-endpoint assertion on the default path', async () => {
      const result = await clientAssertionVerifier.verifyClientAssertion(request(signAssertion()), {
        supabase: makeDb(),
        oauthConfig: configDouble(),
        random: () => 0.99,
      });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
    });
  });

  describe('one replay store, three audiences', () => {
    it('records the jti in the shared oauth_client_assertion_jti table', async () => {
      const db = makeDb();
      await verifyAtTokenEndpoint(signAssertion(), { db });

      expect(db.calls.insertedInto).to.deep.equal(['oauth_client_assertion_jti']);
      expect(db.calls.insertedRows[0].client_id).to.equal(MCP_CLIENT_ID);
    });

    it('refuses a replayed jti at this endpoint', async () => {
      const db = makeDb({ insertError: { code: '23505' } });
      const result = await verifyAtTokenEndpoint(signAssertion(), { db });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_replayed');
    });
  });
});
