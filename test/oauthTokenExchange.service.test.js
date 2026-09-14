// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const jwt = require('jsonwebtoken');

const tokenExchangeService = require('../services/oauth/tokenExchangeService');

const ISSUER = 'https://api.nutrihelp.test';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const BACKEND_API_AUDIENCE = 'https://api.nutrihelp.test/api';
const ASSISTANT_CLIENT_ID = 'https://assistant.example/client';
const MCP_SERVER_CLIENT_ID = 'https://mcp.nutrihelp.test/client';
const GRANT_ID = '8f3a1c2e-0d44-4a1b-9c77-2b6e5f0a91d3';
const USER_ID = 653;

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

const asKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const AS_PRIVATE_PEM = asKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const AS_PUBLIC_PEM = asKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
const AS_KID = 'as-key-1';

const foreignKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const FOREIGN_PRIVATE_PEM = foreignKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });

/** No role_name default - fail-closed cases need its absence. */
const userRow = (overrides = {}) => ({
  user_id: USER_ID,
  role_id: 7,
  ...overrides,
});

const grantRow = (overrides = {}) => ({
  grant_id: GRANT_ID,
  user_id: USER_ID,
  client_id: ASSISTANT_CLIENT_ID,
  resource: MCP_RESOURCE,
  scopes: 'nutrition:read mealplan:read',
  status: 'active',
  ...overrides,
});

const makeDb = ({
  grant = grantRow(),
  grantError = null,
  user = userRow({ user_roles: { role_name: 'user' } }),
  userError = null,
} = {}) => {
  const calls = { grantLookups: 0, userLookups: 0, userFilters: [], userSelect: null };

  return {
    calls,
    from(table) {
      if (table === 'mcp_client_grants') {
        return {
          select: () => ({
            eq: () => ({
              maybeSingle: async () => {
                calls.grantLookups += 1;
                return { data: grantError ? null : grant, error: grantError };
              },
            }),
          }),
        };
      }

      if (table === 'users') {
        return {
          select: (columns) => {
            calls.userSelect = columns;
            return {
              eq: (column, value) => {
                calls.userFilters.push([column, value]);
                return {
                  maybeSingle: async () => {
                    calls.userLookups += 1;
                    return { data: userError ? null : user, error: userError };
                  },
                };
              },
            };
          },
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
  tokenEndpointAudience: () => `${ISSUER}/api/oauth/token`,
  introspectionAudience: () => `${ISSUER}/api/oauth/introspect`,
  ...overrides,
});

const signingKeyDouble = (overrides = {}) => ({
  getSigningKey: () => ({
    ok: true,
    key: {
      kid: AS_KID,
      alg: 'RS256',
      privateKeyPem: AS_PRIVATE_PEM,
      publicKeyPem: AS_PUBLIC_PEM,
      ...overrides,
    },
  }),
});

const verificationKeysDouble = () => ({
  getVerificationKeys: () => [{ kid: AS_KID, alg: 'RS256', publicKeyPem: AS_PUBLIC_PEM }],
});

/** A genuine MCP access token, signed by the AS key the verifier trusts. */
const signSubjectToken = (overrides = {}, { key = AS_PRIVATE_PEM } = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: ISSUER,
      aud: MCP_RESOURCE,
      sub: String(USER_ID),
      scope: 'nutrition:read mealplan:read',
      client_id: ASSISTANT_CLIENT_ID,
      grant_id: GRANT_ID,
      jti: crypto.randomUUID(),
      type: 'mcp_access',
      iat: now,
      exp: now + 900,
      ...overrides,
    },
    key,
    { algorithm: 'RS256', header: { kid: AS_KID } }
  );
};

const exchange = (params = {}, { db = makeDb(), config = {}, signingKey } = {}) =>
  tokenExchangeService.exchange(
    {
      subject_token: signSubjectToken(),
      subject_token_type: ACCESS_TOKEN_TYPE,
      ...params,
    },
    {
      supabase: db,
      oauthConfig: configDouble(config),
      asVerificationKeys: verificationKeysDouble(),
      asSigningKey: signingKey || signingKeyDouble(),
      actorClientId: MCP_SERVER_CLIENT_ID,
    }
  );

const claimsOf = (result) =>
  jwt.verify(result.credential, AS_PUBLIC_PEM, {
    algorithms: ['RS256'],
    issuer: ISSUER,
    audience: BACKEND_API_AUDIENCE,
  });

describe('oauth token exchange service (RFC 8693)', () => {
  describe('the exchanged credential', () => {
    it('issues a credential the AS public key verifies', async () => {
      const result = await exchange();

      expect(result.outcome).to.equal('issued');
      expect(() => claimsOf(result)).to.not.throw();
    });

    it('lives exactly 120 seconds', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.exp - claims.iat).to.equal(120);
    });

    it('reports that lifetime as expires_in', async () => {
      const result = await exchange();

      expect(result.expiresIn).to.equal(120);
    });

    it('is RS256 and carries the AS kid', async () => {
      const result = await exchange();
      const header = jwt.decode(result.credential, { complete: true }).header;

      expect(header.alg).to.equal('RS256');
      expect(header.kid).to.equal(AS_KID);
    });

    it('carries type mcp_upstream', async () => {
      expect(claimsOf(await exchange()).type).to.equal('mcp_upstream');
    });

    it('is addressed to the backend API, not to the MCP resource', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.aud).to.equal(BACKEND_API_AUDIENCE);
      expect(claims.aud).to.not.equal(MCP_RESOURCE);
    });

    it('carries BOTH sub and userId', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.sub).to.equal(String(USER_ID));
      expect(claims.userId).to.equal(USER_ID);
    });

    it('carries the grant id and a jti', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.grant_id).to.equal(GRANT_ID);
      expect(claims.jti).to.be.a('string').and.not.empty;
    });

    it('mints a fresh jti per exchange', async () => {
      const [first, second] = [claimsOf(await exchange()), claimsOf(await exchange())];

      expect(first.jti).to.not.equal(second.jti);
    });

    it('names the ASSISTANT in client_id and the MCP SERVER in act', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.client_id).to.equal(ASSISTANT_CLIENT_ID);
      expect(claims.act.sub).to.equal(MCP_SERVER_CLIENT_ID);
      expect(claims.act.sub).to.not.equal(claims.client_id);
    });

    it('refuses to mint when the signing key is unavailable', async () => {
      const result = await exchange(
        {},
        { signingKey: { getSigningKey: () => ({ ok: false, detail: 'signing_key_unconfigured' }) } }
      );

      expect(result.outcome).to.equal('unavailable');
      expect(result.detail).to.equal('signing_key_unconfigured');
      expect(result.credential).to.equal(undefined);
    });

    it('refuses to mint from a key that carries no kid', async () => {
      const result = await exchange(
        {},
        {
          signingKey: {
            getSigningKey: () => ({
              ok: true,
              key: { kid: null, alg: 'RS256', privateKeyPem: AS_PRIVATE_PEM },
            }),
          },
        }
      );

      expect(result.outcome).to.equal('unavailable');
      expect(result.detail).to.equal('signing_key_id_absent');
      expect(result.credential).to.equal(undefined);
    });

    it('refuses to mint when the backend audience is unconfigured', async () => {
      const result = await exchange({}, { config: { backendApiAudience: () => null } });

      expect(result.outcome).to.equal('unavailable');
      expect(result.credential).to.equal(undefined);
    });
  });

  describe('identity comes from the subject token, never from a parameter', () => {
    it('ignores a user identity supplied in the request', async () => {
      const claims = claimsOf(
        await exchange({ sub: '1', userId: 1, user_id: 1, subject: 1, email: 'a@b.test' })
      );

      expect(claims.sub).to.equal(String(USER_ID));
      expect(claims.userId).to.equal(USER_ID);
    });

    it('renders the grant user id as a string sub', async () => {
      const db = makeDb({
        grant: grantRow({ user_id: 653 }),
        user: userRow({ user_roles: { role_name: 'user' } }),
      });
      const claims = claimsOf(await exchange({}, { db }));

      expect(claims.sub).to.equal('653');
      expect(claims.sub).to.be.a('string');
    });
  });

  describe('role resolution — fails closed, at exchange time', () => {
    it('reads the role from the database and puts it in the credential', async () => {
      const db = makeDb({ user: userRow({ user_roles: { role_name: 'nutritionist' } }) });
      const claims = claimsOf(await exchange({}, { db }));

      expect(claims.role).to.equal('nutritionist');
      expect(db.calls.userLookups).to.equal(1);
    });

    it('re-reads the role on every exchange rather than trusting the token', async () => {
      const subjectToken = signSubjectToken({ role: 'admin' });

      const asUser = claimsOf(
        await exchange(
          { subject_token: subjectToken },
          { db: makeDb({ user: userRow({ user_roles: { role_name: 'user' } }) }) }
        )
      );
      const asAdmin = claimsOf(
        await exchange(
          { subject_token: subjectToken },
          { db: makeDb({ user: userRow({ user_roles: { role_name: 'admin' } }) }) }
        )
      );

      expect(asUser.role).to.equal('user');
      expect(asAdmin.role).to.equal('admin');
    });

    it('refuses as invalid_grant when the role does not resolve', async () => {
      const db = makeDb({ user: userRow() });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_grant');
      expect(result.detail).to.equal('role_unresolved');
    });

    it('does not fall back to the user role when the mapping is missing', async () => {
      const db = makeDb({ user: userRow({ user_roles: null }) });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('refused');
      expect(result.credential).to.equal(undefined);
    });

    it('treats an empty role name as unresolved', async () => {
      const db = makeDb({ user: userRow({ user_roles: { role_name: '   ' } }) });
      const result = await exchange({}, { db });

      expect(result.error).to.equal('invalid_grant');
    });

    it('refuses as invalid_grant when the user row is gone', async () => {
      const db = makeDb({ user: null });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_grant');
      expect(result.detail).to.equal('user_not_found');
    });

    it('answers unavailable — not invalid_grant — when the role lookup errors', async () => {
      const db = makeDb({ userError: { message: 'connection reset' } });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('unavailable');
      expect(result.error).to.equal(undefined);
    });

    it('accepts the joined row when PostgREST returns it as an array', async () => {
      const db = makeDb({ user: userRow({ user_roles: [{ role_name: 'admin' }] }) });
      const claims = claimsOf(await exchange({}, { db }));

      expect(claims.role).to.equal('admin');
    });

    it('looks the user up by the grant user id', async () => {
      const db = makeDb();
      await exchange({}, { db });

      expect(db.calls.userFilters).to.deep.equal([['user_id', USER_ID]]);
    });
  });

  describe('subject token and grant state', () => {
    it('refuses a forged subject token as invalid_grant', async () => {
      const result = await exchange({
        subject_token: signSubjectToken({}, { key: FOREIGN_PRIVATE_PEM }),
      });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_grant');
    });

    it('does NOT flag a security anomaly for a token that failed verification', async () => {
      const result = await exchange({
        subject_token: signSubjectToken({}, { key: FOREIGN_PRIVATE_PEM }),
      });

      expect(result.subjectTokenVerified).to.equal(false);
    });

    it('FLAGS a security anomaly when a genuinely signed token is refused', async () => {
      const db = makeDb({ grant: grantRow({ status: 'revoked' }) });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_grant');
      expect(result.subjectTokenVerified).to.equal(true);
    });

    it('refuses an unknown grant as invalid_grant', async () => {
      const db = makeDb({ grant: null });
      const result = await exchange({}, { db });

      expect(result.error).to.equal('invalid_grant');
    });

    it('refuses an expired subject token as invalid_grant', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await exchange({
        subject_token: signSubjectToken({ iat: now - 4000, exp: now - 3600 }),
      });

      expect(result.error).to.equal('invalid_grant');
    });

    it('refuses a platform access token presented as the subject token', async () => {
      const result = await exchange({ subject_token: signSubjectToken({ type: 'access' }) });

      expect(result.error).to.equal('invalid_grant');
    });

    it('answers unavailable when the grant lookup errors', async () => {
      const db = makeDb({ grantError: { message: 'connection reset' } });
      const result = await exchange({}, { db });

      expect(result.outcome).to.equal('unavailable');
    });

    it('never reaches the role lookup for an inactive grant', async () => {
      // Mandatory order: a revoked grant stops before anything else happens.
      const db = makeDb({ grant: grantRow({ status: 'revoked' }) });
      await exchange({}, { db });

      expect(db.calls.userLookups).to.equal(0);
    });
  });

  describe('scope — invalid_scope, never insufficient_scope', () => {
    it('issues the full granted scope when none is requested', async () => {
      const claims = claimsOf(await exchange());

      expect(claims.scope).to.equal('nutrition:read mealplan:read');
    });

    it('narrows to the requested subset', async () => {
      const claims = claimsOf(await exchange({ scope: 'mealplan:read' }));

      expect(claims.scope).to.equal('mealplan:read');
    });

    it('refuses a requested scope that exceeds the grant', async () => {
      const result = await exchange({ scope: 'nutrition:read meallog:write' });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_scope');
    });

    it('never answers insufficient_scope', async () => {
      const result = await exchange({ scope: 'meallog:write' });

      expect(result.error).to.not.equal('insufficient_scope');
      expect(result.httpStatus).to.not.equal(403);
    });

    it('refuses a repeated scope parameter that exceeds the grant', async () => {
      const result = await exchange({ scope: ['nutrition:read', 'meallog:write'] });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_scope');
    });

    it('downscopes correctly when a repeated scope parameter is within the grant', async () => {
      const claims = claimsOf(await exchange({ scope: ['mealplan:read'] }));

      expect(claims.scope).to.equal('mealplan:read');
    });

    it('refuses a scope the token itself no longer carries', async () => {
      const result = await exchange({
        subject_token: signSubjectToken({ scope: 'nutrition:read' }),
        scope: 'mealplan:read',
      });

      expect(result.error).to.equal('invalid_scope');
    });
  });

  describe('target — invalid_target', () => {
    it('accepts the backend API as the requested resource', async () => {
      const result = await exchange({ resource: BACKEND_API_AUDIENCE });

      expect(result.outcome).to.equal('issued');
    });

    it('refuses a resource this server will not issue for', async () => {
      const result = await exchange({ resource: 'https://elsewhere.example/api' });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_target');
    });

    it('refuses an audience this server will not issue for', async () => {
      const result = await exchange({ audience: MCP_RESOURCE });

      expect(result.error).to.equal('invalid_target');
    });

    it('defaults to the backend API when no target is requested', async () => {
      expect(claimsOf(await exchange()).aud).to.equal(BACKEND_API_AUDIENCE);
    });
  });

  describe('request shape — invalid_request', () => {
    it('refuses a missing subject token', async () => {
      const result = await exchange({ subject_token: undefined });

      expect(result.outcome).to.equal('refused');
      expect(result.error).to.equal('invalid_request');
    });

    it('refuses a missing subject_token_type', async () => {
      // RFC 8693 §2.1 makes subject_token_type REQUIRED.
      const result = await exchange({ subject_token_type: undefined });

      expect(result.error).to.equal('invalid_request');
    });

    it('refuses a subject_token_type this server does not accept', async () => {
      const result = await exchange({
        subject_token_type: 'urn:ietf:params:oauth:token-type:refresh_token',
      });

      expect(result.error).to.equal('invalid_request');
    });

    it('refuses a requested_token_type this server does not issue', async () => {
      const result = await exchange({
        requested_token_type: 'urn:ietf:params:oauth:token-type:saml2',
      });

      expect(result.error).to.equal('invalid_request');
    });

    it('accepts an explicit access-token requested_token_type', async () => {
      const result = await exchange({ requested_token_type: ACCESS_TOKEN_TYPE });

      expect(result.outcome).to.equal('issued');
    });

    it('does not touch the database for a malformed request', async () => {
      const db = makeDb();
      await exchange({ subject_token: undefined }, { db });

      expect(db.calls.grantLookups).to.equal(0);
      expect(db.calls.userLookups).to.equal(0);
    });
  });
});
