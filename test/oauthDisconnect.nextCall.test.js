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
const liveSupabase = require('../dbConnection');

// The env defaults above yield to anything already exported, so a real
// SUPABASE_* in the shell would make the module client live. Every service on
// this path takes deps.supabase; one that stops doing so must fail loudly here
// rather than dial out. `before`/`after` are mocha's, `beforeAll`/`afterAll`
// jest's — both runners glob this file.
const beforeAllHook = global.before || global.beforeAll;
const afterAllHook = global.after || global.afterAll;

/**
 * Ticket 42 done-when, backend half: disconnecting takes effect on the next
 * call. The done-when's other half — tested while a cached credential exists —
 * belongs to the MCP server and is not exercised here (see below).
 *
 * One router, one stateful database double shared by POST /token, POST
 * /introspect and DELETE /grants/:id. The DELETE is the only thing that changes
 * the grant row — nothing in this file edits it by hand — so an inactive answer
 * after the DELETE can only come from the DELETE. Client authentication is a
 * real private_key_jwt against a real key; only the database, the platform
 * bearer and the log sinks are doubled. No live database is touched.
 *
 * What the backend owes, and what it does not:
 *
 * - Owed here: once the grant is revoked, the very next introspection of the
 *   same access token answers active:false, and the same token can no longer
 *   be exchanged, and both refusals say the grant status is why. The same
 *   user's grant on another assistant, and another user's grant on the same
 *   assistant, are unaffected.
 *
 * - NOT owed here: refusing an exchanged credential that was minted before the
 *   revocation and is still held. The backend does not re-check the grant when
 *   that credential is presented; it is short-lived (120 seconds) by design.
 *   Keeping a held credential from outliving a revoked grant is the MCP
 *   server's job: it introspects before it would consult any credential
 *   cache. The held credential below exists to prove the scenario is the real
 *   one, not to assert that the backend refuses it.
 */

const ISSUER = 'https://api.nutrihelp.test';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const MCP_RESOURCE = 'https://mcp.nutrihelp.test/mcp';
const BACKEND_API_AUDIENCE = 'https://api.nutrihelp.test/api';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';
const FRONTEND_ORIGIN = 'https://gonutrihelp.vercel.app';

const USER_ID = 42;
const OTHER_USER_ID = 43;
const ASSISTANT_CLIENT_ID = 'https://claude.ai/mcp-client';
const OTHER_ASSISTANT_CLIENT_ID = 'https://other-assistant.example/mcp-client';

// One control row per axis the revocation must not spill along:
// G2 = same user, other assistant; G3 = other user, same assistant.
const GRANT_ID = '22d9ede4-4195-4cba-addf-a44efa16cf53';
const OTHER_GRANT_ID = '9f1c0b2f-5d7c-4e90-8a1e-3f1b6a526d1e';
const OTHER_USER_GRANT_ID = '5b7e1c3a-8d24-4f6b-9a0e-c2d4f6a8b1e3';

const EXCHANGE_ANOMALY_EVENT = 'mcp_token_exchange_refused_after_verification';

const EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const pemPair = () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    private: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    public: pair.publicKey.export({ type: 'spki', format: 'pem' }),
  };
};

const asPem = pemPair(); // this server's AS key
const mcpPem = pemPair(); // the MCP server's private_key_jwt key

const mintAccessToken = ({ grantId, clientId, userId = USER_ID }) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: ISSUER,
      aud: MCP_RESOURCE,
      sub: String(userId),
      type: 'mcp_access',
      scope: 'nutrition:read',
      client_id: clientId,
      grant_id: grantId,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
    },
    asPem.private,
    { algorithm: 'RS256', keyid: 'as-key-1' }
  );
};

/** A genuine private_key_jwt. Fresh jti every call — the replay store is live. */
const mintClientAssertion = (audience) => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: MCP_CLIENT_ID,
      sub: MCP_CLIENT_ID,
      aud: audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 60,
    },
    mcpPem.private,
    { algorithm: 'RS256' }
  );
};

/**
 * A tiny in-memory table: select/update honour every eq/is filter, so a write
 * lands only on the rows its filters name. That is what lets G2 and G3 prove
 * the revocation did not spill over.
 */
const makeTable = (rows) => {
  // eq and is(col, null) both reduce to strict equality for these rows.
  const matches = (row, filters) => filters.every(([col, val]) => row[col] === val);

  return {
    rows,
    select: () => {
      const filters = [];
      const chain = {
        eq: (col, val) => {
          filters.push([col, val]);
          return chain;
        },
        maybeSingle: async () => {
          const found = rows.find((row) => matches(row, filters));
          return { data: found ? { ...found } : null, error: null };
        },
      };
      return chain;
    },
    update: (patch) => {
      const filters = [];
      const chain = {
        eq: (col, val) => {
          filters.push([col, val]);
          return chain;
        },
        is: (col, val) => {
          filters.push([col, val]);
          return chain;
        },
        // supabase-js builders are thenable; awaiting the chain runs the write.
        then: (resolve) => {
          rows.filter((row) => matches(row, filters)).forEach((row) => Object.assign(row, patch));
          return resolve({ error: null });
        },
      };
      return chain;
    },
  };
};

const makeDb = () => {
  const grants = makeTable([
    {
      grant_id: GRANT_ID,
      user_id: USER_ID,
      client_id: ASSISTANT_CLIENT_ID,
      resource: MCP_RESOURCE,
      scopes: 'nutrition:read',
      status: 'active',
    },
    {
      grant_id: OTHER_GRANT_ID,
      user_id: USER_ID,
      client_id: OTHER_ASSISTANT_CLIENT_ID,
      resource: MCP_RESOURCE,
      scopes: 'nutrition:read',
      status: 'active',
    },
    {
      grant_id: OTHER_USER_GRANT_ID,
      user_id: OTHER_USER_ID,
      client_id: ASSISTANT_CLIENT_ID,
      resource: MCP_RESOURCE,
      scopes: 'nutrition:read',
      status: 'active',
    },
  ]);
  const refreshTokens = makeTable([
    { grant_id: GRANT_ID, user_id: USER_ID, revoked_at: null },
    { grant_id: OTHER_GRANT_ID, user_id: USER_ID, revoked_at: null },
    { grant_id: OTHER_USER_GRANT_ID, user_id: OTHER_USER_ID, revoked_at: null },
  ]);
  const users = makeTable([{ user_id: USER_ID, role_id: 7, user_roles: { role_name: 'user' } }]);
  const seenJtis = new Set();

  return {
    grants,
    refreshTokens,
    from(table) {
      if (table === 'mcp_client_grants') return grants;
      if (table === 'oauth_refresh_tokens') return refreshTokens;
      if (table === 'users') return users;

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
            data: [{ kid: null, alg: 'RS256', public_key_pem: mcpPem.public, slot: 1 }],
            error: null,
          }),
        };
        return chain;
      }

      if (table === 'oauth_client_assertion_jti') {
        return {
          insert: async (rows) => {
            const { jti } = rows[0];
            if (seenJtis.has(jti)) return { error: { code: '23505' } };
            seenJtis.add(jti);
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

/** app.refusals captures every logGrantRefusal record, so a test can pin WHY. */
const makeApp = (db) => {
  const refusals = [];
  const deps = {
    supabase: db,
    // Never sample the jti purge: keeps every run on the same path.
    random: () => 1,
    // The platform bearer is not under test; the grant owner is signed in.
    authenticateToken: (req, res, next) => {
      req.user = { userId: USER_ID };
      return next();
    },
    asVerificationKeys: {
      getVerificationKeys: () => [{ kid: 'as-key-1', alg: 'RS256', publicKeyPem: asPem.public }],
    },
    asSigningKey: {
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
    oauthConfig: {
      mcpAccessTokenIssuer: () => ISSUER,
      mcpResourceIdentifier: () => MCP_RESOURCE,
      backendApiAudience: () => BACKEND_API_AUDIENCE,
      tokenEndpointAudience: () => TOKEN_URL,
      introspectionAudience: () => INTROSPECTION_URL,
      frontendOrigin: () => FRONTEND_ORIGIN,
    },
    introspectionLog: {
      logOperational: async () => {},
      logGrantRefusal: async (record) => {
        refusals.push(record);
      },
    },
  };

  const app = express();
  app.use('/api/oauth', createOauthRouter(deps));
  app.refusals = refusals;
  return app;
};

/** Runs one request and returns it with the refusal records it produced. */
const withRefusals = async (app, send) => {
  const start = app.refusals.length;
  const response = await send();
  return { response, refusals: app.refusals.slice(start) };
};

const exchange = (app, subjectToken) =>
  request(app)
    .post('/api/oauth/token')
    .type('form')
    .send({
      grant_type: EXCHANGE_GRANT_TYPE,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN_TYPE,
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: mintClientAssertion(TOKEN_URL),
    });

const introspect = (app, token) =>
  request(app)
    .post('/api/oauth/introspect')
    .type('form')
    .send({
      token,
      token_type_hint: 'access_token',
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: mintClientAssertion(INTROSPECTION_URL),
    });

const disconnect = (app, grantId) =>
  request(app).delete(`/api/oauth/grants/${grantId}`).set('Origin', FRONTEND_ORIGIN);

const credentialClaims = (response) =>
  jwt.verify(response.body.access_token, asPem.public, {
    algorithms: ['RS256'],
    issuer: ISSUER,
    audience: BACKEND_API_AUDIENCE,
  });

describe('ticket 42 — disconnect takes effect on the next call, with a credential held', () => {
  let originalFrom;
  beforeAllHook(() => {
    originalFrom = liveSupabase.from;
    liveSupabase.from = (table) => {
      throw new Error(`live Supabase client reached for table ${table}; inject deps.supabase`);
    };
  });
  afterAllHook(() => {
    liveSupabase.from = originalFrom;
  });

  it('flips the same access token from active to inactive, and it can no longer be exchanged', async () => {
    const db = makeDb();
    const app = makeApp(db);
    const accessToken = mintAccessToken({ grantId: GRANT_ID, clientId: ASSISTANT_CLIENT_ID });

    // 1. Exchange: a credential for this grant is now held.
    const exchanged = await exchange(app, accessToken);
    expect(exchanged.status, 'step 1 exchange').to.equal(200);
    const held = credentialClaims(exchanged);
    expect(held.type).to.equal('mcp_upstream');
    expect(held.grant_id).to.equal(GRANT_ID);

    // 2. Same database instance, same token: active before the disconnect. This
    //    is what makes step 4 attributable to step 3 rather than to the fixture.
    const before = await introspect(app, accessToken);
    expect(before.status, 'step 2 introspect').to.equal(200);
    expect(before.body.active, 'step 2: active before disconnect').to.equal(true);
    expect(before.body.grant_id).to.equal(GRANT_ID);

    // 3. The user disconnects.
    const disconnected = await disconnect(app, GRANT_ID);
    expect(disconnected.status, 'step 3 disconnect').to.equal(204);

    // 4. The very next introspection of the same token value is inactive — and
    //    inactive BECAUSE the status is revoked. {active:false} alone has many
    //    causes (subject/client/resource mismatch among them), so pin the reason.
    const step4 = await withRefusals(app, () => introspect(app, accessToken));
    expect(step4.response.status, 'step 4 introspect').to.equal(200);
    expect(step4.response.body, 'step 4: inactive on the next call').to.deep.equal({
      active: false,
    });
    expect(step4.refusals, 'step 4: exactly one refusal record').to.have.lengthOf(1);
    expect(step4.refusals[0].detail, 'step 4: refused for status').to.equal('grant_status:revoked');

    // 5. The same subject token can no longer be exchanged, for the same reason.
    const step5 = await withRefusals(app, () => exchange(app, accessToken));
    expect(step5.response.status, 'step 5 re-exchange').to.equal(400);
    expect(step5.response.body.error).to.equal('invalid_grant');
    expect(step5.response.body).to.not.have.property('access_token');
    expect(step5.refusals, 'step 5: exactly one refusal record').to.have.lengthOf(1);
    expect(step5.refusals[0].eventType).to.equal(EXCHANGE_ANOMALY_EVENT);
    expect(step5.refusals[0].detail, 'step 5: refused for status').to.equal('grant_status:revoked');

    // And the reason is the write, recorded where introspection reads it.
    const grantRow = db.grants.rows.find((row) => row.grant_id === GRANT_ID);
    expect(grantRow.status).to.equal('revoked');
  });

  it('revokes only the named grant: not the same user on another assistant, not another user on the same assistant', async () => {
    const db = makeDb();
    const app = makeApp(db);
    const revokedToken = mintAccessToken({ grantId: GRANT_ID, clientId: ASSISTANT_CLIENT_ID });
    const otherToken = mintAccessToken({
      grantId: OTHER_GRANT_ID,
      clientId: OTHER_ASSISTANT_CLIENT_ID,
    });
    const otherUserToken = mintAccessToken({
      grantId: OTHER_USER_GRANT_ID,
      clientId: ASSISTANT_CLIENT_ID,
      userId: OTHER_USER_ID,
    });

    expect((await exchange(app, revokedToken)).status).to.equal(200);
    expect((await exchange(app, otherToken)).status).to.equal(200);
    expect((await introspect(app, otherUserToken)).body.active, 'G3 active before').to.equal(true);

    expect((await disconnect(app, GRANT_ID)).status).to.equal(204);

    // Positive anchor: the disconnect did land, so "the others survived" below
    // cannot pass on a DELETE that wrote nothing.
    const revoked = await introspect(app, revokedToken);
    expect(revoked.body, 'G must be inactive after its disconnect').to.deep.equal({
      active: false,
    });
    const revokedRefresh = db.refreshTokens.rows.find((row) => row.grant_id === GRANT_ID);
    expect(revokedRefresh.revoked_at, "G's refresh family must be swept").to.be.a('string');

    // G3 — another user, same assistant: a revocation keyed on client alone hits this.
    const otherUser = await introspect(app, otherUserToken);
    expect(otherUser.status).to.equal(200);
    expect(otherUser.body.active, 'G3 must stay active').to.equal(true);
    expect(otherUser.body.grant_id).to.equal(OTHER_USER_GRANT_ID);

    // G2 — same user, another assistant: a revocation keyed on user alone hits this.
    const other = await introspect(app, otherToken);
    expect(other.status).to.equal(200);
    expect(other.body.active, 'G2 must stay active').to.equal(true);
    expect(other.body.grant_id).to.equal(OTHER_GRANT_ID);

    const otherExchange = await exchange(app, otherToken);
    expect(otherExchange.status, 'G2 must still exchange').to.equal(200);
    expect(credentialClaims(otherExchange).grant_id).to.equal(OTHER_GRANT_ID);

    const otherRefresh = db.refreshTokens.rows.find((row) => row.grant_id === OTHER_GRANT_ID);
    expect(otherRefresh.revoked_at, "G2's refresh family must be untouched").to.equal(null);
    const otherUserRefresh = db.refreshTokens.rows.find(
      (row) => row.grant_id === OTHER_USER_GRANT_ID
    );
    expect(otherUserRefresh.revoked_at, "G3's refresh family must be untouched").to.equal(null);
  });
});
