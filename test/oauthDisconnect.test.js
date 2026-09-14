// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Same guard as
// test/authService.oauthExchange.test.js. Must run before any require below.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const express = require('express');
const request = require('supertest');

const { createOauthRouter } = require('../routes/oauth');
const realIntrospectionLog = require('../services/oauth/introspectionLog');

/**
 * DELETE /api/oauth/grants/:grantId. Real router/controller/service; doubles
 * for Supabase, bearer, origin, and log sinks. The Supabase double records
 * filters and refuses unexpected shapes — a permissive double would go green
 * for code that revokes the grant and never touches refresh tokens.
 */

const ORIGIN = 'https://gonutrihelp.vercel.app';
const PREVIEW_ORIGIN = 'https://frontend-nutrihelp-eta.vercel.app';
const GRANT_ID = '22d9ede4-4195-4cba-addf-a44efa16cf53';
const OTHER_GRANT_ID = '9f1c0b2f-5d7c-4e90-8a1e-3f1b6a526d1e';
const USER_ID = 42;
const CLIENT_ID = 'https://claude.ai/mcp-client';
const RESOURCE = 'https://mcp.nutrihelp.test/mcp';

const ACTIVE_GRANT = {
  grant_id: GRANT_ID,
  user_id: USER_ID,
  client_id: CLIENT_ID,
  resource: RESOURCE,
  status: 'active',
};

/**
 * @param grant   the row the (grant_id, user_id) filter resolves to, or null
 * @param errors  { lookup, grantUpdate, refreshUpdate } to force failures
 */
const makeDb = ({ grant = ACTIVE_GRANT, errors = {} } = {}) => {
  // Clone is the store — updates mutate it so retries re-read written state.
  // Do not mutate ACTIVE_GRANT (shared module constant).
  const row = grant ? { ...grant } : null;

  const calls = {
    lookupFilters: [],
    grantUpdates: [],
    grantUpdateFilters: [],
    refreshUpdates: [],
    refreshUpdateFilters: [],
    refreshIsNull: [],
  };

  const grantSelectChain = () => {
    const chain = {
      eq: (col, val) => {
        calls.lookupFilters.push([col, val]);
        return chain;
      },
      maybeSingle: async () => {
        if (errors.lookup) return { data: null, error: errors.lookup };
        // Only return the row when BOTH filters match.
        const byGrant = calls.lookupFilters.find(([c]) => c === 'grant_id');
        const byUser = calls.lookupFilters.find(([c]) => c === 'user_id');
        if (!byGrant || !byUser) {
          throw new Error('lookup must filter on both grant_id and user_id');
        }
        if (!row) return { data: null, error: null };
        const matches = row.grant_id === byGrant[1] && row.user_id === byUser[1];
        return { data: matches ? { ...row } : null, error: null };
      },
    };
    return chain;
  };

  return {
    calls,
    from(table) {
      if (table === 'mcp_client_grants') {
        return {
          select: () => grantSelectChain(),
          update: (patch) => {
            calls.grantUpdates.push(patch);
            const chain = {
              eq: (col, val) => {
                calls.grantUpdateFilters.push([col, val]);
                return chain;
              },
              then: undefined,
            };
            // Awaiting the chain resolves it; supabase-js builders are thenable.
            chain.then = (resolve) => {
              if (errors.grantUpdate) return resolve({ error: errors.grantUpdate });
              // Reflect the write or double-call tests never hit the retry path.
              if (row) Object.assign(row, patch);
              return resolve({ error: null });
            };
            return chain;
          },
        };
      }

      if (table === 'oauth_refresh_tokens') {
        return {
          update: (patch) => {
            calls.refreshUpdates.push(patch);
            const chain = {
              eq: (col, val) => {
                calls.refreshUpdateFilters.push([col, val]);
                return chain;
              },
              is: (col, val) => {
                calls.refreshIsNull.push([col, val]);
                return chain;
              },
              then: undefined,
            };
            chain.then = (resolve) =>
              resolve(errors.refreshUpdate ? { error: errors.refreshUpdate } : { error: null });
            return chain;
          },
        };
      }

      throw new Error(`unexpected table: ${table}`);
    },
  };
};

/**
 * @param sinks  when set, real introspectionLog runs with only the sinks
 *               beneath it doubled — needed to assert stamped event identity.
 */
const makeApp = ({
  db = makeDb(),
  user = { userId: USER_ID },
  origin = ORIGIN,
  log,
  sinks,
} = {}) => {
  const seen = { operational: [], security: [] };
  const deps = {
    supabase: db,
    authenticateToken: (req, res, next) => {
      if (!user) return res.status(401).json({ error: 'unauthorized' });
      req.user = user;
      return next();
    },
    oauthConfig: { frontendOrigin: () => origin },
    introspectionLog:
      log ||
      (sinks
        ? realIntrospectionLog
        : {
            logOperational: async (ctx) => seen.operational.push(ctx),
            logGrantRefusal: async (ctx) => seen.security.push(ctx),
          }),
  };

  if (sinks) {
    deps.errorLogService = sinks.errorLogService || {
      logError: async (r) => seen.operational.push(r),
    };
    deps.securityEventService = sinks.securityEventService || {
      logSecurityEvent: async (r) => seen.security.push(r),
    };
  }

  const app = express();
  app.use('/api/oauth', createOauthRouter(deps));
  app.seen = seen;
  return app;
};

const disconnect = (app, grantId = GRANT_ID, originHeader = ORIGIN) => {
  const r = request(app).delete(`/api/oauth/grants/${grantId}`);
  if (originHeader !== null) r.set('Origin', originHeader);
  return r.set('x-correlation-id', crypto.randomUUID());
};

describe('DELETE /api/oauth/grants/:grantId', () => {
  describe('the cascade — revocation must reach the refresh families', () => {
    it('revokes the grant AND every live refresh token carrying it', async () => {
      // Schema has no status cascade; code must sweep refresh families.
      const db = makeDb();

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(204);
      expect(db.calls.grantUpdates).to.have.lengthOf(1);
      expect(db.calls.grantUpdates[0].status).to.equal('revoked');

      expect(db.calls.refreshUpdates, 'refresh sweep never ran').to.have.lengthOf(1);
      expect(db.calls.refreshUpdates[0].revoked_at).to.be.a('string');
      expect(db.calls.refreshUpdateFilters).to.deep.include(['grant_id', GRANT_ID]);
      expect(db.calls.refreshIsNull).to.deep.include(['revoked_at', null]);
    });

    it('sweeps refresh tokens even when the grant was already revoked', async () => {
      // Retry after a prior failed sweep must still finish the job.
      const db = makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(204);
      expect(db.calls.grantUpdates, 'must not re-stamp revoked_at').to.have.lengthOf(0);
      expect(db.calls.refreshUpdates, 'sweep must still run').to.have.lengthOf(1);
    });

    it('sets revoked_at alongside status, which the CHECK constraint also requires', async () => {
      const db = makeDb();

      await disconnect(makeApp({ db }));

      const patch = db.calls.grantUpdates[0];
      expect(patch.status).to.equal('revoked');
      expect(patch.revoked_at).to.be.a('string');
      expect(Number.isNaN(Date.parse(patch.revoked_at))).to.equal(false);
      expect(patch.revoke_reason).to.be.a('string').and.not.equal('');
    });

    it('answers 503, not 204, when the refresh sweep fails after the grant was revoked', async () => {
      const db = makeDb({ errors: { refreshUpdate: { code: '08006' } } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(503);
      expect(db.calls.grantUpdates).to.have.lengthOf(1);
    });

    it('answers 503 and never touches refresh tokens when the grant update fails', async () => {
      const db = makeDb({ errors: { grantUpdate: { code: '08006' } } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(503);
      expect(db.calls.refreshUpdates).to.have.lengthOf(0);
    });
  });

  describe('ownership is the control, not the opacity of the id', () => {
    it('answers 404 for a grant belonging to someone else', async () => {
      const db = makeDb({ grant: { ...ACTIVE_GRANT, user_id: 99 } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(404);
      expect(db.calls.grantUpdates).to.have.lengthOf(0);
      expect(db.calls.refreshUpdates).to.have.lengthOf(0);
    });

    it('answers 404 for a grant that does not exist, identically', async () => {
      const db = makeDb({ grant: null });

      const response = await disconnect(makeApp({ db }), OTHER_GRANT_ID);

      expect(response.status).to.equal(404);
    });

    it('returns the same body for "not yours" and "no such grant"', async () => {
      const notYours = await disconnect(
        makeApp({ db: makeDb({ grant: { ...ACTIVE_GRANT, user_id: 99 } }) })
      );
      const missing = await disconnect(makeApp({ db: makeDb({ grant: null }) }), OTHER_GRANT_ID);

      expect(notYours.status).to.equal(missing.status);
      expect(notYours.body).to.deep.equal(missing.body);
    });

    it('filters the lookup on BOTH grant_id and user_id', async () => {
      // Double throws if either filter is missing.
      const db = makeDb();

      await disconnect(makeApp({ db }));

      expect(db.calls.lookupFilters).to.deep.include(['grant_id', GRANT_ID]);
      expect(db.calls.lookupFilters).to.deep.include(['user_id', USER_ID]);
    });

    it('re-asserts ownership on the mutating statement, not just the lookup', async () => {
      const db = makeDb();

      await disconnect(makeApp({ db }));

      expect(db.calls.grantUpdateFilters).to.deep.include(['grant_id', GRANT_ID]);
      expect(db.calls.grantUpdateFilters).to.deep.include(['user_id', USER_ID]);
    });
  });

  describe('idempotence — disconnect is not an exceptional operation', () => {
    it('answers 204 when the grant is already revoked', async () => {
      const db = makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(204);
    });

    it('answers 204 for a replaced grant too', async () => {
      const db = makeDb({ grant: { ...ACTIVE_GRANT, status: 'replaced' } });

      const response = await disconnect(makeApp({ db }));

      expect(response.status).to.equal(204);
    });

    it('returns no body on success', async () => {
      const response = await disconnect(makeApp());

      expect(response.status).to.equal(204);
      expect(response.text === '' || response.text === undefined).to.equal(true);
    });

    it('survives a double-click: the second call re-reads a REVOKED grant and still sweeps', async () => {
      // makeDb reflects writes; second call must hit already-revoked + re-sweep.
      const db = makeDb({ grant: ACTIVE_GRANT });
      const app = makeApp({ db });

      const first = await disconnect(app);
      const second = await disconnect(app);

      expect(first.status).to.equal(204);
      expect(second.status).to.equal(204);

      expect(db.calls.grantUpdates, 'the retry re-stamped revoked_at').to.have.lengthOf(1);
      expect(db.calls.refreshUpdates, 'sweep did not run on the retry').to.have.lengthOf(2);
      expect(app.seen.security.map((e) => e.detail)).to.deep.equal([
        'user_disconnect',
        'user_disconnect_already_revoked',
      ]);
    });
  });

  describe('the path carries an opaque uuid and nothing else', () => {
    it('answers 404 for a malformed grant id without querying the database', async () => {
      const db = makeDb();

      const response = await disconnect(makeApp({ db }), 'not-a-uuid');

      expect(response.status).to.equal(404);
      expect(db.calls.lookupFilters, 'malformed id reached the database').to.have.lengthOf(0);
    });

    it('answers 404 for a url-shaped path segment rather than letting it reach a query', async () => {
      const db = makeDb();

      const response = await disconnect(
        makeApp({ db }),
        encodeURIComponent('https://claude.ai/mcp-client')
      );

      expect(response.status).to.equal(404);
      expect(db.calls.lookupFilters).to.have.lengthOf(0);
    });
  });

  describe('bearer and origin, removed independently', () => {
    it('answers 401 without a valid bearer token', async () => {
      const response = await disconnect(makeApp({ user: null }));

      expect(response.status).to.equal(401);
    });

    it('answers 403 when the Origin header is absent', async () => {
      const response = await disconnect(makeApp(), GRANT_ID, null);

      expect(response.status).to.equal(403);
    });

    it('answers 403 for a literal "null" Origin', async () => {
      const response = await disconnect(makeApp(), GRANT_ID, 'null');

      expect(response.status).to.equal(403);
    });

    it('answers 403 for a PREVIEW deployment on the same wildcard', async () => {
      const response = await disconnect(makeApp(), GRANT_ID, PREVIEW_ORIGIN);

      expect(response.status).to.equal(403);
    });

    it('answers 403 for an origin that merely ends with the allowed one', async () => {
      const response = await disconnect(makeApp(), GRANT_ID, 'https://evil-gonutrihelp.vercel.app');

      expect(response.status).to.equal(403);
    });

    it('answers 503, not 403, when no frontend origin is configured', async () => {
      const response = await disconnect(makeApp({ origin: null }));

      expect(response.status).to.equal(503);
    });

    it('checks the bearer before the origin, so an anonymous caller learns nothing about config', async () => {
      const response = await disconnect(makeApp({ user: null, origin: null }), GRANT_ID, null);

      expect(response.status).to.equal(401);
    });

    // eslint-disable-next-line mocha/no-skipped-tests
    it.skip('rejects a request without the action-bound CSRF token [BLOCKED: no issuer]', () => {
      // Contract wants Bearer+Origin+CSRF; issuer is GET /api/oauth/grants
      // (unowned). Inventing a shape would fake coverage. Not skipped because
      // the route is dark — OAUTH_ROUTES_ENABLED also mounts /introspect.
      // Gap is action-binding, not cross-site forgery (Bearer-only). See
      // routes/oauth.js. Unskip when GET /api/oauth/grants has an owner.
    });
  });

  describe('logging', () => {
    it('records a successful disconnection on the security channel with user, grant and client', async () => {
      const app = makeApp();

      await disconnect(app);

      expect(app.seen.security).to.have.lengthOf(1);
      expect(app.seen.security[0].userId).to.equal(USER_ID);
      expect(app.seen.security[0].clientId).to.equal(CLIENT_ID);
      expect(app.seen.security[0].detail).to.equal('user_disconnect');
      expect(app.seen.operational).to.have.lengthOf(0);
    });

    it('distinguishes an already-revoked disconnect in the record', async () => {
      const app = makeApp({ db: makeDb({ grant: { ...ACTIVE_GRANT, status: 'revoked' } }) });

      await disconnect(app);

      expect(app.seen.security[0].detail).to.equal('user_disconnect_already_revoked');
    });

    it('logs a write failure operationally, not as a security event', async () => {
      const app = makeApp({ db: makeDb({ errors: { refreshUpdate: { code: '08006' } } }) });

      await disconnect(app);

      expect(app.seen.operational).to.have.lengthOf(1);
      expect(app.seen.operational[0].httpStatus).to.equal(503);
      expect(app.seen.security).to.have.lengthOf(0);
    });

    it('stamps the DISCONNECT event identity on the security record', async () => {
      // Real introspectionLog — defaults are introspect; must override.
      const security = [];
      const app = makeApp({
        sinks: { securityEventService: { logSecurityEvent: async (r) => security.push(r) } },
      });

      await disconnect(app);

      expect(security).to.have.lengthOf(1);
      expect(security[0].event_type).to.equal('mcp_grant_user_disconnected');
      expect(security[0].resource).to.equal('DELETE /api/oauth/grants/:grantId');
      expect(security[0].metadata.detail).to.equal('user_disconnect');
    });

    it('stamps the disconnect endpoint on an operational failure too', async () => {
      const operational = [];
      const app = makeApp({
        db: makeDb({ errors: { refreshUpdate: { code: '08006' } } }),
        sinks: { errorLogService: { logError: async (r) => operational.push(r) } },
      });

      const response = await disconnect(app);

      expect(response.status).to.equal(503);
      expect(operational).to.have.lengthOf(1);
      expect(operational[0].additionalContext.endpoint).to.equal(
        'DELETE /api/oauth/grants/:grantId'
      );
      expect(operational[0].error.message).to.equal('oauth_disconnect:grant_disconnect_failed');
    });

    it('NEVER labels a disconnect with introspection identity, on either path', async () => {
      // Positive asserts alone stay green if constants regress to introspect.
      const INTROSPECTION_MARKERS = [
        'mcp_introspection_grant_inactive',
        'POST /api/oauth/introspect',
        'oauth_introspect:',
      ];

      const security = [];
      const operational = [];
      const sinks = {
        securityEventService: { logSecurityEvent: async (r) => security.push(r) },
        // Error.message must be lifted — JSON.stringify(Error) is {}.
        errorLogService: {
          logError: async (r) =>
            operational.push({ ...r, errorMessage: r.error && r.error.message }),
        },
      };

      await disconnect(makeApp({ sinks }));
      await disconnect(
        makeApp({ sinks, db: makeDb({ errors: { refreshUpdate: { code: '08006' } } }) })
      );

      expect(security, 'success path logged no security event').to.have.lengthOf(1);
      expect(operational, 'failure path logged no operational event').to.have.lengthOf(1);

      const serialised = JSON.stringify({ security, operational });
      INTROSPECTION_MARKERS.forEach((marker) => {
        expect(serialised, `disconnect claimed introspection identity: ${marker}`).to.not.contain(
          marker
        );
      });
    });

    it('never puts the client URL in a path or the token in a log', async () => {
      const app = makeApp();

      await disconnect(app);

      const serialised = JSON.stringify(app.seen);
      expect(serialised).to.contain(CLIENT_ID);
      expect(serialised).to.not.contain('Bearer');
    });
  });

  describe('reconnect after disconnect — this is a disconnect, not a ban', () => {
    it('revokes by status rather than deleting the row', async () => {
      // Partial unique index is WHERE status='active'; revoke frees the slot.
      const db = makeDb();

      await disconnect(makeApp({ db }));

      expect(db.calls.grantUpdates).to.have.lengthOf(1);
      expect(db.calls.grantUpdates[0].status).to.equal('revoked');
      expect(db.calls.grantUpdates[0]).to.not.have.property('deleted');
    });
  });
});
