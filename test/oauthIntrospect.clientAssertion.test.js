// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Same guard as
// test/authService.oauthExchange.test.js. Must run before any require below
// that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');
const jwt = require('jsonwebtoken');

const clientAssertionVerifier = require('../services/oauth/clientAssertionVerifier');

/**
 * private_key_jwt for introspect. Forgery tests prove none/HS256 are
 * arithmetically valid first (jwa accepts them; Q16c must refuse in our code).
 * Use deps injection, not proxyquire (broken under jest’s module loader).
 */

const INTROSPECTION_URL = 'https://api.nutrihelp.test/api/oauth/introspect';
const TOKEN_URL = 'https://api.nutrihelp.test/api/oauth/token';
const ISSUER_IDENTIFIER = 'https://api.nutrihelp.test';
const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPem = {
  private: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: rsa.publicKey.export({ type: 'spki', format: 'pem' }),
};

const otherRsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherRsaPem = { public: otherRsa.publicKey.export({ type: 'spki', format: 'pem' }) };

const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ecPem = {
  private: ec.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  public: ec.publicKey.export({ type: 'spki', format: 'pem' }),
};

const CONFIDENTIAL_CLIENT = {
  client_id: MCP_CLIENT_ID,
  client_type: 'service_confidential',
  token_endpoint_auth_method: 'private_key_jwt',
  is_active: true,
};

const keyRow = (overrides = {}) => ({
  kid: null,
  alg: 'RS256',
  public_key_pem: rsaPem.public,
  slot: 1,
  ...overrides,
});

/**
 * Supabase double: does NOT apply the key cap (returns all rows, records
 * limit) so query.limit and loop.slice are tested separately. Records purge
 * filter/order/limit so expires_at vs created_at regressions are visible.
 */
const makeDb = ({
  clientRow = CONFIDENTIAL_CLIENT,
  keyRows = [keyRow()],
  insertError = null,
  purgeError = null,
} = {}) => {
  const calls = {
    clientLookups: 0,
    keyLookups: 0,
    inserts: 0,
    purges: 0,
    keyFilters: [],
    keyLimit: null,
    purgeFilter: null,
    purgeOrder: null,
    purgeLimit: null,
  };

  return {
    calls,
    from(table) {
      if (table === 'oauth_clients') {
        return {
          select: () => ({
            eq: () => ({
              maybeSingle: async () => {
                calls.clientLookups += 1;
                return { data: clientRow, error: null };
              },
            }),
          }),
        };
      }

      if (table === 'oauth_client_keys') {
        const chain = {
          select: () => chain,
          eq: (column, value) => {
            calls.keyFilters.push([column, value]);
            return chain;
          },
          lte: () => chain,
          gt: () => chain,
          order: () => chain,
          limit: async (n) => {
            calls.keyLookups += 1;
            calls.keyLimit = n;
            // Everything, uncapped — the code under test must do the capping.
            return { data: keyRows, error: null };
          },
        };
        return chain;
      }

      if (table === 'oauth_client_assertion_jti') {
        return {
          insert: async () => {
            calls.inserts += 1;
            return { error: insertError };
          },
          // PostgREST 12: DELETE+limit requires order — mirror that chain.
          delete: () => ({
            lt: (column, value) => {
              calls.purgeFilter = [column, value];
              return {
                order: (column2, options) => {
                  calls.purgeOrder = [column2, options];
                  return {
                    limit: async (n) => {
                      calls.purges += 1;
                      calls.purgeLimit = n;
                      return { error: purgeError };
                    },
                  };
                },
              };
            },
          }),
        };
      }

      throw new Error(`unexpected table: ${table}`);
    },
  };
};

const configDouble = (overrides = {}) => ({
  introspectionAudience: () => INTROSPECTION_URL,
  mcpAccessTokenIssuer: () => ISSUER_IDENTIFIER,
  mcpResourceIdentifier: () => 'https://mcp.nutrihelp.test/mcp',
  ...overrides,
});

const verify = (params, { db = makeDb(), config = {}, random } = {}) =>
  clientAssertionVerifier.verifyClientAssertion(params, {
    supabase: db,
    oauthConfig: configDouble(config),
    ...(random ? { random } : {}),
  });

const assertionClaims = (overrides = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: MCP_CLIENT_ID,
    sub: MCP_CLIENT_ID,
    aud: INTROSPECTION_URL,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 60,
    ...overrides,
  };
};

const signAssertion = (claims = {}, { key = rsaPem.private, algorithm = 'RS256', keyid } = {}) =>
  jwt.sign(assertionClaims(claims), key, keyid ? { algorithm, keyid } : { algorithm });

const request = (assertion, overrides = {}) => ({
  client_assertion: assertion,
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  ...overrides,
});

describe('OAuth introspection — private_key_jwt client authentication', () => {
  describe('algorithm confusion — the library accepts these, Q16c does not', () => {
    it('refuses alg:none, and the unsigned assertion is otherwise well-formed', async () => {
      const unsigned = jwt.sign(assertionClaims(), '', { algorithm: 'none' });

      // Control: the token really is a parseable JWT that a permissive
      // verifier would accept. If this ever fails, the refusal below would be
      // passing for the wrong reason.
      expect(jwt.decode(unsigned)).to.include({ iss: MCP_CLIENT_ID });
      expect(jwt.verify(unsigned, '', { algorithms: ['none'] })).to.include({ iss: MCP_CLIENT_ID });

      const db = makeDb();
      const result = await verify(request(unsigned), { db });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('algorithm_not_allowed:none');
      expect(db.calls.inserts).to.equal(0);
    });

    it('refuses an HS256 assertion signed with the client public key, though its signature is arithmetically valid', async () => {
      // The classic asymmetric-to-symmetric confusion: public_key_pem is the
      // stored verification material AND, under HS256, the HMAC secret.
      const forged = jwt.sign(assertionClaims(), rsaPem.public, { algorithm: 'HS256' });

      // Control: the forgery carries a genuinely valid HMAC over the public
      // key. Computed with raw crypto rather than jwt.verify, because
      // jsonwebtoken 9 has its own "secretOrPublicKey must be a symmetric key
      // when using HS256" guard — which is a welcome second layer but is NOT
      // what enforces Q16c here, and a control that leaned on it would be
      // testing the library instead of this verifier.
      const [header64, payload64, signature64] = forged.split('.');
      const validHmac = crypto
        .createHmac('sha256', rsaPem.public)
        .update(`${header64}.${payload64}`)
        .digest('base64url');
      expect(signature64).to.equal(validHmac);
      expect(jwt.decode(forged)).to.include({ iss: MCP_CLIENT_ID });

      const db = makeDb();
      const result = await verify(request(forged), { db });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('algorithm_not_allowed:HS256');
      expect(db.calls.inserts).to.equal(0);
    });

    it('bounds the attacker-controlled algorithm name before it reaches a log', async () => {
      // L3. `alg` is unverified, unbounded, attacker-chosen, and was
      // interpolated straight into a detail string bound for error_logs.
      const hostile = 'HS256' + '\n'.repeat(500) + 'X'.repeat(5000);
      const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
      const crafted = `${encode({ alg: hostile, typ: 'JWT' })}.${encode(assertionClaims())}.c2ln`;

      const result = await verify(request(crafted));

      expect(result.httpStatus).to.equal(401);
      expect(result.detail.length).to.be.below(64);
      expect(result.detail).to.not.contain('\n');
      expect(result.detail).to.equal('algorithm_not_allowed:HS256XXXXXXXXXXX');
    });

    it('refuses an assertion whose header algorithm is outside the Q16c allowlist', async () => {
      const psSigned = jwt.sign(assertionClaims(), rsaPem.private, { algorithm: 'PS256' });

      const result = await verify(request(psSigned));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('algorithm_not_allowed:PS256');
    });

    it('verifies against the algorithm on the KEY ROW, not the one in the header', async () => {
      // ⚠️ THE FIXTURE IS THE TEST. The key row claims ES256 while holding an
      // RSA public key, and the assertion is a genuine RS256 signature by the
      // matching private key. So the ONLY thing that can refuse it is the pin
      // reading `alg` from the key row: swap the pin to the header's value and
      // an RSA key verifies an RSA signature, and this goes green.
      //
      // An EC key here instead would make the test unfalsifiable — an RS256
      // signature cannot verify against an EC public key whatever is pinned,
      // so it would pass with the pin removed and prove nothing. That is what
      // it did before, which is why the pin had ZERO proofs rather than one.
      //
      // Mutation-proved: changing `algorithms: [keyAlgorithm]` to
      // `[headerAlgorithm]` in clientAssertionVerifier.js — that one line and
      // nothing else — turns this red with `expected true to equal false`.
      // Under that mutant an attacker holding only the PUBLIC key
      // authenticates as the MCP server.
      const db = makeDb({ keyRows: [keyRow({ alg: 'ES256', public_key_pem: rsaPem.public })] });

      const result = await verify(request(signAssertion()), { db });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('assertion_signature_rejected');
    });
  });

  describe('audience — Q16a, exactly this endpoint and nothing else', () => {
    it('accepts the introspection endpoint URL', async () => {
      const result = await verify(request(signAssertion()));

      expect(result.ok).to.equal(true);
      expect(result.clientId).to.equal(MCP_CLIENT_ID);
    });

    it('refuses an assertion minted for the sibling token endpoint', async () => {
      const result = await verify(request(signAssertion({ aud: TOKEN_URL })));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_signature_rejected');
    });

    it('refuses the issuer identifier presented as aud', async () => {
      const result = await verify(request(signAssertion({ aud: ISSUER_IDENTIFIER })));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
    });

    it('refuses a multi-valued aud that merely contains the right URL', async () => {
      // ⚠️ jwt.verify's `audience` option is satisfied by ANY element of an
      // array aud, so ["<correct>", "https://evil.test"] passes it. RFC 7519
      // permits multi-valued aud; Q16a does not — this endpoint accepts ONLY
      // its own absolute URL. Without the scalar comparison after
      // verification, "compared exactly" read stronger than what was enforced.
      const result = await verify(
        request(signAssertion({ aud: [INTROSPECTION_URL, 'https://evil.test'] }))
      );

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_audience_not_sole');
    });

    it('answers 503, not 401, when the expected audience is unconfigured', async () => {
      // Our configuration fault, not their credential. 503 is retryable and
      // truthful; 401 would blame the caller for our missing variable.
      const result = await verify(request(signAssertion()), {
        config: { introspectionAudience: () => null },
      });

      expect(result.httpStatus).to.equal(503);
      expect(result.detail).to.equal('introspection_audience_unconfigured');
    });
  });

  describe('client identity', () => {
    it('requires iss and sub to be the same registered client id', async () => {
      const result = await verify(
        request(signAssertion({ sub: 'https://mcp.nutrihelp.test/other' }))
      );

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('assertion_iss_sub_mismatch');
    });

    it('never verifies a private_key_jwt presented by an assistant_public client', async () => {
      // Asserted here as well as in the schema: the contract asks for this
      // refusal to be provable in application code, not only by a CHECK.
      const db = makeDb({
        clientRow: {
          ...CONFIDENTIAL_CLIENT,
          client_type: 'assistant_public',
          token_endpoint_auth_method: 'none',
        },
      });

      const result = await verify(request(signAssertion()), { db });

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('client_not_confidential');
    });

    it('refuses a deactivated client', async () => {
      const db = makeDb({ clientRow: { ...CONFIDENTIAL_CLIENT, is_active: false } });

      const result = await verify(request(signAssertion()), { db });

      expect(result.detail).to.equal('client_unknown_or_inactive');
    });

    it('refuses an unregistered client', async () => {
      const db = makeDb({ clientRow: null });

      const result = await verify(request(signAssertion()), { db });

      expect(result.detail).to.equal('client_unknown_or_inactive');
    });
  });

  describe('multi-key trial — the Q16b relaxation, capped at two', () => {
    it('verifies against the second in-window key when the first does not match', async () => {
      const db = makeDb({
        keyRows: [
          keyRow({ slot: 1, public_key_pem: otherRsaPem.public }),
          keyRow({ slot: 2, public_key_pem: rsaPem.public }),
        ],
      });

      const result = await verify(request(signAssertion()), { db });

      expect(result.ok).to.equal(true);
    });

    it('stops at two keys — a third in-window key is never tried', async () => {
      // The cap is the acceptance criterion of the Q16b follow-up ticket, so
      // it is tested behaviourally: sign with the THIRD key, require refusal.
      const db = makeDb({
        keyRows: [
          keyRow({ slot: 1, public_key_pem: otherRsaPem.public }),
          keyRow({ slot: 2, public_key_pem: ecPem.public, alg: 'ES256' }),
          keyRow({ slot: 1, public_key_pem: rsaPem.public }),
        ],
      });

      const result = await verify(request(signAssertion()), { db });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('assertion_signature_rejected');
    });

    it('selects by kid when the assertion carries one', async () => {
      const db = makeDb({ keyRows: [keyRow({ kid: 'key-2' })] });
      const withKid = signAssertion({}, { keyid: 'key-2' });

      const result = await verify(request(withKid), { db });

      expect(result.ok).to.equal(true);
      expect(db.calls.keyFilters).to.deep.include(['kid', 'key-2']);
    });

    it('caps the query itself at two rows', async () => {
      // The other cap. The loop's .slice() is proved by the test above (which
      // signs with a third row the double returns uncapped); this proves the
      // query never asks for more than two in the first place.
      const db = makeDb({ keyRows: [keyRow(), keyRow({ slot: 2 })] });

      await verify(request(signAssertion()), { db });

      expect(db.calls.keyLimit).to.equal(clientAssertionVerifier.MAX_KEYS_TRIED);
      expect(db.calls.keyLimit).to.equal(2);
    });

    it('refuses a forged assertion with 401 even when a later key row is unverifiable', async () => {
      // L1. `unsupportedAlgorithm` used to be sticky across the loop, so a
      // client with slot 1 = RS256 and slot 2 = EdDSA turned a plainly forged
      // assertion into a 503 — telling an attacker's retry loop to keep going
      // instead of stopping hard. 503 belongs only to the case where every row
      // tried was unverifiable.
      const db = makeDb({
        keyRows: [
          keyRow({ slot: 1, public_key_pem: otherRsaPem.public }),
          keyRow({ slot: 2, alg: 'EdDSA' }),
        ],
      });

      const result = await verify(request(signAssertion()), { db });

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_signature_rejected');
    });

    it('refuses when no key is in window', async () => {
      const db = makeDb({ keyRows: [] });

      const result = await verify(request(signAssertion()), { db });

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('no_key_in_window');
    });

    it('accepts an ES256 assertion against an ES256 key row', async () => {
      const db = makeDb({ keyRows: [keyRow({ alg: 'ES256', public_key_pem: ecPem.public })] });
      const assertion = signAssertion({}, { key: ecPem.private, algorithm: 'ES256' });

      const result = await verify(request(assertion), { db });

      expect(result.ok).to.equal(true);
    });
  });

  describe('EdDSA — a Q16c gap, refused loudly rather than narrowed silently', () => {
    it('answers 503 with a named gap when the registered key is EdDSA', async () => {
      // jsonwebtoken/jwa cannot verify EdDSA (measured: `"EdDSA" is not a
      // valid algorithm`). EdDSA is nonetheless a binding part of the Q16c
      // allowlist, so this must NOT present as "algorithm not allowed" — that
      // would read as a decision to drop it. It is our gap, and 503 says so.
      const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
      const handCrafted = `${encode({ alg: 'EdDSA', typ: 'JWT' })}.${encode(assertionClaims())}.c2ln`;

      const db = makeDb({ keyRows: [keyRow({ alg: 'EdDSA' })] });
      const result = await verify(request(handCrafted), { db });

      expect(result.httpStatus).to.equal(503);
      expect(result.detail).to.equal('unsupported_algorithm_q16c_gap:EdDSA');
    });

    it('keeps EdDSA in the Q16c allowlist constant even though it cannot be verified here', () => {
      expect(clientAssertionVerifier.Q16C_ALGORITHM_ALLOWLIST).to.deep.equal([
        'RS256',
        'ES256',
        'EdDSA',
      ]);
      expect(clientAssertionVerifier.VERIFIABLE_ALGORITHMS).to.deep.equal(['RS256', 'ES256']);
    });
  });

  describe('lifetime and replay', () => {
    it('rejects exp - iat greater than 300 seconds', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await verify(request(signAssertion({ iat: now, exp: now + 301 })));

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_lifetime_too_long');
    });

    it('accepts a lifetime of exactly 300 seconds', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await verify(request(signAssertion({ iat: now, exp: now + 300 })));

      expect(result.ok).to.equal(true);
    });

    it('refuses a crafted assertion whose exp - iat collapses to zero in floating point', async () => {
      // ⚠️ M1/M3. `exp - iat <= 300` bounds two caller-chosen numbers, and at
      // large magnitudes the subtraction collapses: 1e15 - (1e15 - 300) === 0.
      // So this satisfied the lifetime guard, verified, and then reached
      // `new Date((exp + 30) * 1000).toISOString()` — which throws RangeError
      // OUT of the function. Express 4 does not route that to the error
      // handler, so the request produced no response at all: the socket was
      // held until the caller's deadline and the failure was reported as a
      // timeout for something that never timed out.
      const iat = 1e15 - 300;
      const result = await verify(request(signAssertion({ iat, exp: 1e15 })));

      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_expiry_too_far_ahead');
    });

    it('refuses an assertion expiring far in the future even with a short nominal lifetime', async () => {
      // The same hole at ordinary magnitudes: a 300-second window opening a
      // decade from now verifies under an iat-relative bound alone, and its
      // replay row is then retained for a decade — unbounded growth on the
      // highest-write table in the design.
      const iat = Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 3600 - 300;
      const result = await verify(request(signAssertion({ iat, exp: iat + 300 })));

      expect(result.ok).to.equal(false);
      expect(result.detail).to.be.oneOf([
        'assertion_expiry_too_far_ahead',
        'assertion_issued_in_future',
      ]);
    });

    it('refuses an assertion issued in the future beyond the leeway', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await verify(request(signAssertion({ iat: now + 120, exp: now + 180 })));

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('assertion_issued_in_future');
    });

    it('refuses a non-finite exp before it can reach Date construction', async () => {
      // Infinity is `typeof 'number'`, so the original guard admitted it.
      const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
      const now = Math.floor(Date.now() / 1000);
      // JSON has no Infinity literal, so craft the payload textually.
      const header = encode({ alg: 'RS256', typ: 'JWT' });
      const payload = Buffer.from(
        `{"iss":"${MCP_CLIENT_ID}","sub":"${MCP_CLIENT_ID}","aud":"${INTROSPECTION_URL}","jti":"x","iat":${now},"exp":1e999}`
      ).toString('base64url');
      const result = await verify(request(`${header}.${payload}.c2ln`));

      // Refused somewhere — signature, or the finiteness guard. What matters
      // is that it does not throw and does not hang.
      expect(result.ok).to.equal(false);
      expect(result.httpStatus).to.be.oneOf([401, 503]);
    });

    it('accepts an assertion inside the 30 second leeway that has just expired', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await verify(request(signAssertion({ iat: now - 70, exp: now - 10 })));

      expect(result.ok).to.equal(true);
    });

    it('refuses an assertion expired beyond the leeway', async () => {
      const now = Math.floor(Date.now() / 1000);
      const result = await verify(request(signAssertion({ iat: now - 400, exp: now - 340 })));

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('assertion_signature_rejected');
    });

    it('refuses an assertion with no jti', async () => {
      const now = Math.floor(Date.now() / 1000);
      const assertion = jwt.sign(
        {
          iss: MCP_CLIENT_ID,
          sub: MCP_CLIENT_ID,
          aud: INTROSPECTION_URL,
          iat: now,
          exp: now + 60,
        },
        rsaPem.private,
        { algorithm: 'RS256' }
      );

      const result = await verify(request(assertion));

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_jti_absent');
    });

    it('refuses an assertion with no iat', async () => {
      const now = Math.floor(Date.now() / 1000);
      const assertion = jwt.sign(
        {
          iss: MCP_CLIENT_ID,
          sub: MCP_CLIENT_ID,
          aud: INTROSPECTION_URL,
          jti: crypto.randomUUID(),
          exp: now + 60,
        },
        rsaPem.private,
        { algorithm: 'RS256', noTimestamp: true }
      );

      const result = await verify(request(assertion));

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_missing_iat_or_exp');
    });

    it('treats a primary-key collision on (client_id, jti) as a replay', async () => {
      const db = makeDb({ insertError: { code: '23505', message: 'duplicate key' } });

      const result = await verify(request(signAssertion()), { db });

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_replayed');
    });

    it('answers 503 when the replay store itself is unavailable', async () => {
      // A replay store that cannot be written is not a bad credential.
      const db = makeDb({ insertError: { code: '08006', message: 'connection failure' } });

      const result = await verify(request(signAssertion()), { db });

      expect(result.httpStatus).to.equal(503);
      expect(result.detail).to.equal('replay_store_unavailable');
    });

    it('records the jti only after the signature verifies', async () => {
      const db = makeDb({ keyRows: [keyRow({ public_key_pem: otherRsaPem.public })] });

      await verify(request(signAssertion()), { db });

      expect(db.calls.inserts).to.equal(0);
    });
  });

  describe('replay-store purge — migration 002 §4 assigns this to ticket 42', () => {
    it('deletes by expires_at, not created_at, and bounds the batch', async () => {
      // Pin the filter column: created_at would drop rows still in the replay window.
      const db = makeDb();

      const result = await clientAssertionVerifier.purgeExpiredJtis(db, () => 0);

      expect(result.purged).to.equal(true);
      const [column, bound] = db.calls.purgeFilter;
      expect(column).to.equal('expires_at');
      expect(db.calls.purgeLimit).to.equal(clientAssertionVerifier.JTI_PURGE_BATCH_SIZE);

      // The bound is "now", so nothing unexpired is ever in range.
      const boundMs = Date.parse(bound);
      expect(Number.isNaN(boundMs)).to.equal(false);
      expect(Math.abs(boundMs - Date.now())).to.be.below(5000);
    });

    it('orders by expires_at ascending before applying the limit (PostgREST 12 requires it)', async () => {
      // Pin column + direction: no order → PGRST109 every call; descending starves old rows.
      const db = makeDb();

      await clientAssertionVerifier.purgeExpiredJtis(db, () => 0);

      expect(db.calls.purgeOrder).to.not.equal(null);
      const [column, options] = db.calls.purgeOrder;
      expect(column).to.equal('expires_at');
      expect(options).to.deep.equal({ ascending: true });
    });

    it('reports failure when supabase resolves with an error', async () => {
      // supabase-js resolves on failure — must read error, not assume purged:true.
      const db = makeDb({ purgeError: { code: '42601', message: 'syntax error' } });

      const result = await clientAssertionVerifier.purgeExpiredJtis(db, () => 0);

      expect(result.purged).to.equal(false);
      expect(result.error).to.deep.equal({ code: '42601', message: 'syntax error' });
    });

    it('surfaces a purge failure on the verification result so it can be logged', async () => {
      const db = makeDb({ purgeError: { code: '42601', message: 'syntax error' } });

      const result = await verify(request(signAssertion()), { db, random: () => 0 });

      expect(result.ok).to.equal(true);
      expect(result.purge.error).to.deep.equal({ code: '42601', message: 'syntax error' });
    });

    it('purges on a sampled call', async () => {
      const db = makeDb();

      await clientAssertionVerifier.purgeExpiredJtis(db, () => 0);

      expect(db.calls.purges).to.equal(1);
    });

    it('does not purge on an unsampled call', async () => {
      const db = makeDb();

      await clientAssertionVerifier.purgeExpiredJtis(db, () => 0.99);

      expect(db.calls.purges).to.equal(0);
    });

    it('runs the purge on the verification path when sampled', async () => {
      const db = makeDb();

      const result = await verify(request(signAssertion()), { db, random: () => 0 });

      expect(result.ok).to.equal(true);
      expect(db.calls.purges).to.equal(1);
    });

    it('never fails a verification because the purge failed', async () => {
      const db = makeDb();
      const exploding = {
        from: (table) =>
          table === 'oauth_client_assertion_jti'
            ? {
                insert: async () => ({ error: null }),
                // Include .order so this throws from limit, not missing chain link.
                delete: () => ({
                  lt: () => ({
                    order: () => ({
                      limit: async () => {
                        throw new Error('purge exploded');
                      },
                    }),
                  }),
                }),
              }
            : db.from(table),
      };

      const result = await verify(request(signAssertion()), { db: exploding, random: () => 0 });

      expect(result.ok).to.equal(true);
    });
  });

  describe('request shape', () => {
    it('answers 400 for a missing client_assertion_type', async () => {
      const result = await verify({ client_assertion: signAssertion() });

      expect(result.httpStatus).to.equal(400);
      expect(result.reason).to.equal('invalid_request');
    });

    it('answers 400 for the wrong client_assertion_type', async () => {
      const result = await verify(
        request(signAssertion(), {
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
        })
      );

      expect(result.httpStatus).to.equal(400);
    });

    it('answers 400 for a missing client_assertion', async () => {
      const result = await verify({
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      });

      expect(result.httpStatus).to.equal(400);
    });

    it('answers 401 for an undecodable assertion', async () => {
      const result = await verify(request('not-a-jwt'));

      expect(result.httpStatus).to.equal(401);
      expect(result.detail).to.equal('assertion_undecodable');
    });
  });
});
