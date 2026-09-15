// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const http = require('http');

const { expect } = require('chai');

const safeMetadataFetch = require('../services/oauth/safeMetadataFetch');

/**
 * Ticket 41, checklist items 3, 4 and 5 — the outbound request itself.
 * Two layers, tested separately because they can only be tested separately:
 * resolvePinnedAddress   decides. Injected `lookup`, REAL address guard.
 */

// Both must be addresses the guard genuinely allows. Note that the obvious
const ALLOWED_V4 = '93.184.216.34';
const ALLOWED_V6 = '2606:4700:4700::1111';

/** The guard is real here — these are the decisions under test. */
const resolveWith = (addresses, url = 'https://cimd.example/client', extra = {}) => {
  const calls = { lookups: [] };
  const lookup = async (hostname, options) => {
    calls.lookups.push({ hostname, options });
    if (addresses instanceof Error) throw addresses;
    return addresses;
  };
  return {
    calls,
    result: safeMetadataFetch.resolvePinnedAddress(url, { lookup, ...extra }),
  };
};

describe('oauth client metadata — SSRF-safe fetch', () => {
  describe('the URL itself', () => {
    const refuses = async (url) => {
      const { result } = resolveWith([{ address: ALLOWED_V4, family: 4 }], url);
      const outcome = await result;
      expect(outcome.ok).to.equal(false);
      return outcome;
    };

    it('refuses a plaintext http URL', async () => {
      const outcome = await refuses('http://cimd.example/client');

      expect(outcome.reason).to.equal('url_not_https');
    });

    it('refuses a non-web scheme', async () => {
      await refuses('file:///etc/passwd');
      await refuses('ftp://cimd.example/client');
      // gopher: is the classic SSRF protocol-smuggling scheme.
      await refuses('gopher://cimd.example:70/x');
    });

    it('refuses a URL carrying userinfo', async () => {
      await refuses('https://user:pass@cimd.example/client');
      await refuses('https://cimd.example@internal.example/client');
    });

    it('refuses a URL with a query or a fragment', async () => {
      // The schema (mig 002, oauth_clients_id_is_https) forbids both, because
      await refuses('https://cimd.example/client?x=1');
      await refuses('https://cimd.example/client#frag');
    });

    it('refuses something that is not a URL at all', async () => {
      await refuses('not a url');
      await refuses('');
    });

    it('accepts an ordinary https URL', async () => {
      // The section has to let something through, or every case above passes
      const { result } = resolveWith([{ address: ALLOWED_V4, family: 4 }]);

      expect((await result).ok).to.equal(true);
    });
  });

  describe('resolution covers BOTH address families (item 1)', () => {
    it('asks for every address, not just the first', async () => {
      const { calls, result } = resolveWith([{ address: ALLOWED_V4, family: 4 }]);
      await result;

      expect(calls.lookups).to.have.lengthOf(1);
      expect(calls.lookups[0].options.all).to.equal(true);
      expect(calls.lookups[0].options.family).to.equal(0);
    });

    it('⚠️ refuses a host with one PUBLIC A record and one PRIVATE AAAA record', async () => {
      // THE case item 1 is about. A v4-only check sees 93.184.216.34, connects
      const { result } = resolveWith([
        { address: ALLOWED_V4, family: 4 },
        { address: 'fd00::1', family: 6 },
      ]);
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.contain('unique_local');
    });

    it('refuses a host with one public AAAA and one private A', async () => {
      const { result } = resolveWith([
        { address: ALLOWED_V6, family: 6 },
        { address: '10.1.2.3', family: 4 },
      ]);

      expect((await result).ok).to.equal(false);
    });

    it('refuses a host resolving only to the cloud metadata address', async () => {
      const { result } = resolveWith([{ address: '169.254.169.254', family: 4 }]);
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.contain('link_local');
    });

    it('refuses a host resolving to the IPv4-mapped metadata address', async () => {
      const { result } = resolveWith([{ address: '::ffff:169.254.169.254', family: 6 }]);

      expect((await result).ok).to.equal(false);
    });

    it('accepts a host whose every address is public', async () => {
      const { result } = resolveWith([
        { address: ALLOWED_V4, family: 4 },
        { address: ALLOWED_V6, family: 6 },
      ]);
      const outcome = await result;

      expect(outcome.ok).to.equal(true);
      expect(outcome.address).to.equal(ALLOWED_V4);
    });

    it('refuses when DNS returns no addresses', async () => {
      const { result } = resolveWith([]);
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.equal('dns_no_addresses');
    });

    it('refuses when DNS fails, rather than proceeding', async () => {
      const { result } = resolveWith(new Error('ENOTFOUND'));
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(outcome.reason).to.equal('dns_lookup_failed');
    });

    it('checks an IP-literal host directly, with no DNS at all', async () => {
      const { calls, result } = resolveWith([], 'https://169.254.169.254/client');
      const outcome = await result;

      expect(outcome.ok).to.equal(false);
      expect(calls.lookups).to.have.lengthOf(0);
    });

    it('allows a public IP-literal host without DNS', async () => {
      const { calls, result } = resolveWith([], `https://${ALLOWED_V4}/client`);
      const outcome = await result;

      expect(outcome.ok).to.equal(true);
      expect(calls.lookups).to.have.lengthOf(0);
    });

    it('refuses a bracketed IPv6 loopback literal', async () => {
      const { result } = resolveWith([], 'https://[::1]/client');

      expect((await result).ok).to.equal(false);
    });
  });

  describe('the transport — guard neutralised, real server (see header)', () => {
    let server;
    let port;
    let requests;

    /** Guard off so a loopback test server is reachable; see the file header. */
    const OPEN_GUARD = { isBlockedAddress: () => ({ blocked: false, family: 4 }) };

    const start = (handler) =>
      new Promise((resolve) => {
        requests = [];
        server = http.createServer((req, res) => {
          requests.push({ url: req.url, headers: req.headers });
          handler(req, res);
        });
        server.listen(0, '127.0.0.1', () => {
          port = server.address().port;
          resolve();
        });
      });

    afterEach(
      () =>
        new Promise((resolve) => {
          if (!server) return resolve();
          server.closeAllConnections?.();
          return server.close(() => resolve());
        })
    );

    const fetchFrom = (overrides = {}) => {
      const calls = { lookups: 0 };
      return safeMetadataFetch.fetchDocument(`https://cimd.example:${port}/client`, {
        // One call only: a second would be the rebinding window reopening.
        lookup: async () => {
          calls.lookups += 1;
          return [{ address: '127.0.0.1', family: 4 }];
        },
        addressGuard: OPEN_GUARD,
        transport: http,
        calls,
        ...overrides,
      });
    };

    const jsonHandler =
      (body, status = 200, headers = {}) =>
      (req, res) => {
        res.writeHead(status, { 'content-type': 'application/json', ...headers });
        res.end(typeof body === 'string' ? body : JSON.stringify(body));
      };

    it('fetches a JSON document from an allowed address', async () => {
      await start(jsonHandler({ client_name: 'Test Assistant' }));

      const result = await fetchFrom();

      expect(result.ok).to.equal(true);
      expect(JSON.parse(result.body).client_name).to.equal('Test Assistant');
    });

    it('sends the HOSTNAME in the Host header, not the pinned IP (item 3)', async () => {
      await start(jsonHandler({ client_name: 'x' }));

      await fetchFrom();

      expect(requests[0].headers.host).to.contain('cimd.example');
      expect(requests[0].headers.host).to.not.contain('127.0.0.1');
    });

    it('resolves ONCE and connects to the pinned address (item 3)', async () => {
      await start(jsonHandler({ client_name: 'x' }));

      const calls = { lookups: 0 };
      const result = await safeMetadataFetch.fetchDocument(`https://cimd.example:${port}/client`, {
        lookup: async () => {
          calls.lookups += 1;
          return [{ address: '127.0.0.1', family: 4 }];
        },
        addressGuard: OPEN_GUARD,
        transport: http,
      });

      expect(result.ok).to.equal(true);
      expect(calls.lookups).to.equal(1);
      expect(requests).to.have.lengthOf(1);
    });

    describe('redirects are refused, never followed (item 4)', () => {
      [301, 302, 303, 307, 308].forEach((status) => {
        it(`refuses ${status}`, async () => {
          await start((req, res) => {
            res.writeHead(status, { location: 'http://169.254.169.254/latest/meta-data/' });
            res.end();
          });

          const result = await fetchFrom();

          expect(result.ok).to.equal(false);
          expect(result.reason).to.equal(`redirect_refused:${status}`);
        });
      });

      it('makes exactly ONE request — the Location is never fetched', async () => {
        await start((req, res) => {
          res.writeHead(302, { location: `http://127.0.0.1:${port}/second` });
          res.end();
        });

        await fetchFrom();

        expect(requests).to.have.lengthOf(1);
        expect(requests[0].url).to.equal('/client');
      });
    });

    describe('size and time caps (item 5)', () => {
      it('refuses a body larger than the cap when there is NO Content-Length', async () => {
        // Chunked, so there is no header to check — the cap can only be
        await start((req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          const chunk = 'x'.repeat(4096);
          let sent = 0;
          const pump = () => {
            while (sent < 2_000_000) {
              sent += chunk.length;
              if (!res.write(chunk)) return res.once('drain', pump);
            }
            return res.end();
          };
          pump();
        });

        const result = await fetchFrom({ maxBytes: 16 * 1024 });

        expect(result.ok).to.equal(false);
        expect(result.reason).to.equal('response_too_large');
      });

      it('refuses early on a Content-Length that already exceeds the cap', async () => {
        await start((req, res) => {
          const body = 'x'.repeat(200_000);
          res.writeHead(200, {
            'content-type': 'application/json',
            'content-length': String(body.length),
          });
          res.end(body);
        });

        const result = await fetchFrom({ maxBytes: 16 * 1024 });

        expect(result.ok).to.equal(false);
        expect(result.reason).to.contain('too_large');
      });

      it('accepts a body just under the cap', async () => {
        const body = JSON.stringify({ client_name: 'y'.repeat(1000) });
        await start(jsonHandler(body));

        const result = await fetchFrom({ maxBytes: 16 * 1024 });

        expect(result.ok).to.equal(true);
      });

      it('treats maxBytes: 0 as "allow nothing", not as "use the default"', async () => {
        // Pins ?? over ||. A caller passing 0 means allow nothing; `||`
        await start(jsonHandler({ client_name: 'x' }));

        const result = await fetchFrom({ maxBytes: 0 });

        expect(result.ok).to.equal(false);
        expect(result.reason).to.contain('too_large');
      });

      it('treats timeoutMs: 0 as "no time at all", not as "use the default"', async () => {
        // The same pin on the other option, and it opens NO socket: with no
        const opened = [];
        const result = await safeMetadataFetch.fetchDocument(`https://${ALLOWED_V4}/client`, {
          timeoutMs: 0,
          transport: {
            request: () => {
              opened.push('socket');
              throw new Error('no budget remained, so nothing should be opened');
            },
          },
        });

        expect(result.ok).to.equal(false);
        expect(result.reason).to.equal('deadline_exceeded');
        expect(opened).to.deep.equal([]);
      });

      it('refuses a server that never finishes responding', async () => {
        await start((req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.write('{"client_name":');
          // Never ends. The deadline is the only thing that closes this.
        });

        const result = await fetchFrom({ timeoutMs: 300 });

        expect(result.ok).to.equal(false);
        expect(result.reason).to.equal('deadline_exceeded');
      });

      it('applies ONE budget across the whole operation, not one per phase', async () => {
        // Two slow phases that are each under the cap but together exceed it.
        await start((req, res) => {
          setTimeout(() => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.write('{"client_name":"a"');
            setTimeout(() => res.end('}'), 250);
          }, 250);
        });

        const started = Date.now();
        const result = await fetchFrom({ timeoutMs: 300 });
        const elapsed = Date.now() - started;

        expect(result.ok).to.equal(false);
        expect(result.reason).to.equal('deadline_exceeded');
        // Closed near the deadline, not after both phases completed.
        expect(elapsed).to.be.below(600);
      });
    });

    describe('the response has to look like a metadata document', () => {
      it('refuses a non-200 status', async () => {
        await start(jsonHandler({}, 404));

        const result = await fetchFrom();

        expect(result.ok).to.equal(false);
        expect(result.reason).to.equal('unexpected_status:404');
      });

      it('refuses a non-JSON content type', async () => {
        await start((req, res) => {
          res.writeHead(200, { 'content-type': 'text/html' });
          res.end('<html>not a metadata document</html>');
        });

        const result = await fetchFrom();

        expect(result.ok).to.equal(false);
        expect(result.reason).to.contain('content_type');
      });

      it('accepts application/json with parameters', async () => {
        await start((req, res) => {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ client_name: 'x' }));
        });

        expect((await fetchFrom()).ok).to.equal(true);
      });

      it('refuses a missing content type', async () => {
        await start((req, res) => {
          res.writeHead(200, {});
          res.end(JSON.stringify({ client_name: 'x' }));
        });

        expect((await fetchFrom()).ok).to.equal(false);
      });

      it('sends Accept: application/json', async () => {
        await start(jsonHandler({ client_name: 'x' }));

        await fetchFrom();

        expect(requests[0].headers.accept).to.equal('application/json');
      });
    });
  });

  describe('⚠️ TLS is really verified, against the NAME, over a PINNED address', () => {
    // CRITICAL 1. Every way to defeat this is silent, and until these existed
    const https = require('https');
    const { createSelfSignedCertificate } = require('./helpers/selfSignedCertificate');

    const OPEN_GUARD = { isBlockedAddress: () => ({ blocked: false, family: 4 }) };

    let tlsServer;
    let tlsPort;

    /**
 * Minted once, lazily, the first time one of these cases runs — so the
 * ~37ms of RSA keygen is not spent when the suite is filtered elsewhere.
 * ⚠️ Lazy rather than a `before()` hook ON PURPOSE. `before` is mocha-only;
 */
    let minted = null;
    const certificate = () => {
      if (!minted) {
        // SAN DNS:cimd.example is what makes the wrong-hostname case below
        minted = createSelfSignedCertificate('cimd.example');
      }
      return minted;
    };

    beforeEach(
      () =>
        new Promise((resolve) => {
          tlsServer = https.createServer(
            { cert: certificate().certPem, key: certificate().keyPem },
            (req, res) => {
              res.writeHead(200, { 'content-type': 'application/json' });
              res.end(JSON.stringify({ client_name: 'Over Real TLS' }));
            }
          );
          tlsServer.listen(0, '127.0.0.1', () => {
            tlsPort = tlsServer.address().port;
            resolve();
          });
        })
    );

    afterEach(
      () =>
        new Promise((resolve) => {
          if (!tlsServer) return resolve();
          tlsServer.closeAllConnections?.();
          return tlsServer.close(() => resolve());
        })
    );

    /** Always pinned to 127.0.0.1; only the NAME in the URL changes. */
    const fetchOverTls = (hostname, extra = {}) =>
      safeMetadataFetch.fetchDocument(`https://${hostname}:${tlsPort}/client`, {
        lookup: async () => [{ address: '127.0.0.1', family: 4 }],
        addressGuard: OPEN_GUARD,
        timeoutMs: 4000,
        ...extra,
      });

    it('REFUSES a certificate the trust store does not accept', async () => {
      const result = await fetchOverTls('cimd.example');

      expect(result.ok).to.equal(false);
      expect(result.reason).to.contain('request_failed');
    });

    it('ACCEPTS the certificate when its CA is trusted — the pin still verifies', async () => {
      // The positive control. Without it the two refusals above and below
      const result = await fetchOverTls('cimd.example', { ca: certificate().certPem });

      expect(result.ok).to.equal(true);
      expect(JSON.parse(result.body).client_name).to.equal('Over Real TLS');
      // Connected to the pinned address, not to the name.
      expect(result.address).to.equal('127.0.0.1');
    });

    it('REFUSES a trusted certificate presented for the WRONG hostname', async () => {
      // THE property: the certificate is checked against the NAME, not against
      const result = await fetchOverTls('other.example', { ca: certificate().certPem });

      expect(result.ok).to.equal(false);
      expect(result.reason).to.contain('ALTNAME');
    });

    it('carries the hostname as SNI, not the pinned address', async () => {
      // Read off the handshake the server actually saw, rather than off the options object we passed.
      const seen = [];
      tlsServer.on('secureConnection', (socket) => seen.push(socket.servername));

      await fetchOverTls('cimd.example', { ca: certificate().certPem });

      expect(seen).to.deep.equal(['cimd.example']);
    });

    it('states servername explicitly rather than leaning on the host default', async () => {
      const captured = [];
      await safeMetadataFetch.fetchDocument(`https://cimd.example:${tlsPort}/client`, {
        lookup: async () => [{ address: '127.0.0.1', family: 4 }],
        addressGuard: OPEN_GUARD,
        transport: {
          request: (options, cb) => {
            captured.push(options);
            return https.request({ ...options, ca: certificate().certPem }, cb);
          },
        },
      });

      expect(captured[0].servername).to.equal('cimd.example');
      expect(captured[0].rejectUnauthorized).to.equal(true);
      // An identity check that always succeeds is the same as none at all.
      expect(captured[0].checkServerIdentity).to.equal(undefined);
    });
  });

  describe('⚠️ the seam — fetchDocument refuses a blocked address for real', () => {
    // CRITICAL 2. Every link was proved and the CHAIN was not: the guard was
    it('refuses a host resolving to the cloud metadata address, opening NO socket', async () => {
      const opened = [];
      const result = await safeMetadataFetch.fetchDocument('https://cimd.example/client', {
        // Resolves SUCCESSFULLY to a blocked address — the discriminating
        lookup: async () => [{ address: '169.254.169.254', family: 4 }],
        // REAL guard. No OPEN_GUARD here; that is the whole point.
        transport: {
          request: () => {
            opened.push('socket');
            throw new Error('a socket must never be opened for a blocked address');
          },
        },
      });

      expect(result.ok).to.equal(false);
      expect(result.reason).to.contain('link_local');
      expect(opened).to.deep.equal([]);
    });

    it('refuses a private IPv6 answer through the same seam', async () => {
      const opened = [];
      const result = await safeMetadataFetch.fetchDocument('https://cimd.example/client', {
        lookup: async () => [{ address: 'fd00:ec2::254', family: 6 }],
        transport: {
          request: () => {
            opened.push('socket');
            throw new Error('a socket must never be opened for a blocked address');
          },
        },
      });

      expect(result.ok).to.equal(false);
      expect(result.reason).to.contain('unique_local');
      expect(opened).to.deep.equal([]);
    });
  });

  describe('DNS spends from the same budget as the request (S1)', () => {
    it('gives up on a stalled resolver instead of waiting for the platform', async () => {
      // dns.promises.lookup has no timeout; unraced, the real bound is libc's
      const started = Date.now();
      const result = await safeMetadataFetch.fetchDocument('https://cimd.example/client', {
        lookup: () => new Promise(() => {}),
        timeoutMs: 300,
        transport: {
          request: () => {
            throw new Error('must not reach the socket');
          },
        },
      });
      const elapsed = Date.now() - started;

      expect(result.ok).to.equal(false);
      expect(result.reason).to.equal('dns_lookup_timeout');
      expect(elapsed).to.be.below(2000);
    });
  });

  describe('the default transport is node core, not a redirect-following client', () => {
    it('does not use axios', () => {
      // axios is a dependency of this repo and follows redirects BY DEFAULT.
      const source = require('fs').readFileSync(
        require.resolve('../services/oauth/safeMetadataFetch'),
        'utf8'
      );

      // Check the REQUIRE, not the word: the module names axios in a comment
      expect(source).to.not.contain("require('axios')");
      expect(source).to.not.contain('require("axios")');
      expect(source).to.contain("require('https')");
    });
  });
});
