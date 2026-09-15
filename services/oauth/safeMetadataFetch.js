const dns = require('dns');
const https = require('https');
const net = require('net');

const addressGuardModule = require('./addressGuard');

/**
 * Outbound CIMD metadata fetch (ticket 41). Stranger-chosen URL from inside
 * our network.
 *
 * Uses Node core `https`, not axios (axios follows redirects by default).
 * resolvePinnedAddress() chooses the address; fetchDocument() connects only
 * to that pin. Deps injection for tests (proxyquire is inert under jest).
 */

const DEFAULT_MAX_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

const fail = (reason) => ({ ok: false, reason });

/**
 * https URL, no userinfo/query/fragment (matches mig 002 client_id CHECK).
 * Userinfo refused: https://good.example@internal.example/ resolves to internal.
 */
const parseClientIdUrl = (rawUrl) => {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') return null;

  let url;
  try {
    url = new URL(rawUrl);
  } catch (err) {
    return null;
  }

  if (url.protocol !== 'https:') return { rejected: 'url_not_https' };
  if (url.username !== '' || url.password !== '') return { rejected: 'url_has_userinfo' };
  if (url.search !== '') return { rejected: 'url_has_query' };
  if (url.hash !== '') return { rejected: 'url_has_fragment' };
  if (url.hostname === '') return { rejected: 'url_has_no_host' };

  return { url };
};

/** Strip brackets URL keeps around an IPv6 host. */
const bareHostname = (hostname) =>
  hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

/**
 * Resolve both families; refuse the host if ANY address is blocked (do not
 * prefer a public A over a private AAAA).
 *
 * @returns {Promise<{ok: true, address, family, url} | {ok: false, reason}>}
 */
const resolvePinnedAddress = async (rawUrl, deps = {}) => {
  const guard = deps.addressGuard || addressGuardModule;
  const lookup = deps.lookup || dns.promises.lookup;

  const parsed = parseClientIdUrl(rawUrl);
  if (!parsed) return fail('url_unparseable');
  if (parsed.rejected) return fail(parsed.rejected);

  const { url } = parsed;
  const hostname = bareHostname(url.hostname);

  // net.isIP answers "is literal"; the guard answers "is allowed" — don't mix.
  if (net.isIP(hostname)) {
    const literal = guard.isBlockedAddress(hostname);
    if (literal.blocked) return fail(`address_blocked:${literal.reason}`);
    return { ok: true, address: hostname, family: net.isIPv6(hostname) ? 6 : 4, url };
  }

  // DNS shares the request budget (?? not || so timeoutMs:0 stays 0).
  const budgetMs = deps.budgetMs ?? deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let addresses;
  let dnsTimer = null;
  try {
    addresses = await Promise.race([
      lookup(hostname, { all: true, family: 0, verbatim: true }),
      new Promise((resolve, reject) => {
        dnsTimer = setTimeout(() => reject(new Error('dns_lookup_timeout')), budgetMs);
        if (typeof dnsTimer.unref === 'function') dnsTimer.unref();
      }),
    ]);
  } catch (err) {
    return fail(
      err && err.message === 'dns_lookup_timeout' ? 'dns_lookup_timeout' : 'dns_lookup_failed'
    );
  } finally {
    if (dnsTimer) clearTimeout(dnsTimer);
  }

  if (!Array.isArray(addresses) || addresses.length === 0) {
    return fail('dns_no_addresses');
  }

  for (const entry of addresses) {
    const verdict = guard.isBlockedAddress(entry && entry.address);
    if (verdict.blocked) {
      return fail(`address_blocked:${verdict.reason}`);
    }
  }

  const chosen = addresses[0];
  return {
    ok: true,
    address: chosen.address,
    family: net.isIPv6(chosen.address) ? 6 : 4,
    url,
  };
};

const isJsonContentType = (value) =>
  typeof value === 'string' && /^application\/(?:[\w.+-]+\+)?json\s*(?:;|$)/i.test(value.trim());

/** Internal refusal detail — bounded code for operators, never for clients. */
const requestFailure = (err) => {
  const code = err && (err.code || err.name);
  if (typeof code !== 'string' || code === '') return 'request_failed';
  return `request_failed:${code.replace(/[^A-Za-z0-9_]/g, '').slice(0, 48)}`;
};

/**
 * Connect only to the pinned address; TLS still verifies the hostname.
 * Custom lookup closes the DNS-rebinding window. rejectUnauthorized stays ON
 * with no deps passthrough to disable it.
 */
const fetchDocument = async (rawUrl, deps = {}) => {
  const transport = deps.transport || https;
  // ?? not || so maxBytes/timeoutMs of 0 mean "allow nothing" / "no time".
  const maxBytes = deps.maxBytes ?? DEFAULT_MAX_BYTES;
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const startedAt = Date.now();
  const pinned = await resolvePinnedAddress(rawUrl, { ...deps, budgetMs: timeoutMs });
  if (!pinned.ok) return pinned;

  const remainingMs = timeoutMs - (Date.now() - startedAt);
  if (remainingMs <= 0) return fail('deadline_exceeded');

  const { url, address, family } = pinned;
  const hostname = bareHostname(url.hostname);

  return new Promise((resolve) => {
    let settled = false;
    let request = null;
    let received = 0;
    const chunks = [];

    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (request) request.destroy();
      resolve(outcome);
    };

    const deadline = setTimeout(() => finish(fail('deadline_exceeded')), remainingMs);

    const options = {
      lookup: (lookupHost, lookupOptions, callback) => {
        const entry = { address, family };
        if (lookupOptions && lookupOptions.all) return callback(null, [entry]);
        return callback(null, address, family);
      },
      host: hostname,
      hostname,
      // Explicit SNI — do not set host to the pinned IP or this breaks.
      servername: hostname,
      rejectUnauthorized: true,
      // TEST SEAM ONLY: `ca` replaces the trust store; never set in production.
      // clientMetadataService does not forward this.
      ...(deps.ca ? { ca: deps.ca } : {}),
      port: url.port || 443,
      path: url.pathname,
      method: 'GET',
      headers: {
        accept: 'application/json',
        host: url.port ? `${url.hostname}:${url.port}` : url.hostname,
        'user-agent': 'NutriHelp-AS/1.0 (+client-id-metadata-document)',
      },
    };

    try {
      request = transport.request(options, (response) => {
        const status = response.statusCode;

        // Redirects refused, never followed.
        if (status >= 300 && status < 400) {
          response.destroy();
          return finish(fail(`redirect_refused:${status}`));
        }

        if (status !== 200) {
          response.destroy();
          return finish(fail(`unexpected_status:${status}`));
        }

        if (!isJsonContentType(response.headers['content-type'])) {
          response.destroy();
          return finish(fail('unexpected_content_type'));
        }

        // Content-Length is an optimisation only; stream enforces the cap.
        const declared = Number(response.headers['content-length']);
        if (Number.isFinite(declared) && declared > maxBytes) {
          response.destroy();
          return finish(fail('declared_length_too_large'));
        }

        response.on('data', (chunk) => {
          received += chunk.length;
          if (received > maxBytes) {
            response.destroy();
            return finish(fail('response_too_large'));
          }
          return chunks.push(chunk);
        });

        response.on('error', () => finish(fail('response_stream_error')));
        return response.on('end', () =>
          finish({
            ok: true,
            status,
            body: Buffer.concat(chunks).toString('utf8'),
            address,
          })
        );
      });
    } catch (err) {
      return finish(fail(requestFailure(err)));
    }

    request.on('error', (err) => finish(fail(requestFailure(err))));
    // remainingMs, not timeoutMs — DNS already spent from the budget.
    request.setTimeout(remainingMs, () => finish(fail('deadline_exceeded')));
    return request.end();
  });
};

module.exports = {
  resolvePinnedAddress,
  fetchDocument,
  parseClientIdUrl, // shared with clientMetadataService pre-check
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
};
