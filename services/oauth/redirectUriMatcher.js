const net = require('net');

/**
 * Redirect-URI comparison (ticket 41). Exact match, with one exception: loopback
 * ignores PORT (RFC 8252 §7.3). Loopback is decided by parsing, never substring.
 * Unparseable is never a match — including two identical junk strings.
 *
 * Deliberate asymmetry with addressGuard:
 *   addressGuard('::ffff:127.0.0.1')     -> blocked (socket address encodings)
 *   isLoopbackHost('::ffff:127.0.0.1')   -> false  (registration string match)
 * Widening this to treat mapped forms as loopback would widen the port exception.
 */

/** Loopback names/ranges — by parsing, never by text. */
const isLoopbackHost = (hostname) => {
  if (typeof hostname !== 'string' || hostname === '') return false;

  const bare =
    hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

  if (bare.toLowerCase() === 'localhost') return true; // RFC 6761
  if (net.isIPv4(bare)) return bare.split('.')[0] === '127'; // whole 127/8

  if (net.isIPv6(bare)) {
    const probe = new net.BlockList();
    probe.addAddress('::1', 'ipv6');
    return probe.check(bare, 'ipv6');
  }

  return false;
};

const parse = (value) => {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
};

/**
 * @param {string} registered the URI on file
 * @param {string} presented  the URI the client sent
 * @returns {boolean}
 */
const redirectUriMatches = (registered, presented) => {
  const a = parse(registered);
  const b = parse(presented);

  if (!a || !b) return false;

  if (a.protocol !== b.protocol) return false;
  if (a.hostname !== b.hostname) return false;
  if (a.pathname !== b.pathname) return false;
  if (a.search !== b.search) return false;
  if (a.hash !== b.hash) return false;
  if (a.username !== b.username || a.password !== b.password) return false;

  // Only exception: both loopback → ignore port.
  // Second isLoopbackHost is redundant today (hostname already equal) but kept
  // if that equality is ever relaxed (e.g. localhost ≡ 127.0.0.1).
  if (isLoopbackHost(a.hostname) && isLoopbackHost(b.hostname)) return true;

  return a.port === b.port;
};

/**
 * @param {string[]} registeredList
 * @param {string} presented
 * @returns {boolean} false if list empty/absent — never "allow anything"
 */
const matchesAny = (registeredList, presented) => {
  if (!Array.isArray(registeredList) || registeredList.length === 0) return false;
  return registeredList.some((registered) => redirectUriMatches(registered, presented));
};

module.exports = { redirectUriMatches, matchesAny, isLoopbackHost };
