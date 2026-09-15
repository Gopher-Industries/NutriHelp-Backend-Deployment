// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const { expect } = require('chai');

const redirectUriMatcher = require('../services/oauth/redirectUriMatcher');

/**
 * Ticket 41, checklist item 7: redirect-URI comparison ignores the PORT for
 * loopback addresses ONLY.
 * This is an exact-match EXCEPTION inside a security check, which is the kind
 */

const matches = (registered, presented) =>
  redirectUriMatcher.redirectUriMatches(registered, presented);

describe('oauth client metadata — redirect URI matching', () => {
  describe('the default is exact', () => {
    it('matches an identical URI', () => {
      expect(matches('https://app.example/cb', 'https://app.example/cb')).to.equal(true);
    });

    it('refuses a different path', () => {
      expect(matches('https://app.example/cb', 'https://app.example/other')).to.equal(false);
    });

    it('refuses a different host', () => {
      expect(matches('https://app.example/cb', 'https://evil.example/cb')).to.equal(false);
    });

    it('refuses a different scheme', () => {
      expect(matches('https://app.example/cb', 'http://app.example/cb')).to.equal(false);
    });

    it('refuses a different query string', () => {
      expect(matches('https://app.example/cb?a=1', 'https://app.example/cb?a=2')).to.equal(false);
    });

    it('refuses a trailing-slash difference', () => {
      expect(matches('https://app.example/cb', 'https://app.example/cb/')).to.equal(false);
    });

    it('treats the host case-insensitively but the path case-sensitively', () => {
      // Hosts are case-insensitive by RFC 3986; paths are not, and folding
      expect(matches('https://App.Example/cb', 'https://app.example/cb')).to.equal(true);
      expect(matches('https://app.example/cb', 'https://app.example/CB')).to.equal(false);
    });
  });

  describe('⚠️ the port exception applies to loopback ONLY', () => {
    it('refuses a different port on a PUBLIC host', () => {
      // THE case that matters. If the loopback exception ever leaks out of its
      expect(matches('https://app.example/cb', 'https://app.example:8443/cb')).to.equal(false);
    });

    it('refuses a different port on a public host even when one side is explicit', () => {
      expect(matches('https://app.example:443/cb', 'https://app.example:8443/cb')).to.equal(false);
    });

    it('refuses a host that merely CONTAINS the word localhost', () => {
      // localhost.evil.example is a perfectly ordinary public hostname owned
      expect(
        matches('https://localhost.evil.example/cb', 'https://localhost.evil.example:9999/cb')
      ).to.equal(false);
    });

    it('refuses a host that merely starts with a loopback-looking label', () => {
      expect(
        matches('https://127.0.0.1.evil.example/cb', 'https://127.0.0.1.evil.example:9/cb')
      ).to.equal(false);
    });
  });

  describe('loopback gets the port exception', () => {
    it('ignores the port for 127.0.0.1', () => {
      // Claude Code binds a different ephemeral port every run, so exact matching breaks the client outright.
      expect(matches('http://127.0.0.1:1234/cb', 'http://127.0.0.1:55555/cb')).to.equal(true);
    });

    it('ignores the port anywhere in 127.0.0.0/8', () => {
      expect(matches('http://127.0.0.2:1/cb', 'http://127.0.0.2:2/cb')).to.equal(true);
    });

    it('ignores the port for the IPv6 loopback', () => {
      expect(matches('http://[::1]:1234/cb', 'http://[::1]:55555/cb')).to.equal(true);
    });

    it('ignores the port for localhost', () => {
      expect(matches('http://localhost:1234/cb', 'http://localhost:55555/cb')).to.equal(true);
    });

    it('still compares the PATH exactly on loopback', () => {
      expect(matches('http://127.0.0.1:1234/cb', 'http://127.0.0.1:5555/other')).to.equal(false);
    });

    it('still compares the SCHEME exactly on loopback', () => {
      expect(matches('http://127.0.0.1:1234/cb', 'https://127.0.0.1:5555/cb')).to.equal(false);
    });

    it('still compares the QUERY exactly on loopback', () => {
      expect(matches('http://127.0.0.1:1/cb?a=1', 'http://127.0.0.1:2/cb?a=2')).to.equal(false);
    });

    it('does not treat localhost and 127.0.0.1 as the same host', () => {
      // Both are loopback, but the host itself is still compared exactly —
      expect(matches('http://localhost:1/cb', 'http://127.0.0.1:1/cb')).to.equal(false);
    });

    it('does not let a loopback REGISTERED uri match a public PRESENTED one', () => {
      expect(matches('http://127.0.0.1:1/cb', 'http://app.example:1/cb')).to.equal(false);
    });
  });

  describe('fails closed on anything it cannot parse', () => {
    const JUNK = ['', '   ', 'not a uri', '://missing-scheme', null, undefined, 42, {}];

    JUNK.forEach((value) => {
      it(`refuses ${JSON.stringify(value)} as the presented uri`, () => {
        expect(matches('https://app.example/cb', value)).to.equal(false);
      });

      it(`refuses ${JSON.stringify(value)} as the registered uri`, () => {
        expect(matches(value, 'https://app.example/cb')).to.equal(false);
      });
    });

    it('refuses when both sides are junk, rather than calling them equal', () => {
      // Two unparseable strings are not a match. String equality here would
      expect(matches('', '')).to.equal(false);
      expect(matches('not a uri', 'not a uri')).to.equal(false);
    });
  });

  describe('matchesAny over a registered list', () => {
    const REGISTERED = ['https://app.example/cb', 'http://127.0.0.1:1234/cb'];

    it('accepts a uri present in the list', () => {
      expect(redirectUriMatcher.matchesAny(REGISTERED, 'https://app.example/cb')).to.equal(true);
    });

    it('applies the loopback port exception through the list', () => {
      expect(redirectUriMatcher.matchesAny(REGISTERED, 'http://127.0.0.1:60123/cb')).to.equal(true);
    });

    it('refuses a uri absent from the list', () => {
      expect(redirectUriMatcher.matchesAny(REGISTERED, 'https://evil.example/cb')).to.equal(false);
    });

    it('refuses everything against an empty or absent list', () => {
      expect(redirectUriMatcher.matchesAny([], 'https://app.example/cb')).to.equal(false);
      expect(redirectUriMatcher.matchesAny(null, 'https://app.example/cb')).to.equal(false);
      expect(redirectUriMatcher.matchesAny(undefined, 'https://app.example/cb')).to.equal(false);
    });
  });
});
