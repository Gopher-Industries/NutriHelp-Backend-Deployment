// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const { expect } = require('chai');

const addressGuard = require('../services/oauth/addressGuard');

/**
 * Ticket 41, checklist items 1 and 2: which literal addresses may we connect to.
 * This is the allow/deny decision on its own, separate from DNS and from the
 * socket. Everything here is a pure function of an address string, so every
 */

const blocked = (address) => addressGuard.isBlockedAddress(address).blocked;

describe('oauth client metadata — address guard', () => {
  describe('IPv4 ranges that must never be connected to', () => {
    const CASES = [
      ['0.0.0.0', 'this-network'],
      ['0.1.2.3', 'this-network'],
      ['10.0.0.1', 'private'],
      ['10.255.255.254', 'private'],
      ['100.64.0.1', 'carrier-grade NAT'],
      ['127.0.0.1', 'loopback'],
      ['127.1.2.3', 'loopback — the whole /8, not just .0.0.1'],
      ['169.254.0.1', 'link-local'],
      ['169.254.169.254', 'THE cloud metadata address'],
      ['172.16.0.1', 'private'],
      ['172.31.255.254', 'private — top of the /12'],
      ['192.0.0.1', 'IETF protocol assignments'],
      ['192.168.0.1', 'private'],
      ['198.18.0.1', 'benchmarking'],
      ['192.0.2.1', 'TEST-NET-1'],
      ['198.51.100.1', 'TEST-NET-2'],
      ['203.0.113.1', 'TEST-NET-3'],
      ['192.88.99.1', '6to4 relay anycast'],
      ['224.0.0.1', 'multicast'],
      ['239.255.255.255', 'multicast — top of the /4'],
      ['240.0.0.1', 'reserved'],
      ['255.255.255.255', 'broadcast'],
    ];

    CASES.forEach(([address, why]) => {
      it(`refuses ${address} (${why})`, () => {
        expect(blocked(address)).to.equal(true);
      });
    });

    it('does not refuse a public address', () => {
      // The guard has to let something through, or every test above passes
      expect(blocked('8.8.8.8')).to.equal(false);
    });

    it('does not refuse an address merely adjacent to a blocked range', () => {
      expect(blocked('172.32.0.1')).to.equal(false);
      expect(blocked('11.0.0.1')).to.equal(false);
      expect(blocked('126.255.255.255')).to.equal(false);
      expect(blocked('100.128.0.1')).to.equal(false);
    });
  });

  describe('IPv6 ranges that must never be connected to', () => {
    const CASES = [
      ['::', 'unspecified'],
      ['::1', 'loopback'],
      ['fc00::1', 'unique local'],
      ['fd00::1', 'unique local'],
      ['fd00:ec2::254', 'THE IPv6 cloud metadata address'],
      ['fe80::1', 'link-local'],
      ['ff02::1', 'multicast'],
      ['2001:db8::1', 'documentation'],
      ['100::1', 'discard-only'],
    ];

    CASES.forEach(([address, why]) => {
      it(`refuses ${address} (${why})`, () => {
        expect(blocked(address)).to.equal(true);
      });
    });

    it('does not refuse a public IPv6 address', () => {
      expect(blocked('2606:4700:4700::1111')).to.equal(false);
      expect(blocked('2001:4860:4860::8888')).to.equal(false);
    });
  });

  describe('the IPv6 forms that wrap an IPv4 address', () => {

    it('refuses the IPv4-MAPPED form of a private address', () => {
      expect(blocked('::ffff:10.0.0.1')).to.equal(true);
    });

    it('refuses the IPv4-MAPPED form of the cloud metadata address', () => {
      expect(blocked('::ffff:169.254.169.254')).to.equal(true);
    });

    it('refuses the IPv4-mapped form written in hex', () => {
      // ::ffff:a9fe:a9fe is 169.254.169.254. Same address, and a guard doing
      expect(blocked('::ffff:a9fe:a9fe')).to.equal(true);
      expect(blocked('::ffff:a00:1')).to.equal(true);
    });

    it('refuses the IPv4-COMPATIBLE form of a private address', () => {
      // Measured: net.BlockList does NOT catch this one against an IPv4 rule.
      expect(blocked('::10.0.0.1')).to.equal(true);
    });

    it('refuses the IPv4-compatible form of the cloud metadata address', () => {
      expect(blocked('::169.254.169.254')).to.equal(true);
    });

    it('refuses a NAT64-embedded private address', () => {
      expect(blocked('64:ff9b::10.0.0.1')).to.equal(true);
    });

    it('refuses a 6to4 address embedding a private IPv4 host', () => {
      expect(blocked('2002:0a00:0001::1')).to.equal(true);
    });

    it('refuses a Teredo address', () => {
      expect(blocked('2001:0:1:2:3:4:5:6')).to.equal(true);
    });

    it('still allows a public 2001::/16 address that is NOT Teredo', () => {
      // 2001::/32 is Teredo; 2001:4860::/32 is Google. Blocking the wrong
      expect(blocked('2001:4860:4860::8888')).to.equal(false);
      expect(blocked('2001:500:200::b')).to.equal(false);
    });
  });

  describe('the two range lists are pinned', () => {
    it('has the expected number of IPv4 ranges', () => {
      expect(addressGuard.BLOCKED_IPV4).to.have.lengthOf(15);
    });

    it('has the expected number of IPv6 ranges', () => {
      expect(addressGuard.BLOCKED_IPV6).to.have.lengthOf(9);
    });

    it('states every range as [subnet, prefix, reason]', () => {
      [...addressGuard.BLOCKED_IPV4, ...addressGuard.BLOCKED_IPV6].forEach((entry) => {
        expect(entry).to.have.lengthOf(3);
        expect(entry[1]).to.be.a('number');
        expect(entry[2]).to.be.a('string').and.not.empty;
      });
    });
  });

  describe('anything it cannot positively classify', () => {
    const JUNK = ['', '   ', 'example.com', 'not-an-ip', '10.0.0', '10.0.0.1.5', '999.1.1.1'];

    JUNK.forEach((value) => {
      it(`refuses ${JSON.stringify(value)}`, () => {
        expect(blocked(value)).to.equal(true);
      });
    });

    it('refuses a non-string', () => {
      expect(blocked(null)).to.equal(true);
      expect(blocked(undefined)).to.equal(true);
      expect(blocked(1234)).to.equal(true);
      expect(blocked({})).to.equal(true);
    });

    it('names a reason on every refusal', () => {
      // The reason is what reaches the operational log; a refusal nobody can diagnose gets switched off.
      const result = addressGuard.isBlockedAddress('169.254.169.254');

      expect(result.blocked).to.equal(true);
      expect(result.reason).to.be.a('string').and.not.empty;
    });
  });
});
