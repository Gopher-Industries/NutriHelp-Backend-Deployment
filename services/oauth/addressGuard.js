const net = require('net');

/**
 * Outbound CIMD address denylist (ticket 41). Applied to resolved IP literals
 * only — never hostnames or URL strings. Fail closed on anything unclassified.
 *
 * Measured on Node v25: BlockList catches ::ffff:10.0.0.1 against an IPv4 rule,
 * but NOT ::10.0.0.1 — so ::/96 is stated explicitly for IPv4-compatible form.
 */

/** IPv4 ranges that are never a legitimate CIMD host. */
const BLOCKED_IPV4 = Object.freeze([
  ['0.0.0.0', 8, 'this_network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'carrier_grade_nat'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link_local'], // includes 169.254.169.254
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'ietf_protocol_assignments'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'],
  ['192.88.99.0', 24, 'six_to_four_relay'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'], // includes 255.255.255.255
]);

const BLOCKED_IPV6 = Object.freeze([
  // ::/96: unspecified, ::1, and IPv4-compatible — BlockList does not imply this.
  ['::', 96, 'unspecified_loopback_or_ipv4_compatible'],
  // Transition encodings that can embed a private IPv4.
  ['64:ff9b::', 96, 'nat64'],
  ['2002::', 16, 'six_to_four'],
  ['2001::', 32, 'teredo'],
  ['100::', 64, 'discard_only'],
  ['2001:db8::', 32, 'documentation'],
  ['fc00::', 7, 'unique_local'], // covers fd00:ec2::254
  ['fe80::', 10, 'link_local'],
  ['ff00::', 8, 'multicast'],
]);

const buildBlockList = () => {
  const list = new net.BlockList();
  BLOCKED_IPV4.forEach(([address, prefix]) => list.addSubnet(address, prefix, 'ipv4'));
  BLOCKED_IPV6.forEach(([address, prefix]) => list.addSubnet(address, prefix, 'ipv6'));
  return list;
};

const BLOCK_LIST = buildBlockList();

const describeIpv4 = (address) => {
  const match = BLOCKED_IPV4.find(([subnet, prefix]) => {
    const probe = new net.BlockList();
    probe.addSubnet(subnet, prefix, 'ipv4');
    return probe.check(address, 'ipv4');
  });
  return match ? match[2] : 'blocked_ipv4';
};

const describeIpv6 = (address) => {
  const v6Match = BLOCKED_IPV6.find(([subnet, prefix]) => {
    const probe = new net.BlockList();
    probe.addSubnet(subnet, prefix, 'ipv6');
    return probe.check(address, 'ipv6');
  });
  if (v6Match) return v6Match[2];

  // IPv4-mapped: matched an IPv4 rule, not an IPv6 one.
  const v4Match = BLOCKED_IPV4.find(([subnet, prefix]) => {
    const probe = new net.BlockList();
    probe.addSubnet(subnet, prefix, 'ipv4');
    return probe.check(address, 'ipv6');
  });
  return v4Match ? `ipv4_mapped_${v4Match[2]}` : 'blocked_ipv6';
};

/**
 * @param {string} address a literal IP address, already resolved
 * @returns {{blocked: true, reason: string} | {blocked: false, family: 4 | 6}}
 */
const isBlockedAddress = (address) => {
  if (typeof address !== 'string' || address.trim() === '') {
    return { blocked: true, reason: 'address_not_a_string' };
  }

  const candidate = address.trim();

  if (net.isIPv4(candidate)) {
    return BLOCK_LIST.check(candidate, 'ipv4')
      ? { blocked: true, reason: describeIpv4(candidate) }
      : { blocked: false, family: 4 };
  }

  if (net.isIPv6(candidate)) {
    return BLOCK_LIST.check(candidate, 'ipv6')
      ? { blocked: true, reason: describeIpv6(candidate) }
      : { blocked: false, family: 6 };
  }

  // Hostname must never reach here — caller skipped resolution.
  return { blocked: true, reason: 'address_not_an_ip_literal' };
};

module.exports = {
  isBlockedAddress,
  BLOCKED_IPV4,
  BLOCKED_IPV6,
};
