#!/usr/bin/env node
/**
 * Ticket 41 item 6: probe cloud metadata endpoints from THIS host (Render),
 * not a laptop. Exit 0 = unreachable; 1 = reachable or inconclusive.
 * Defence in depth — addressGuard is the real control.
 */

const net = require('net');

const TIMEOUT_MS = 3000;

/** IPv4 reachability control — without it, no-egress hosts falsely PASS. */
const IPV4_CONTROL = ['1.1.1.1', 443, 'Cloudflare DNS over TLS - IPv4 reachability control'];

/** IPv6 control — failure is INCONCLUSIVE for v6 targets, not VOID. */
const IPV6_CONTROL = [
  '2606:4700:4700::1111',
  443,
  'Cloudflare DNS over TLS - IPv6 reachability control',
];

const TARGETS = [
  ['169.254.169.254', 80, 'AWS IMDSv1/v2, GCP, Azure, DigitalOcean, Oracle', 4],
  ['fd00:ec2::254', 80, 'AWS IMDS over IPv6', 6],
  ['100.100.100.200', 80, 'Alibaba Cloud', 4],
  ['192.0.0.192', 80, 'Oracle Cloud (legacy)', 4],
  ['169.254.170.2', 80, 'AWS ECS task metadata', 4],
];

const probe = ([host, port, label]) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const done = (reachable, detail) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ host, port, label, reachable, detail });
    };

    const timer = setTimeout(() => done(false, 'timeout'), TIMEOUT_MS);

    socket.once('connect', () => {
      clearTimeout(timer);
      done(true, 'connected');
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      done(false, err.code || 'error');
    });

    try {
      socket.connect(port, host);
    } catch (err) {
      clearTimeout(timer);
      done(false, err.code || 'threw');
    }
  });

const main = async () => {
  process.stdout.write(
    `Probing cloud metadata endpoints from this host (${TIMEOUT_MS}ms each)\n\n`
  );

  // Controls first, one per family. Each says whether results in that family mean anything at all.
  const [v4Control, v6Control] = await Promise.all([probe(IPV4_CONTROL), probe(IPV6_CONTROL)]);

  [v4Control, v6Control].forEach((control) => {
    process.stdout.write(
      `  control  ${`${control.host}:${control.port}`.padEnd(26)} -> ` +
        `${control.reachable ? 'reachable' : 'UNREACHABLE'} (${control.detail})\n`
    );
  });
  process.stdout.write('\n');

  // No IPv4 egress at all means the prober has shown nothing, in any family.
  if (!v4Control.reachable) {
    process.stdout.write(
      'VOID: the prober could not reach its IPv4 control address, so it has not shown\n' +
        'it can reach anything. A host with no egress produces exactly the same silence\n' +
        'as a host that is correctly blocked, and without this control that silence\n' +
        'reads as PASS. Re-run where outbound traffic is permitted.\n' +
        'Do NOT record this run as evidence for checklist item 6.\n'
    );
    process.exit(1);
  }

  const results = await Promise.all(TARGETS.map(probe));
  let reachableCount = 0;
  let inconclusiveCount = 0;

  results.forEach((result, index) => {
    const family = TARGETS[index][3];
    // An IPv6 target on a host with no IPv6 stack refuses in microseconds and
    const inconclusive = family === 6 && !v6Control.reachable && !result.reachable;

    let verdict;
    if (result.reachable) {
      verdict = 'REACHABLE  <-- investigate';
      reachableCount += 1;
    } else if (inconclusive) {
      verdict = 'INCONCLUSIVE (no IPv6)';
      inconclusiveCount += 1;
    } else {
      verdict = 'unreachable';
    }

    process.stdout.write(
      `  ${verdict.padEnd(26)} ${`${result.host}:${result.port}`.padEnd(26)} ` +
        `(${result.detail})  ${result.label}\n`
    );
  });

  process.stdout.write('\n');

  if (reachableCount > 0) {
    process.stdout.write(
      `FAIL: ${reachableCount} metadata endpoint(s) answered. The egress assertion for\n` +
        'ticket 41 checklist item 6 cannot be made until this is explained or blocked.\n'
    );
    process.exit(1);
  }

  if (inconclusiveCount > 0) {
    process.stdout.write(
      `INCONCLUSIVE: no metadata endpoint answered, but ${inconclusiveCount} IPv6 target(s)\n` +
        'were not really tested â€” this host has no IPv6 egress, so their silence says\n' +
        'nothing about whether a v6-capable host could reach them. The IPv4 result is\n' +
        'sound and may be recorded as such. Re-run on a v6-capable instance before\n' +
        'claiming item 6 in full.\n'
    );
    process.exit(1);
  }

  process.stdout.write(
    'PASS: both controls were reachable and no probed metadata endpoint answered.\n'
  );
  process.exit(0);
};

main().catch((err) => {
  process.stderr.write(`probe failed to run: ${err && err.message}\n`);
  process.exit(1);
});
