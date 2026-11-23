require('./support/dummyEnv');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const auditRouter = require('../routes/mcpAudit');
const { validBatch } = require('../services/mcpAuditEvents');

const serviceId = 'https://mcp.example.test/client';
const started = {
  event_id: randomUUID(), phase: 'started', timestamp: new Date().toISOString(), schema_version: 1,
  correlation_id: randomUUID(), grant_id: randomUUID(), user_id: '42',
  client_id: 'https://assistant.example.test/client', argument_hash: 'a'.repeat(64),
  tool: 'nutrition_lookup', scope: 'nutrition:read', confirmation: 'not_required', introspection: 'active',
};
const completed = { ...started, phase: 'completion', outcome: 'success', latency_ms: 42,
  exchange: 'not_required', upstream_status_class: '2xx' };
const body = JSON.stringify({ events: [started, completed] });
const path = '/api/security-events/mcp';
const digest = value => createHash('sha256').update(value).digest('hex');

function fixture({ signed = body, identity = serviceId, result = { data: 2, error: null } } = {}) {
  const calls = [];
  const verify = async (_, options) => {
    assert.equal(options.requireBodyDigest, true);
    assert.equal(options.assertionAudience.resolve({ auditIngestAudience: () => path }), path);
    return { ok: true, clientId: identity, bodyDigest: digest(signed) };
  };
  const db = { rpc: async (name, params) => { calls.push([name, params]); return result; } };
  const app = express().use(path, auditRouter({ db, verify, serviceId }));
  const post = (value = body) => request(app).post(path).set('Authorization', 'Bearer fixture').type('json').send(value);
  return { app, calls, post };
}
describe('MCP audit intake', () => {
  it('acknowledges both phases only after persistence confirms the batch', async () => {
    const { calls, post } = fixture();
    const res = await post().expect(200);
    assert.deepEqual(calls, [['ingest_mcp_audit_events', { envelopes: [started, completed] }]]);
    assert.deepEqual(res.body.data.acknowledged, [started, completed].map(({ event_id, phase }) => ({ event_id, phase })));
  });
  it('does not acknowledge a failed or incomplete transaction', async () => {
    for (const result of [{ error: { code: '08006' } }, { data: 1 }]) {
      const res = await fixture({ result }).post().expect(503);
      assert.equal(res.body.acknowledged, undefined);
    }
    await fixture({ result: { error: { code: '23505' } } }).post().expect(409);
  });
  it('checks the authenticated identity and signed bytes before persistence', async () => {
    for (const [options, status] of [[{ identity: 'other' },403], [{ signed: body + ' ' },401]]) {
      const { post, calls } = fixture(options);
      await post().expect(status);
      assert.equal(calls.length, 0);
    }
    await request(fixture().app).post(path).send({}).expect(401);
  });
  it('bounds the body and rejects excess or sensitive fields without echoing them', async () => {
    const value = JSON.stringify({ events: [{ ...started, arguments: { text: 'synthetic-private-input' } }] });
    const { post, calls } = fixture({ signed: value });
    const res = await post(value).expect(400);
    assert(!res.text.includes('synthetic-private-input'));
    await post(' '.repeat(17000)).expect(413);
    assert.equal(calls.length, 0);
    assert.equal(validBatch({ events: [{ ...started, phase: 'completion' }] }), false);
    assert.equal(validBatch({ events: [{ ...completed, outcome: 'failure', upstream_status_class: '5xx' }] }), true);
  });
});
