const express = require('express');
const { createHash } = require('node:crypto');
const { verifyClientAssertion, ASSERTION_TYPE } = require('../services/oauth/clientAssertionVerifier');
const { validBatch } = require('../services/mcpAuditEvents');

const audience = {
  resolve: config => config.auditIngestAudience(),
  unconfiguredDetail: 'audit_ingest_audience_unconfigured',
};

module.exports = function auditRouter({
  verify = verifyClientAssertion, db = require('../dbConnection'), serviceId = process.env.MCP_CLIENT_ID,
} = {}) {
  const router = express.Router();
  async function authenticate(req, res, next) {
    if (!serviceId) return res.sendStatus(503);
    const token = /^Bearer ([^\s,]+)$/i.exec(req.get('Authorization') || '');
    if (!token) return res.sendStatus(401);
    try {
      const auth = await verify({ client_assertion: token[1], client_assertion_type: ASSERTION_TYPE },
        { assertionAudience: audience, requireBodyDigest: true, supabase: db });
      if (!auth.ok) return res.sendStatus(auth.httpStatus);
      if (auth.clientId !== serviceId) return res.sendStatus(403);
      res.locals.auditDigest = auth.bodyDigest;
      next();
    } catch { return res.sendStatus(503); }
  }

  router.post('/', authenticate, express.raw({ type: 'application/json', limit: '16kb', inflate: false }),
    async (req, res) => {
      if (!Buffer.isBuffer(req.body)) return res.sendStatus(415);
      if (createHash('sha256').update(req.body).digest('hex') !== res.locals.auditDigest) return res.sendStatus(401);
      let batch;
      try { batch = JSON.parse(req.body.toString('utf8')); } catch { return res.sendStatus(400); }
      if (!validBatch(batch)) return res.sendStatus(400);
      try {
        const { data, error } = await db.rpc('ingest_mcp_audit_events', { envelopes: batch.events });
        if (error?.code === '23505') return res.sendStatus(409);
        if (error || data !== batch.events.length) return res.sendStatus(503);
        const acknowledged = batch.events.map(({ event_id, phase }) => ({ event_id, phase }));
        return res.json({ success: true, data: { acknowledged } });
      } catch { return res.sendStatus(503); }
    });
  router.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    return res.sendStatus([400, 413, 415].includes(err.status) ? err.status : 503);
  });
  return router;
};
