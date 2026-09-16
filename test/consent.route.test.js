process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const { expect } = require('chai');
const express = require('express');
const request = require('supertest');
const sinon = require('sinon');

const { authenticateToken } = require('../middleware/authenticateToken');
const authService = require('../services/authService');
sinon.stub(authService, 'verifyAccessToken');
const { createConsentRouter } = require('../routes/consent');
const consentService = { approveConsent: sinon.stub() };
const consentController = {
  approve: async (req, res, next) => {
    try {
      const result = await consentService.approveConsent({
        userId: req.user.userId,
        transactionId: req.body.transaction_id,
        csrfToken: req.body.csrf_token,
      });
      return res.status(200).json({ success: true, data: result });
    } catch (error) {
      return next(error);
    }
  },
};

const ORIGIN = 'https://app.nutrihelp.example';

const makeApp = () => {
  process.env.OAUTH_FRONTEND_ORIGIN = ORIGIN;
  const app = express();
  app.use(express.json());
  app.use('/api/consent', createConsentRouter({ authenticateToken, consentController }));
  app.use((error, _req, res, _next) => {
    res.status(error.status || 500).json({ error: error.message });
  });
  return app;
};

describe('consent approval routes', () => {
  beforeEach(() => {
    authService.verifyAccessToken.reset();
    consentService.approveConsent.reset();
    consentService.approveConsent.resolves({ authorizationCode: 'issued-code' });
  });

  it('requires a website access token', async () => {
    const response = await request(makeApp())
      .post('/api/consent/approve')
      .set('Origin', ORIGIN)
      .send({ transaction_id: 'transaction-1', csrf_token: 'csrf-token-1' });

    expect(response.status).to.equal(401);
    expect(consentService.approveConsent.called).to.equal(false);
  });

  it('rejects an MCP access token on the website consent route', async () => {
    authService.verifyAccessToken.returns({ userId: 42, role: 'user', type: 'mcp_access' });

    const response = await request(makeApp())
      .post('/api/consent/approve')
      .set('Authorization', 'Bearer mcp-token')
      .set('Origin', ORIGIN)
      .send({ transaction_id: 'transaction-1', csrf_token: 'csrf-token-1' });

    expect(response.status).to.equal(401);
    expect(response.body.code).to.equal('INVALID_TOKEN_TYPE');
    expect(consentService.approveConsent.called).to.equal(false);
  });

  it('does not issue a code when approval fails', async () => {
    authService.verifyAccessToken.returns({ userId: 42, role: 'user', type: 'access' });
    const error = new Error('Approval transaction is invalid or expired');
    error.status = 400;
    consentService.approveConsent.rejects(error);

    const response = await request(makeApp())
      .post('/api/consent/approve')
      .set('Authorization', 'Bearer website-token')
      .set('Origin', ORIGIN)
      .send({ transaction_id: 'transaction-1', csrf_token: 'csrf-token-1' });

    expect(response.status).to.equal(400);
    expect(response.body).to.not.have.property('authorizationCode');
    expect(response.body).to.not.have.property('code');
  });

  it('does not issue a code when approval is replayed', async () => {
    authService.verifyAccessToken.returns({ userId: 42, role: 'user', type: 'access' });
    const error = new Error('Approval token has already been used');
    error.status = 409;
    error.code = 'CONSENT_ALREADY_USED';
    consentService.approveConsent.rejects(error);

    const response = await request(makeApp())
      .post('/api/consent/approve')
      .set('Authorization', 'Bearer website-token')
      .set('Origin', ORIGIN)
      .send({ transaction_id: 'transaction-1', csrf_token: 'csrf-token-1' });

    expect(response.status).to.equal(409);
    expect(response.body).to.not.have.property('authorizationCode');
    expect(response.body).to.not.have.property('code');
  });
});