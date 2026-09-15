const crypto = require('crypto');
const { expect } = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();
const {
  requireCsrfToken,
  requireFrontendOrigin,
} = require('../../middleware/csrfProtection');

describe('consent approval', () => {
  afterEach(() => sinon.restore());

  it('hashes the single-use token and returns the authorization code from the OAuth transaction', async () => {
    const rpc = sinon.stub().resolves({
      data: {
        status: 'approved',
        authorization_code: 'one-time-code',
        transaction_id: 'transaction-1',
        redirect_uri: 'https://assistant.example/callback',
        state: 'state-1',
      },
      error: null,
    });
    const service = proxyquire('../../services/consentService', {
      './supabaseClient': { getSupabaseServiceClient: () => ({ rpc }) },
    });

    const result = await service.approveConsent({
      userId: 42,
      transactionId: 'transaction-1',
      approvalToken: 'approval-secret',
    });

    expect(rpc.calledOnce).to.equal(true);
    expect(rpc.firstCall.args[0]).to.equal('approve_oauth_authorization');
    expect(rpc.firstCall.args[1]).to.deep.equal({
      p_transaction_id: 'transaction-1',
      p_user_id: 42,
      p_approval_token_hash: crypto.createHash('sha256').update('approval-secret').digest('hex'),
    });
    expect(result).to.deep.equal({
      authorizationCode: 'one-time-code',
      transactionId: 'transaction-1',
      redirectUri: 'https://assistant.example/callback',
      state: 'state-1',
    });
  });

  it('rejects a replay reported by the atomic OAuth operation', async () => {
    const service = proxyquire('../../services/consentService', {
      './supabaseClient': {
        getSupabaseServiceClient: () => ({
          rpc: sinon.stub().resolves({ data: { status: 'already_used' }, error: null }),
        }),
      },
    });

    try {
      await service.approveConsent({ userId: 42, transactionId: 'transaction-1', approvalToken: 'secret' });
      throw new Error('Expected replay to be rejected');
    } catch (error) {
      expect(error.status).to.equal(409);
      expect(error.code).to.equal('CONSENT_ALREADY_USED');
    }
  });

  it('fails closed when the OAuth schema operation is not installed', async () => {
    const service = proxyquire('../../services/consentService', {
      './supabaseClient': {
        getSupabaseServiceClient: () => ({
          rpc: sinon.stub().resolves({ error: { code: '42883' } }),
        }),
      },
    });

    try {
      await service.approveConsent({ userId: 42, transactionId: 'transaction-1', approvalToken: 'secret' });
      throw new Error('Expected missing OAuth operation to be rejected');
    } catch (error) {
      expect(error.status).to.equal(503);
    }
  });

  it('requires the exact production frontend origin', () => {
    const previousEnvironment = process.env.NODE_ENV;
    const previousOrigin = process.env.FRONTEND_ORIGIN;
    process.env.NODE_ENV = 'production';
    process.env.FRONTEND_ORIGIN = 'https://app.nutrihelp.example';

    const rejected = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    requireFrontendOrigin({ headers: { origin: 'https://preview.nutrihelp.example' } }, rejected, sinon.stub());
    expect(rejected.status.calledWith(403)).to.equal(true);

    const accepted = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    const next = sinon.stub();
    requireFrontendOrigin({ headers: { origin: 'https://app.nutrihelp.example' } }, accepted, next);
    expect(next.calledOnce).to.equal(true);

    process.env.NODE_ENV = previousEnvironment;
    process.env.FRONTEND_ORIGIN = previousOrigin;
  });

  it('requires the CSRF header to match the consent cookie', () => {
    const request = {
      headers: {
        'x-csrf-token': 'csrf-value',
        cookie: 'nutrihelp_csrf=csrf-value',
      },
    };
    const next = sinon.stub();
    requireCsrfToken(request, {}, next);
    expect(next.calledOnce).to.equal(true);

    const rejected = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    requireCsrfToken({ headers: { 'x-csrf-token': 'wrong', cookie: 'nutrihelp_csrf=csrf-value' } }, rejected, sinon.stub());
    expect(rejected.status.calledWith(403)).to.equal(true);
  });
});