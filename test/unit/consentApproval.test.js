const crypto = require('crypto');
const { expect } = require('chai');
const sinon = require('sinon');
const { approveConsent } = require('../../services/consentService');
const { requireCsrfToken } = require('../../middleware/csrfProtection');
const { requireExactOrigin } = require('../../middleware/requireExactOrigin');

describe('consent approval', () => {
  afterEach(() => sinon.restore());

  it('hashes the transaction reference and returns the authorization code', async () => {
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
    const result = await approveConsent({
      userId: 42,
      transactionId: 'transaction-1',
      csrfToken: 'csrf-token-1',
      supabase: { rpc },
    });

    expect(rpc.calledOnce).to.equal(true);
    expect(rpc.firstCall.args[0]).to.equal('approve_oauth_authorization');
    expect(rpc.firstCall.args[1]).to.deep.equal({
      p_transaction_hash: crypto.createHash('sha256').update('transaction-1').digest('hex'),
      p_user_id: 42,
      p_csrf_token: 'csrf-token-1',
    });
    expect(result).to.deep.equal({
      authorizationCode: 'one-time-code',
      transactionId: 'transaction-1',
      redirectUri: 'https://assistant.example/callback',
      state: 'state-1',
    });
  });

  it('rejects a replay reported by the atomic OAuth operation', async () => {
    try {
      await approveConsent({
        userId: 42,
        transactionId: 'transaction-1',
        csrfToken: 'csrf-token-1',
        supabase: {
          rpc: sinon.stub().resolves({ data: { status: 'already_used' }, error: null }),
        },
      });
      throw new Error('Expected replay to be rejected');
    } catch (error) {
      expect(error.status).to.equal(409);
      expect(error.code).to.equal('CONSENT_ALREADY_USED');
    }
  });

  it('fails closed when the OAuth schema operation is not installed', async () => {
    try {
      await approveConsent({
        userId: 42,
        transactionId: 'transaction-1',
        csrfToken: 'csrf-token-1',
        supabase: {
          rpc: sinon.stub().resolves({ error: { code: '42883' } }),
        },
      });
      throw new Error('Expected missing OAuth operation to be rejected');
    } catch (error) {
      expect(error.status).to.equal(503);
    }
  });

  it('requires the exact production frontend origin', () => {
    const previousEnvironment = process.env.NODE_ENV;
    const previousOrigin = process.env.OAUTH_FRONTEND_ORIGIN;
    process.env.NODE_ENV = 'production';
    process.env.OAUTH_FRONTEND_ORIGIN = 'https://app.nutrihelp.example';
    const requireOrigin = requireExactOrigin();

    const rejected = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    requireOrigin(
      { get: (header) => (header === 'origin' ? 'https://preview.nutrihelp.example' : undefined) },
      rejected,
      sinon.stub()
    );
    expect(rejected.status.calledWith(403)).to.equal(true);

    const accepted = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    const next = sinon.stub();
    requireOrigin(
      { get: (header) => (header === 'origin' ? 'https://app.nutrihelp.example' : undefined) },
      accepted,
      next
    );
    expect(next.calledOnce).to.equal(true);

    const absentOrigin = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    requireOrigin({ get: () => undefined }, absentOrigin, sinon.stub());
    expect(absentOrigin.status.calledWith(403)).to.equal(true);

    const nullOrigin = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    requireOrigin({ get: () => 'null' }, nullOrigin, sinon.stub());
    expect(nullOrigin.status.calledWith(403)).to.equal(true);

    process.env.NODE_ENV = previousEnvironment;
    process.env.OAUTH_FRONTEND_ORIGIN = previousOrigin;
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

    const malformed = {
      status: sinon.stub().returnsThis(),
      json: sinon.stub().returnsThis(),
    };
    expect(() =>
      requireCsrfToken(
        { headers: { 'x-csrf-token': 'abé', cookie: 'nutrihelp_csrf=abc' } },
        malformed,
        sinon.stub()
      )
    ).to.not.throw();
    expect(malformed.status.calledWith(403)).to.equal(true);
  });
});