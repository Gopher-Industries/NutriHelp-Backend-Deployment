const crypto = require('crypto');
const { getSupabaseServiceClient } = require('./supabaseClient');

function hashValue(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

async function approveConsent({ userId, transactionId, approvalToken }) {
  if (!userId || !transactionId || !approvalToken) {
    const error = new Error('transactionId and approvalToken are required');
    error.status = 400;
    throw error;
  }

  const supabase = getSupabaseServiceClient();
  if (!supabase) {
    const error = new Error('Supabase service client is not configured');
    error.status = 503;
    throw error;
  }

  const { data, error } = await supabase.rpc('approve_oauth_authorization', {
    p_transaction_id: transactionId,
    p_user_id: userId,
    p_approval_token_hash: hashValue(approvalToken),
  });

  if (error) {
    const serviceError = new Error('Consent approval is unavailable until the OAuth schema is installed');
    serviceError.status = error.code === '42883' ? 503 : 500;
    serviceError.cause = error;
    throw serviceError;
  }

  if (!data || data.status !== 'approved') {
    const errorResponse = new Error(data?.status === 'already_used'
      ? 'Approval token has already been used'
      : 'Approval transaction is invalid or expired');
    errorResponse.status = data?.status === 'already_used' ? 409 : 400;
    errorResponse.code = data?.status === 'already_used' ? 'CONSENT_ALREADY_USED' : 'CONSENT_INVALID';
    throw errorResponse;
  }

  return {
    authorizationCode: data.authorization_code,
    transactionId: data.transaction_id,
    redirectUri: data.redirect_uri,
    state: data.state,
  };
}

module.exports = { approveConsent };