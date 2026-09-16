const consentService = require('../services/consentService');

async function approve(req, res, next) {
  try {
    const result = await consentService.approveConsent({
      userId: req.user.userId,
      transactionId: req.body.transaction_id,
      csrfToken: req.body.csrf_token,
    });

    return res.status(200).json({
      success: true,
      data: result,
    });
  } catch (error) {
    return next(error);
  }
}

module.exports = { approve };