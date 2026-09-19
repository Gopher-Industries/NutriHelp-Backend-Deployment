const express = require('express');
const { authenticateToken } = require('../middleware/authenticateToken');
const { issueCsrfToken } = require('../middleware/csrfProtection');
const { requireExactOrigin } = require('../middleware/requireExactOrigin');
const consentController = require('../controller/consentController');

const createConsentRouter = (deps = {}) => {
	const router = express.Router();
	const authenticate = deps.authenticateToken || authenticateToken;
	const exactOrigin = (deps.requireExactOrigin || requireExactOrigin)(deps);
	const controller = deps.consentController || consentController;

	router.get('/csrf', authenticate, exactOrigin, issueCsrfToken);
	router.post('/approve', authenticate, exactOrigin, controller.approve);

	return router;
};

module.exports = createConsentRouter();
module.exports.createConsentRouter = createConsentRouter;