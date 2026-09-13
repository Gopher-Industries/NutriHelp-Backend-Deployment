const express = require('express');
const { authenticateToken } = require('../middleware/authenticateToken');
const { requireCsrfToken, requireFrontendOrigin, issueCsrfToken } = require('../middleware/csrfProtection');
const consentController = require('../controller/consentController');

const router = express.Router();

router.get('/csrf', authenticateToken, requireFrontendOrigin, issueCsrfToken);
router.post('/approve', authenticateToken, requireFrontendOrigin, requireCsrfToken, consentController.approve);

module.exports = router;