const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/authenticateToken');
const authorizeRoles = require('../middleware/authorizeRoles');
const { listUserRoles, updateUserRole } = require('../controller/adminUserRoleController');

router.use(authenticateToken);
router.use(authorizeRoles('admin'));

// GET  /api/admin/user-roles
router.get('/user-roles', listUserRoles);

// PATCH /api/admin/user-roles/:userId
router.patch('/user-roles/:userId', updateUserRole);

module.exports = router;
