const express = require("express");
const router = express.Router();
const controller = require("../controller/userPreferencesController");
const { authenticateToken } = require("../middleware/authenticateToken");
const {
  validateUserPreferences,
  validateHealthContext,
  validateNotificationPreferences,
} = require("../validators/userPreferencesValidator");
const ValidateRequest = require("../middleware/validateRequest");

// GET /api/user/preferences/options — all available lookup options for dropdowns (no auth needed)
router.get("/options", controller.getPreferenceOptionsHandler);

// GET /api/user/preferences — authenticated user reads own preferences
router.get("/", authenticateToken, controller.getUserPreferences);

// POST /api/user/preferences — requires all 7 food preference arrays (full reset)
router.post(
  "/",
  authenticateToken,
  validateUserPreferences,
  ValidateRequest,
  controller.postUserPreferences
);

// PUT /api/user/preferences — partial update: any combination of food prefs + health_context + notifications + ui
router.put(
  "/",
  authenticateToken,
  validateHealthContext,
  ValidateRequest,
  controller.postUserPreferences
);

// GET /api/user/preferences/extended — authenticated user reads full health-context + food prefs
router.get("/extended", authenticateToken, controller.getExtendedUserPreferences);

// PUT /api/user/preferences/extended — authenticated user updates health-context
router.put(
  "/extended",
  authenticateToken,
  validateHealthContext,
  ValidateRequest,
  controller.updateExtendedUserPreferences
);

// GET /api/user/preferences/extended/notifications — authenticated user reads notification prefs
router.get(
  "/extended/notifications",
  authenticateToken,
  controller.getNotificationPreferences
);

// PUT /api/user/preferences/extended/notifications — authenticated user updates notification prefs
router.put(
  "/extended/notifications",
  authenticateToken,
  validateNotificationPreferences,
  ValidateRequest,
  controller.updateNotificationPreferences
);

module.exports = router;
