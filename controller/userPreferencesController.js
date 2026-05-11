const logger = require("../utils/logger");
const { ServiceError } = require("../services/serviceError");
const userPreferencesService = require("../services/userPreferencesService");
const getPreferenceOptions = require("../model/getPreferenceOptions");

function handleError(res, error, label, context = {}) {
  if (error instanceof ServiceError) {
    return res.status(error.statusCode).json({
      success: false,
      error: error.message,
    });
  }

  if (Number.isInteger(error?.statusCode) && error.statusCode >= 400) {
    return res.status(error.statusCode).json({
      success: false,
      error: error.message,
    });
  }

  logger.error(label, { error: error.message, ...context });
  return res.status(500).json({
    success: false,
    error: "Internal server error",
  });
}

const getUserPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.getExtendedPreferences(req.user.userId);
    return res.status(200).json(response);
  } catch (error) {
    return handleError(res, error, "Error fetching user preferences", {
      userId: req.user?.userId,
    });
  }
};

const postUserPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.updateExtendedPreferences(
      req.user?.userId,
      req.body
    );
    return res.status(200).json(response);
  } catch (error) {
    return handleError(res, error, "Error updating user preferences", {
      userId: req.user?.userId,
    });
  }
};

const getExtendedUserPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.getExtendedPreferences(
      req.user.userId
    );
    return res.status(200).json(response);
  } catch (error) {
    return handleError(res, error, "Error fetching extended user preferences", {
      userId: req.user?.userId,
    });
  }
};

const updateExtendedUserPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.updateExtendedPreferences(
      req.user.userId,
      req.body
    );
    return res.status(200).json(response);
  } catch (error) {
    return handleError(res, error, "Error updating extended user preferences", {
      userId: req.user?.userId,
    });
  }
};

const getNotificationPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.getNotificationPreferences(
      req.user.userId
    );
    return res.status(200).json(response);
  } catch (error) {
    return handleError(
      res,
      error,
      "Error fetching notification preferences",
      { userId: req.user?.userId }
    );
  }
};

const updateNotificationPreferences = async (req, res) => {
  try {
    const response = await userPreferencesService.updateNotificationPreferences(
      req.user.userId,
      req.body.notification_preferences || {}
    );
    return res.status(200).json(response);
  } catch (error) {
    return handleError(
      res,
      error,
      "Error updating notification preferences",
      { userId: req.user?.userId }
    );
  }
};

const getPreferenceOptionsHandler = async (req, res) => {
  try {
    const data = await getPreferenceOptions();
    return res.status(200).json({ success: true, data });
  } catch (error) {
    return handleError(res, error, "Error fetching preference options");
  }
};

module.exports = {
  getUserPreferences,
  postUserPreferences,
  getExtendedUserPreferences,
  updateExtendedUserPreferences,
  getNotificationPreferences,
  updateNotificationPreferences,
  getPreferenceOptionsHandler,
};
