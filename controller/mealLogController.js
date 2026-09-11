const { createMealLogService } = require('../services/mealLogService');

function createMealLogController(service = createMealLogService()) {
  return async (req, res, next) => {
    try {
      const result = await service.save(req.user?.userId, req.mealLogInput);
      res.status(result.created ? 201 : 200).json({ success: true, data: result.record });
    } catch (error) {
      next(error);
    }
  };
}

module.exports = { createMealLogController };
