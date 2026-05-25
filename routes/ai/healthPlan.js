const express = require("express");
const { generatePlan } = require("../../services/aiHealthPlanService");

const router = express.Router();

router.post("/generate", async (req, res) => {
  try {
    const { medical_report, health_goal } = req.body;
    if (!medical_report || !health_goal) {
      return res.status(400).json({ error: "medical_report and health_goal are required" });
    }
    const result = await generatePlan(medical_report, health_goal);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: "Plan generation failed due to server error.", detail: e.message });
  }
});

module.exports = router;
