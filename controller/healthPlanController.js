const supabase = require("../dbConnection.js"); // [TEMP-DB-OFF] kept for easy revert
const { generatePlan } = require("../services/aiHealthPlanService");

const toNum = (x) => {
  const n = Number(x);
  return Number.isFinite(n) ? n : undefined;
};

const normGender = (v) => {
  if (v == null) return undefined;
  const s = String(v).trim().toLowerCase();
  if (["m", "male"].includes(s)) return "male";
  if (["f", "female"].includes(s)) return "female";
  if (["prefer_not_to_say", "prefer not to say", "na", "n/a"].includes(s)) return "prefer_not_to_say";
  return "other";
};

function pick(src, keys) {
  if (!src) return undefined;
  for (const k of keys) {
    if (src[k] !== undefined && src[k] !== null && src[k] !== "") return src[k];
  }
  return undefined;
}

function buildHealthSurvey(survey) {
  const gender = normGender(pick(survey, ["Gender", "gender"]));
  const age    = toNum(pick(survey, ["Age", "age"]));
  const height = toNum(pick(survey, ["Height", "height"]));
  const weight = toNum(pick(survey, ["Weight", "weight"]));

  const out = {};
  if (gender != null) out.gender = gender;
  if (age    != null) out.age    = age;
  if (height != null) out.height = height;
  if (weight != null) out.weight = weight;

  return Object.keys(out).length ? out : undefined;
}

function buildHealthGoalFromSurvey(survey) {
  const dpwRaw = pick(survey, ["days_per_week", "daysPerWeek", "DaysPerWeek"]);
  const dpw = Number(dpwRaw);
  if (!Number.isInteger(dpw) || dpw < 0 || dpw > 7) {
    return { error: "survey_data.days_per_week must be an integer 0–7" };
  }

  const out = { days_per_week: dpw };

  const twRaw = pick(survey, ["target_weight", "targetWeight", "TargetWeight"]);
  if (twRaw !== undefined) {
    const tw = Number(twRaw);
    if (!(tw > 0)) return { error: "survey_data.target_weight must be > 0 if provided" };
    out.target_weight = tw;
  }

  const wpRaw = pick(survey, ["workout_place", "workoutPlace", "WorkoutPlace"]);
  if (wpRaw !== undefined) {
    const wp = String(wpRaw).trim().toLowerCase();
    if (!["home", "gym"].includes(wp)) {
      return { error: "survey_data.workout_place must be 'home' or 'gym' if provided" };
    }
    out.workout_place = wp;
  }

  return { value: out };
}

// --------- DB helpers ---------
// [TEMP-DB-OFF] Commented out to avoid writes while user_id is unavailable.
// async function insertHealthPlan(plan) { ... }
// async function insertWeeklyPlans(weeklyPlans) { ... }
// async function deleteHealthPlan(planId) { ... }

function derivePlanGoal(weekly) {
  if (!Array.isArray(weekly) || weekly.length === 0) return null;
  const all = weekly.map((w) => (w?.focus || "").trim()).filter(Boolean);
  if (all.length === 0) return null;
  const first = all[0];
  return all.every((x) => x === first) ? first : "Mixed";
}

/**
 * POST /api/medical-report/plan
 * Body: { medical_report, survey_data, user_id?, survey_id? }
 */
const generateWeeklyPlan = async (req, res) => {
  const body = req.body || {};

  try {
    if (!body.medical_report) {
      return res.status(400).json({ error: "Missing medical_report in request" });
    }
    if (!body.survey_data) {
      return res.status(400).json({ error: "Missing survey_data in request" });
    }

    const hgCheck = buildHealthGoalFromSurvey(body.survey_data);
    if (hgCheck.error) {
      return res.status(400).json({ error: hgCheck.error });
    }
    const health_goal = hgCheck.value;

    const medical_report = Array.isArray(body.medical_report)
      ? body.medical_report
      : [body.medical_report];

    const result = await generatePlan(medical_report, health_goal);

    if (!result.weekly_plan) {
      return res.status(502).json({ error: "AI did not return weekly_plan", message: result });
    }

    // ---------------------- [TEMP-DB-OFF] begin ----------------------
    // DB persistence block removed while FE does not send user_id.
    // See git history to restore insertHealthPlan / insertWeeklyPlans calls.
    // ---------------------- [TEMP-DB-OFF] end ----------------------

    return res.status(200).json({
      plan_id: null,
      suggestion: result.suggestion || "",
      weekly_plan: result.weekly_plan,
      progress_analysis: result.progress_analysis ?? null,
      goal: derivePlanGoal(result.weekly_plan) ?? null,
      length: Array.isArray(result.weekly_plan) ? result.weekly_plan.length : null,
    });
  } catch (err) {
    console.error("[healthPlanController] Unexpected error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = { generateWeeklyPlan };
