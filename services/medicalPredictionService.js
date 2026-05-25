const { ServiceError } = require('./serviceError');

function pick(data, keys) {
  for (const k of keys) {
    if (data[k] !== undefined && data[k] !== null && String(data[k]).trim() !== '') return data[k];
  }
  return undefined;
}

function toNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function toBool(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).toLowerCase().trim();
  if (['yes', 'true', '1'].includes(s)) return true;
  if (['no', 'false', '0'].includes(s)) return false;
  return null;
}

function computeBMI(weight, height) {
  if (!weight || !height || height <= 0) return null;
  return weight / (height * height);
}

// WHO + study-aligned obesity levels matching the ML model labels
function classifyObesity(bmi) {
  if (bmi === null) return null;
  if (bmi < 18.5) return { obesity_level: 'Insufficient_Weight',  confidence: 92.0 };
  if (bmi < 25.0) return { obesity_level: 'Normal_Weight',         confidence: 94.0 };
  if (bmi < 27.5) return { obesity_level: 'Overweight_Level_I',    confidence: 88.0 };
  if (bmi < 30.0) return { obesity_level: 'Overweight_Level_II',   confidence: 86.0 };
  if (bmi < 35.0) return { obesity_level: 'Obesity_Type_I',        confidence: 89.0 };
  if (bmi < 40.0) return { obesity_level: 'Obesity_Type_II',       confidence: 87.0 };
  return           { obesity_level: 'Obesity_Type_III',             confidence: 91.0 };
}

// Simple evidence-based diabetes risk score from survey fields
function assessDiabetes(data, bmi) {
  let score = 0;

  if (bmi !== null) {
    if (bmi >= 30) score += 2;
    else if (bmi >= 25) score += 1;
  }

  const familyHistory = toBool(pick(data, [
    'Any family history of overweight (yes/no)', 'family_history_with_overweight',
  ]));
  if (familyHistory === true) score += 1;

  const highCalorie = toBool(pick(data, [
    'Frequent High Calorie Food Consumption (yes/no)', 'FAVC',
  ]));
  if (highCalorie === true) score += 1;

  const activity = toNum(pick(data, ['Physical Activity Frequency', 'FAF']));
  if (activity !== null) {
    if (activity === 0) score += 2;
    else if (activity < 2) score += 1;
  }

  const water = toNum(pick(data, ['Daily Water Intake', 'CH2O']));
  if (water !== null && water < 1.5) score += 1;

  const monitorsCalories = toBool(pick(data, [
    'Do you monitor your daily calories?', 'SCC',
  ]));
  if (monitorsCalories === false) score += 1;

  const smokes = toBool(pick(data, ['Do you Smoke?', 'SMOKE']));
  if (smokes === true) score += 1;

  const diabetes = score >= 4;
  // confidence increases as score moves further from the threshold of 4
  const confidence = Math.round(Math.min(95, 55 + Math.abs(score - 4) * 8) * 10) / 10;
  return { diabetes, confidence };
}

function encodeMedicalSurvey(data) {
  const maps = {
    male: 1, female: 0,
    yes: 1, no: 0,
    true: 1, false: 0,
    bus: 'Public_Transportation', Yes: 'yes',
  };
  const encoded = {};
  for (const k in data) {
    let val = data[k];
    if (maps[val] !== undefined) val = maps[val];
    if (typeof val === 'string' && val.trim() !== '' && !isNaN(val)) val = Number(val);
    encoded[k] = val;
  }
  return encoded;
}

class MedicalPredictionService {
  async predict(surveyData) {
    if (!surveyData || typeof surveyData !== 'object') {
      throw new ServiceError(400, 'Survey data is required');
    }

    const weight = toNum(pick(surveyData, ['Weight', 'weight']));
    const height = toNum(pick(surveyData, ['Height', 'height']));
    const bmi    = computeBMI(weight, height);

    const obesityResult  = classifyObesity(bmi);
    const diabetesResult = assessDiabetes(surveyData, bmi);

    if (!obesityResult) {
      throw new ServiceError(422, 'Cannot compute obesity level: height and weight are required');
    }

    return {
      statusCode: 200,
      body: {
        medical_report: {
          obesity_prediction:  obesityResult,
          diabetes_prediction: diabetesResult,
          ...(bmi !== null ? { bmi: Math.round(bmi * 100) / 100 } : {}),
        },
        survey_id: null,
      },
    };
  }
}

const medicalPredictionService = new MedicalPredictionService();

module.exports = { MedicalPredictionService, medicalPredictionService, encodeMedicalSurvey };
