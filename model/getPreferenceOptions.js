const supabase = require("../dbConnection.js");

const OPTION_TABLES = [
  { key: "dietary_requirements", table: "dietary_requirements" },
  { key: "allergies",            table: "allergies" },
  { key: "cuisines",             table: "cuisines" },
  { key: "dislikes",             table: "dislikes" },
  { key: "health_conditions",    table: "health_conditions" },
  { key: "spice_levels",         table: "spice_levels" },
  { key: "cooking_methods",      table: "cooking_methods" },
];

async function getPreferenceOptions() {
  const results = await Promise.all(
    OPTION_TABLES.map(async ({ key, table }) => {
      const { data, error } = await supabase
        .from(table)
        .select("id, name")
        .order("name", { ascending: true });

      if (error) throw error;
      return [key, Array.isArray(data) ? data : []];
    })
  );

  return Object.fromEntries(results);
}

module.exports = getPreferenceOptions;
