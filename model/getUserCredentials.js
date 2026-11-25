const supabase = require('../dbConnection.js');

async function getUserCredentials(email) {
  const { data, error } = await supabase
    .from('users')
    .select('user_id, email, password, mfa_enabled, role_id, user_roles (id, role_name)')
    .eq('email', email.trim())
    .maybeSingle();
  if (error) throw error;
  return data;
}

module.exports = getUserCredentials;
