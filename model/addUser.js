const supabase = require('../dbConnection.js');
const { encrypt } = require('../services/encryptionService');

// The email conflict target makes concurrent registration attempts insert-only.
async function addUser(name, email, password, mfa_enabled, contact_number, address) {
  const { data, error } = await supabase
    .from('users')
    .upsert(
      {
        name,
        email,
        password,
        mfa_enabled,
        contact_number: contact_number ? JSON.stringify(await encrypt(contact_number)) : null,
        address: address ? JSON.stringify(await encrypt(address)) : null,
      },
      { onConflict: 'email', ignoreDuplicates: true }
    )
    .select('user_id');

  if (error) throw error;
  if (!Array.isArray(data)) throw new Error('User insert was not acknowledged');
  if (data.length === 0) return null; // Another request already created the row.
  if (!data[0]?.user_id) throw new Error('User insert did not return an ID');
  return data[0];
}
module.exports = addUser;
