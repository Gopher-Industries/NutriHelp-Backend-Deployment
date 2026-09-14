const supabase = require('../../dbConnection');

/**
 * Current role at exchange time. No authService fallbacks — missing role fails
 * closed as refused → invalid_grant. DB errors are unavailable → 503.
 *
 * Own module (ticket 12): do not build against authRepository.js.
 */

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/** PostgREST may return the embedded to-one as object or single-element array. */
const embeddedRole = (userRoles) => {
  const row = Array.isArray(userRoles) ? userRoles[0] : userRoles;
  return row && isNonEmptyString(row.role_name) ? row.role_name.trim() : null;
};

const resolveRole = async (userId, deps = {}) => {
  const db = deps.supabase || supabase;

  let userRow;
  try {
    const { data, error } = await db
      .from('users')
      // Left join: inner join collapses "no role" with "no user".
      .select('user_id, role_id, user_roles!left(role_name)')
      .eq('user_id', userId)
      .maybeSingle();

    if (error) return { outcome: 'unavailable', detail: 'role_lookup_failed' };
    userRow = data;
  } catch (err) {
    return { outcome: 'unavailable', detail: 'role_lookup_failed' };
  }

  if (!userRow) return { outcome: 'refused', detail: 'user_not_found' };

  const role = embeddedRole(userRow.user_roles);
  if (!role) return { outcome: 'refused', detail: 'role_unresolved' };

  return { outcome: 'resolved', role };
};

module.exports = { resolveRole };
