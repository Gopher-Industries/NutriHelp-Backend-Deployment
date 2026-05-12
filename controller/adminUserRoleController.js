const { getSupabaseServiceClient } = require('../services/supabaseClient');

const listUserRoles = async (req, res) => {
  try {
    const supabase = getSupabaseServiceClient();
    if (!supabase) {
      return res.status(503).json({ success: false, error: 'Database service unavailable.' });
    }

    const { limit = 50, q, role, created_from, created_to } = req.query;
    const parsedLimit = Math.min(parseInt(limit, 10) || 50, 500);

    let query = supabase
      .from('users')
      .select('user_id, email, name, account_status, created_at, user_roles!left(role_name)', { count: 'exact' })
      .limit(parsedLimit)
      .order('created_at', { ascending: false });

    if (q) {
      query = query.or(`email.ilike.%${q}%,name.ilike.%${q}%`);
    }
    if (created_from) {
      query = query.gte('created_at', created_from);
    }
    if (created_to) {
      query = query.lte('created_at', created_to);
    }

    const { data, error, count } = await query;

    if (error) {
      return res.status(500).json({ success: false, error: error.message });
    }

    let users = data || [];

    if (role) {
      users = users.filter(u => (u.user_roles?.role_name || '').toLowerCase() === role.toLowerCase());
    }

    res.json({
      success: true,
      total: count,
      data: users.map(u => ({
        user_id: u.user_id,
        email: u.email,
        name: u.name,
        role: u.user_roles?.role_name || 'user',
        account_status: u.account_status,
        created_at: u.created_at,
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
};

const updateUserRole = async (req, res) => {
  try {
    const supabase = getSupabaseServiceClient();
    if (!supabase) {
      return res.status(503).json({ success: false, error: 'Database service unavailable.' });
    }

    const { userId } = req.params;
    const { role } = req.body;

    if (!role || typeof role !== 'string') {
      return res.status(400).json({ success: false, error: 'role is required.' });
    }

    const { data: roleRow, error: roleError } = await supabase
      .from('user_roles')
      .select('id')
      .eq('role_name', role.trim())
      .single();

    if (roleError || !roleRow) {
      return res.status(400).json({ success: false, error: `Role '${role}' does not exist.` });
    }

    const { data, error } = await supabase
      .from('users')
      .update({ role_id: roleRow.id })
      .eq('user_id', userId)
      .select('user_id, email, name, account_status')
      .single();

    if (error) {
      const status = error.code === 'PGRST116' ? 404 : 500;
      return res.status(status).json({ success: false, error: error.message });
    }
    if (!data) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    res.json({ success: true, data: { ...data, role } });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
};

module.exports = { listUserRoles, updateUserRole };
