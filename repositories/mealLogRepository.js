const { ServiceError } = require('../services/serviceError');

// Text casts preserve bigint IDs across PostgREST's JSON boundary.
const projection =
  'id::text,date::text,meal_type,food_name,calories,protein,carbs,fat,fiber,sugar,sodium,time::text';

function createMealLogRepository(
  getClient = () => require('../services/supabaseClient').getSupabaseServiceClient()
) {
  function table() {
    const client = getClient();
    if (!client) throw new ServiceError(503, 'Meal log storage is unavailable');
    // This must be the service-role client: Ticket 46 enables RLS with zero policies.
    return client.from('nutrition_records');
  }

  return {
    async insert(userId, keyHash, meal) {
      const { data, error } = await table()
        .insert({ ...meal, user_id: userId, idempotency_key_hash: keyHash })
        .select(projection)
        .single();
      if (error) throw error;
      return data;
    },
    async findByKey(userId, keyHash) {
      const { data, error } = await table()
        .select(projection)
        .eq('user_id', userId)
        .eq('idempotency_key_hash', keyHash)
        .maybeSingle();
      if (error) throw error;
      return data;
    },
  };
}

module.exports = { createMealLogRepository };
