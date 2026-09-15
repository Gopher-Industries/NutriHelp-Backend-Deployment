/**
 * Supabase double for the oauth_clients / oauth_authorization_transactions
 * pair, shared by every ticket-36 suite.
 *
 * ONE model of these tables, deliberately. Two hand-maintained doubles of one
 * table is the drift shape this project keeps recording — and it bit here
 * exactly once already: a second, simpler double in the rate-limit suite still
 * offered `upsert` after the service had moved to a conditional write, so its
 * "allowed" requests were quietly failing to a server_error redirect instead
 * of reaching the frontend.
 */

/**
 * Supabase double, modelling oauth_clients as an actual keyed table rather
 * than a write sink.
 *
 * It has to, because the property under test is what happens when a row for
 * this client_id ALREADY EXISTS as something else. A permissive double that
 * just records writes goes green for code that overwrites the MCP server's own
 * confidential client into an assistant public one.
 *
 * So the conditional write is simulated faithfully:
 *   update(...).eq(client_id).eq(client_type) matches only when BOTH match
 *   insert(...) on an occupied primary key returns Postgres 23505
 * and a test can seed an existing row of any client_type.
 *
 * @param existingClient  a row already in oauth_clients, or null
 */
const makeDb = ({
  insertError = null,
  clientWriteError = null,
  existingClient = null,
  // Models a CONCURRENT first-sight request that inserted the row between our
  // UPDATE and our INSERT: the insert collides, and the row it collided with
  // is an ordinary assistant row that a re-run UPDATE will match.
  concurrentInsertWins = null,
} = {}) => {
  const calls = { transactionInserts: [], clientUpdates: [], clientInserts: [] };
  // Clone so a test's seed object is never mutated across cases.
  const clients = existingClient ? [{ ...existingClient }] : [];

  return {
    calls,
    clients,
    from(table) {
      if (table === 'oauth_authorization_transactions') {
        return {
          insert: async (rows) => {
            calls.transactionInserts.push(...rows);
            if (insertError) return { data: null, error: insertError };
            return { data: rows, error: null };
          },
        };
      }

      if (table === 'oauth_clients') {
        const filters = [];
        const chain = {
          update: (row) => {
            chain.__pending = { op: 'update', row };
            return chain;
          },
          insert: async (rows) => {
            calls.clientInserts.push(...rows);
            if (clientWriteError) return { data: null, error: clientWriteError };
            if (concurrentInsertWins && clients.length === 0) {
              clients.push({ ...concurrentInsertWins });
              return { data: null, error: { code: '23505', message: 'duplicate key' } };
            }
            const clash = clients.find((c) => c.client_id === rows[0].client_id);
            // Primary key on client_id.
            if (clash) return { data: null, error: { code: '23505', message: 'duplicate key' } };
            clients.push({ ...rows[0] });
            return { data: rows, error: null };
          },
          eq: (column, value) => {
            filters.push([column, value]);
            return chain;
          },
          select: async () => {
            if (clientWriteError) return { data: null, error: clientWriteError };
            const matched = clients.filter((row) =>
              filters.every(([column, value]) => row[column] === value)
            );
            matched.forEach((row) => Object.assign(row, chain.__pending.row));
            calls.clientUpdates.push({ filters: filters.slice(), matched: matched.length });
            return { data: matched.map((r) => ({ client_id: r.client_id })), error: null };
          },
        };
        return chain;
      }

      throw new Error(`unexpected table: ${table}`);
    },
  };
};

module.exports = { makeDb };
