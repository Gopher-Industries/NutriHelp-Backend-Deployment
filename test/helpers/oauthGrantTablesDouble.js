/**
 * Supabase double for oauth_authorization_codes, oauth_refresh_tokens,
 * mcp_client_grants (ticket 39b). Models rows/filters so second operations see
 * consumed/used/revoked state — a write-sink double would green-pass broken
 * single-use. Reproduces lookup_hash UNIQUE and one-child-per-parent.
 *
 * Thenable builder; .is(col, null); maybeSingle/single. Does not project
 * columns — .select('id') still returns the whole row here.
 */

const UNIQUE_VIOLATION = '23505';

/**
 * @param seed.codes           oauth_authorization_codes rows
 * @param seed.refreshTokens   oauth_refresh_tokens rows
 * @param seed.grants          mcp_client_grants rows
 * @param seed.failures        { '<table>.<op>': error } — mutable mid-test via db.failures
 * @param seed.insertCommitsThenFails  row written, call still errors (timeout after commit); once, child inserts only
 * @param seed.consumeCodeAfterRead  concurrent redeem: read unconsumed, then consumed before our update
 * @param seed.claimTokenAfterRead  concurrent rotation: refresh token reads back
 *   unused, then another request claims it before ours does. Only a conditional
 *   claim notices. Fires once, on the lookup_hash read.
 */
const makeDb = ({
  codes = [],
  refreshTokens = [],
  grants = [],
  failures = {},
  consumeCodeAfterRead = false,
  insertCommitsThenFails = false,
  claimTokenAfterRead = false,
} = {}) => {
  // Clone so a test's seed object is never mutated across cases.
  const tables = {
    oauth_authorization_codes: codes.map((row) => ({ ...row })),
    oauth_refresh_tokens: refreshTokens.map((row) => ({ ...row })),
    mcp_client_grants: grants.map((row) => ({ ...row })),
  };

  const calls = {
    codeConsumes: [],
    refreshInserts: [],
    refreshUpdates: [],
    grantUpdates: [],
    // insert attempts including failures — proves a guard stopped the write.
    insertAttempts: [],
  };

  let nextId = 9000;

  const isNullish = (value) => value === null || value === undefined;

  const constraintError = (table, row) => {
    if (table !== 'oauth_refresh_tokens') return null;

    const rows = tables[table];
    if (rows.some((existing) => existing.lookup_hash === row.lookup_hash)) {
      return { code: UNIQUE_VIOLATION, message: 'oauth_refresh_tokens_lookup_hash_key' };
    }
    // UNIQUE(parent_id): null parents exempt; second child of one parent fails.
    if (
      !isNullish(row.parent_id) &&
      rows.some((existing) => existing.parent_id === row.parent_id)
    ) {
      return {
        code: UNIQUE_VIOLATION,
        message: 'oauth_refresh_tokens_one_child_per_parent',
      };
    }
    return null;
  };

  const recordWrite = (table, op, payload) => {
    if (table === 'oauth_authorization_codes' && op === 'update') calls.codeConsumes.push(payload);
    if (table === 'oauth_refresh_tokens' && op === 'insert') calls.refreshInserts.push(payload);
    if (table === 'oauth_refresh_tokens' && op === 'update') calls.refreshUpdates.push(payload);
    if (table === 'mcp_client_grants' && op === 'update') calls.grantUpdates.push(payload);
  };

  const builder = (table) => {
    const filters = [];
    let pending = null;

    const matches = (row) =>
      filters.every(([op, column, value]) =>
        op === 'is' ? isNullish(row[column]) : row[column] === value
      );

    const run = () => {
      const rows = tables[table];
      const op = pending ? pending.op : 'select';
      const injected = failures[`${table}.${op}`];
      if (injected) return { data: null, error: injected };

      if (op === 'insert') {
        calls.insertAttempts.push({ table, rows: pending.rows.length });
        const inserted = [];
        for (const row of pending.rows) {
          const violation = constraintError(table, row);
          if (violation) return { data: null, error: violation };
          const stored = { id: (nextId += 1), ...row };
          rows.push(stored);
          inserted.push({ ...stored });
        }
        recordWrite(table, 'insert', inserted);

        // Committed then reported failed (child inserts only).
        if (
          insertCommitsThenFails &&
          table === 'oauth_refresh_tokens' &&
          !isNullish(pending.rows[0].parent_id)
        ) {
          insertCommitsThenFails = false;
          return { data: null, error: { code: '57014', message: 'statement timeout' } };
        }

        return { data: inserted, error: null };
      }

      const matched = rows.filter(matches);

      // Concurrent rotation claims the token between our read and our claim.
      // Scoped to the lookup_hash read so the child probe is unaffected.
      if (
        op === 'select' &&
        table === 'oauth_refresh_tokens' &&
        claimTokenAfterRead &&
        filters.some(([, column]) => column === 'lookup_hash')
      ) {
        claimTokenAfterRead = false;
        matched.forEach((row) => {
          row.used_at = new Date().toISOString();
        });
        return { data: matched.map((row) => ({ ...row, used_at: null })), error: null };
      }

      // Concurrent consume lands after our read, before our update.
      if (op === 'select' && table === 'oauth_authorization_codes' && consumeCodeAfterRead) {
        consumeCodeAfterRead = false;
        matched.forEach((row) => {
          row.consumed_at = new Date().toISOString();
        });
        return { data: matched.map((row) => ({ ...row, consumed_at: null })), error: null };
      }

      if (op === 'update') {
        matched.forEach((row) => Object.assign(row, pending.patch));
        recordWrite(table, 'update', {
          filters: filters.slice(),
          patch: pending.patch,
          matched: matched.length,
        });
      }

      return { data: matched.map((row) => ({ ...row })), error: null };
    };

    const chain = {
      select: () => chain,
      eq: (column, value) => {
        filters.push(['eq', column, value]);
        return chain;
      },
      is: (column, value) => {
        if (value !== null) throw new Error('double models .is(col, null) only');
        filters.push(['is', column, null]);
        return chain;
      },
      insert: (rows) => {
        pending = { op: 'insert', rows: Array.isArray(rows) ? rows : [rows] };
        return chain;
      },
      update: (patch) => {
        pending = { op: 'update', patch };
        return chain;
      },
      maybeSingle: async () => {
        const { data, error } = run();
        if (error) return { data: null, error };
        return { data: data.length > 0 ? data[0] : null, error: null };
      },
      single: async () => {
        const { data, error } = run();
        if (error) return { data: null, error };
        if (data.length !== 1) {
          return { data: null, error: { code: 'PGRST116', message: 'no rows returned' } };
        }
        return { data: data[0], error: null };
      },
      // PostgrestBuilder is thenable: awaiting the chain runs the query.
      then: (resolve, reject) => Promise.resolve(run()).then(resolve, reject),
    };

    return chain;
  };

  return {
    calls,
    tables,
    failures,
    from: (table) => {
      if (!tables[table]) throw new Error(`unexpected table: ${table}`);
      return builder(table);
    },
  };
};

module.exports = { makeDb, UNIQUE_VIOLATION };
