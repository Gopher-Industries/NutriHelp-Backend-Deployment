// Loopback-only Supabase transport fixture. The production SDK sends its normal
// HTTP requests here; users and MFA tokens are stored in a disposable PostgreSQL.
const express = require('express');
const { PGlite } = require('@electric-sql/pglite');
const { randomUUID } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { readFileSync } = require('node:fs');
const path = require('node:path');

async function startBackend() {
  const db = new PGlite();
  await db.exec(`
    CREATE TABLE users(user_id serial PRIMARY KEY, email text NOT NULL, name text NOT NULL,
      password text NOT NULL, contact_number text, address text, mfa_enabled boolean NOT NULL);
    CREATE TABLE mfatokens(id serial PRIMARY KEY, user_id integer REFERENCES users,
      token integer NOT NULL, expiry timestamptz NOT NULL, is_used boolean NOT NULL);
  `);
  const migration = readFileSync(
    path.join(__dirname, '../../database/migrations/006_registration_email_uniqueness.sql'),
    'utf8'
  );
  await db.exec(migration);
  await db.exec(migration);
  const identities = new Map();
  const options = { confirmFirst: false, failNextInsert: false, failNextRead: false };
  const app = express();
  app.use(express.json());
  app.use('/auth/v1', (_req, res, next) => {
    res.set('X-Supabase-Api-Version', '2024-01-01');
    next();
  });
  function session(user) {
    return {
      access_token: jwt.sign({ sub: user.id, role: 'authenticated' }, 'fixture-only', {
        expiresIn: '1h',
      }),
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: randomUUID(),
      user,
    };
  }
  app.post('/auth/v1/signup', (req, res) => {
    const { email, password, data } = req.body;
    if (identities.has(email)) return res.json({ id: randomUUID(), email, identities: [] });
    const user = {
      id: randomUUID(),
      email,
      user_metadata: data,
      email_confirmed_at: options.confirmFirst ? null : new Date().toISOString(),
    };
    identities.set(email, { password, user });
    return res.json(options.confirmFirst ? user : session(user));
  });
  app.post('/auth/v1/token', (req, res) => {
    const account = identities.get(req.body.email);
    if (!account || account.password !== req.body.password)
      return res.status(400).json({ code: 'invalid_credentials', message: 'Invalid credentials' });
    if (!account.user.email_confirmed_at)
      return res.status(400).json({ code: 'email_not_confirmed', message: 'Email not confirmed' });
    return res.json(session(account.user));
  });
  app.post('/auth/v1/logout', (_req, res) => res.sendStatus(204));
  app.post('/rest/v1/profiles', (_req, res) => res.status(201).end());
  app.all('/rest/v1/brute_force_logs', (req, res) =>
    req.method === 'GET' ? res.json([]) : res.status(204).end()
  );
  app.get('/rest/v1/users', async (req, res, next) => {
    try {
      if (options.failNextRead) {
        options.failNextRead = false;
        return res.status(403).json({ message: 'fixture storage read denied' });
      }
      const result = await db.query('SELECT *, 7 AS role_id FROM users WHERE email=$1', [
        req.query.email.slice(3),
      ]);
      res.json(result.rows.map((row) => ({ ...row, user_roles: { id: 7, role_name: 'user' } })));
    } catch (e) {
      next(e);
    }
  });
  app.post('/rest/v1/users', async (req, res, next) => {
    try {
      if (options.failNextInsert) {
        options.failNextInsert = false;
        return res.status(503).json({ message: 'fixture storage outage' });
      }
      if (
        req.query.on_conflict !== 'email' ||
        !req.get('Prefer')?.includes('resolution=ignore-duplicates')
      )
        return res.status(400).json({ message: 'Expected insert-only conflict policy' });
      const p = req.body;
      const result = await db.query(
        `INSERT INTO users(name,email,password,contact_number,address,mfa_enabled)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(email) DO NOTHING RETURNING user_id`,
        [p.name, p.email, p.password, p.contact_number, p.address, p.mfa_enabled]
      );
      res.status(201).json(result.rows);
    } catch (e) {
      next(e);
    }
  });
  app.post('/rest/v1/mfatokens', async (req, res, next) => {
    try {
      const p = req.body;
      await db.query('INSERT INTO mfatokens(user_id,token,expiry,is_used) VALUES($1,$2,$3,$4)', [
        p.user_id,
        p.token,
        p.expiry,
        p.is_used,
      ]);
      res.status(201).end();
    } catch (e) {
      next(e);
    }
  });
  app.patch('/rest/v1/mfatokens', async (req, res, next) => {
    try {
      if (req.query.id) {
        if (req.query.is_used !== 'eq.false' || !req.query.expiry?.startsWith('gt.'))
          return res.sendStatus(400);
        const result = await db.query(
          'UPDATE mfatokens SET is_used=true WHERE id=$1 AND NOT is_used AND expiry>$2 RETURNING id',
          [req.query.id.slice(3), req.query.expiry.slice(3)]
        );
        return res.json(result.rows);
      } else
        await db.query('UPDATE mfatokens SET is_used=true WHERE user_id=$1 AND NOT is_used', [
          req.query.user_id.slice(3),
        ]);
      res.status(204).end();
    } catch (e) {
      next(e);
    }
  });
  app.get('/rest/v1/mfatokens', async (req, res, next) => {
    try {
      const r = await db.query(
        'SELECT * FROM mfatokens WHERE user_id=$1 AND token=$2 AND NOT is_used ORDER BY expiry DESC LIMIT 1',
        [req.query.user_id.slice(3), req.query.token.slice(3)]
      );
      res.json(r.rows);
    } catch (e) {
      next(e);
    }
  });
  const server = await new Promise((resolve, reject) => {
    const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
    srv.once('error', reject);
  });
  return {
    db,
    identities,
    options,
    url: 'http://127.0.0.1:' + server.address().port,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      await db.close();
    },
  };
}
module.exports = { startBackend };
