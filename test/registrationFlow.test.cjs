const { before, after, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const proxyquire = require('proxyquire').noCallThru();
const { startBackend } = require('./support/registrationBackend.cjs');

describe('web registration, password login and email MFA (local only)', () => {
  let backend, api;
  const mailbox = [];
  const events = [];
  const form = {
    name: 'Example User',
    password: 'Example123!',
    contact_number: '0412345678',
    address: '123 Example Street',
  };
  const signup = (email, password = form.password) =>
    api.post('/api/signup').send({ ...form, email, password });
  const login = (email, password = form.password) =>
    api.post('/api/login').send({ email, password });
  const mfa = (email, code) =>
    api.post('/api/login/mfa').send({ email, password: form.password, mfa_token: code });
  before(async () => {
    backend = await startBackend();
    Object.assign(process.env, {
      NODE_ENV: 'test',
      SUPABASE_URL: backend.url,
      SUPABASE_ANON_KEY: 'fixture-anon',
      SUPABASE_SERVICE_ROLE_KEY: 'fixture-service',
      JWT_TOKEN: 'local-session-signing-fixture',
      ENCRYPTION_KEY_SOURCE: 'env',
      ENCRYPTION_KEY_ENV_NAME: 'ENCRYPTION_KEY',
      ENCRYPTION_KEY: randomBytes(32).toString('hex'),
      GMAIL_USER: 'fixture@example.invalid',
      GMAIL_CLIENT_ID: 'test',
      GMAIL_CLIENT_SECRET: 'test',
      GMAIL_REFRESH_TOKEN: 'test',
    });
    const logLoginEvent = async (event) => {
      events.push(event.eventType);
    };
    const signupService = proxyquire('../services/signupService', {
      '../Monitor_&_Logging/loginLogger': logLoginEvent,
    });
    const signupController = proxyquire('../controller/signupController', {
      '../services/signupService': signupService,
    });
    const emailService = proxyquire('../utils/emailService', {
      googleapis: {
        google: {
          auth: {
            OAuth2: class {
              setCredentials() {}
              on() {}
            },
          },
          gmail: () => ({
            users: {
              messages: {
                send: async ({ requestBody }) => {
                  mailbox.push(Buffer.from(requestBody.raw, 'base64url').toString());
                  return { data: { id: String(mailbox.length) } };
                },
              },
            },
          }),
        },
      },
    });
    const loginController = proxyquire('../controller/loginController', {
      '../services/signupService': signupService,
      '../utils/emailService': emailService,
      '../Monitor_&_Logging/loginLogger': logLoginEvent,
      '../services/securityEventService': { logSecurityEvent: async () => {} },
      '../services/securityLogger': { createLog: () => ({}), log: () => {} },
      '../services/sessionLogService': { sessionHookOnLoginSuccess: async () => {} },
      '../utils/logger': { error: () => {}, warn: () => {} },
    });
    const app = express().use(express.json());
    app.use(
      '/api/signup',
      proxyquire('../routes/signup', { '../controller/signupController.js': signupController })
    );
    app.use(
      '/api/login',
      proxyquire('../routes/login', { '../controller/loginController.js': loginController })
    );
    api = request(app);
  });
  after(async () => {
    if (backend) await backend.close();
  });
  async function completeLogin(email) {
    const challenge = await login(email).expect(202);
    assert.equal(challenge.body.data.session, undefined);
    const message = mailbox.at(-1);
    assert.ok(message.includes('To: ' + email));
    const code = message.match(/<h2[^>]*>(\d{6})<\/h2>/)?.[1];
    assert.ok(code, 'MFA email contains the generated code');
    if (email === 'normal@example.invalid')
      await mfa(email, code === '111111' ? '222222' : '111111').expect(401);
    const result = await mfa(email, code).expect(200);
    assert.equal(result.body.data.user.email, email);
    assert.equal(result.body.data.user.password, undefined);
    assert.equal(
      jwt.verify(result.body.data.session.accessToken, process.env.JWT_TOKEN).userId,
      result.body.data.user.user_id
    );
    return code;
  }
  it('creates a usable login row, issues an MFA email and returns a signed session only after verification', async () => {
    const email = 'normal@example.invalid';
    await signup(email).expect(201);
    const {
      rows: [row],
    } = await backend.db.query('SELECT * FROM users WHERE email=$1', [email]);
    assert.ok(await bcrypt.compare(form.password, row.password));
    assert.equal(row.mfa_enabled, true);
    assert.ok(!row.contact_number.includes(form.contact_number));
    const code = await completeLogin(email);
    await mfa(email, code).expect(401);
    await signup(email, 'Different123!').expect(400);
  });
  it('does not report success on write failure; the original owner can recover and complete MFA', async () => {
    const email = 'orphan@example.invalid';
    const count = events.filter((e) => e === 'SIGNUP_SUCCESS').length;
    backend.options.failNextInsert = true;
    await signup(email).expect(500);
    assert.equal(events.filter((e) => e === 'SIGNUP_SUCCESS').length, count);
    assert.ok(backend.identities.has(email));
    await login(email, 'Different123!').expect(404);
    assert.equal(
      (await backend.db.query('SELECT * FROM users WHERE email=$1', [email])).rows.length,
      0
    );
    await completeLogin(email);
  });
  it('waits for email confirmation when signup returns no session', async () => {
    const email = 'pending@example.invalid';
    backend.options.confirmFirst = true;
    try {
      assert.equal((await signup(email).expect(409)).body.code, 'SIGNUP_PENDING');
    } finally {
      backend.options.confirmFirst = false;
    }
    assert.equal((await login(email).expect(403)).body.code, 'EMAIL_CONFIRMATION_REQUIRED');
    backend.identities.get(email).user.email_confirmed_at = new Date().toISOString();
    await completeLogin(email);
  });
  it('recovers an older Auth identity without profile metadata via explicit registration and original password', async () => {
    const email = 'legacy@example.invalid';
    backend.identities.set(email, {
      password: form.password,
      user: {
        id: '9f754dd0-68c8-4c71-991d-acbc019e099b',
        email,
        email_confirmed_at: new Date().toISOString(),
        user_metadata: {},
      },
    });
    assert.equal((await login(email).expect(409)).body.code, 'SIGNUP_PROFILE_REQUIRED');
    await signup(email, 'Different123!').expect(409);
    assert.equal(
      (await backend.db.query('SELECT * FROM users WHERE email=$1', [email])).rows.length,
      0
    );
    await signup(email).expect(201);
    await completeLogin(email);
  });
  it('creates at most one login row when registration is retried concurrently', async () => {
    const email = 'parallel@example.invalid';
    const result = await Promise.all([signup(email), signup(email)]);
    assert.deepEqual(result.map((r) => r.status).sort(), [201, 400]);
    assert.equal(
      (await backend.db.query('SELECT * FROM users WHERE email=$1', [email])).rows.length,
      1
    );
  });
  it('surfaces database read errors and refuses to claim an unsent MFA email', async () => {
    backend.options.failNextRead = true;
    await login('normal@example.invalid').expect(500);
    const count = mailbox.length;
    delete process.env.GMAIL_REFRESH_TOKEN;
    try {
      await login('normal@example.invalid').expect(500);
    } finally {
      process.env.GMAIL_REFRESH_TOKEN = 'test';
    }
    assert.equal(mailbox.length, count);
  });
});
