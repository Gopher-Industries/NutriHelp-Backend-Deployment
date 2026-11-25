const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const logLoginEvent = require('../Monitor_&_Logging/loginLogger');
const getUserCredentials = require('../model/getUserCredentials');
const addUser = require('../model/addUser');
const { ServiceError } = require('./serviceError');

function emailExists() {
  return new ServiceError(400, 'Email is already registered', { code: 'EMAIL_EXISTS' });
}

function authClient() {
  // A password sign-in must never change the session of a concurrent request.
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

function confirmedUser(data, email) {
  const user = data?.user;
  return data?.session?.access_token &&
    user?.id &&
    user.email_confirmed_at &&
    user.email?.toLowerCase() === email
    ? user
    : null;
}

async function verifyPassword(client, email, password, { signingIn = false } = {}) {
  const { data, error } = await client.auth.signInWithPassword({ email, password });
  if (!error) return confirmedUser(data, email);
  if (signingIn && error.code === 'email_not_confirmed') {
    throw new ServiceError(403, 'Confirm your email before signing in.', {
      code: 'EMAIL_CONFIRMATION_REQUIRED',
    });
  }
  if (['invalid_credentials', 'email_not_confirmed', 'user_banned'].includes(error.code))
    return null;
  throw new ServiceError(503, 'Account verification is temporarily unavailable');
}

async function closeSession(client) {
  // Revoke only the session this request just acquired.
  try {
    await client.auth.signOut({ scope: 'local' });
  } catch {
    console.warn('Could not close temporary signup session');
  }
}

async function createLoginRow(client, user, email, password, profile) {
  const hash = await bcrypt.hash(password, 10);
  const row = await addUser(
    profile.name,
    email,
    hash,
    true,
    profile.contact_number,
    profile.address
  );
  if (!row) return null;
  // Preserve the optional profile update after the login row has been acknowledged.
  try {
    const { error } = await client
      .from('profiles')
      .upsert({ id: user.id, email, ...profile }, { onConflict: 'id', ignoreDuplicates: true });
    if (error) console.warn('Optional signup profile update failed');
  } catch {
    console.warn('Optional signup profile update unavailable');
  }
  return row;
}

async function signup({ name, email, password, contactNumber, address, ip, userAgent }) {
  email = email.trim().toLowerCase();
  async function audit(eventType, userId = null) {
    try {
      await logLoginEvent({
        userId,
        eventType,
        ip: ip === '::1' ? '127.0.0.1' : ip,
        userAgent,
        details: { email },
      });
    } catch {
      console.warn('Could not record signup event');
    }
  }
  const profile = { name, contact_number: contactNumber, address };
  const client = authClient();
  let authenticated = false;
  try {
    if (await getUserCredentials(email)) throw emailExists();
    const { data, error } = await client.auth.signUp({
      email,
      password,
      options: {
        data: profile,
        emailRedirectTo: process.env.APP_ORIGIN ? process.env.APP_ORIGIN + '/login' : undefined,
      },
    });
    if (error && !['user_already_exists', 'email_exists'].includes(error.code)) {
      if (error.code === 'weak_password')
        throw new ServiceError(400, error.message, { code: 'WEAK_PASSWORD' });
      throw new ServiceError(error.status >= 500 ? 503 : 400, 'Unable to register this account');
    }

    // Supabase may deliberately return an obfuscated user for a repeated signup.
    // Only a verified password session authorizes creating the public login row.
    const user = confirmedUser(data, email) || (await verifyPassword(client, email, password));
    if (!user) {
      if (error) throw emailExists();
      throw new ServiceError(
        409,
        'Account setup is incomplete. Check your inbox for a confirmation link, then sign in with your original password.',
        { code: 'SIGNUP_PENDING' }
      );
    }
    authenticated = true;
    if (!(await createLoginRow(client, user, email, password, profile))) throw emailExists();
    await audit('SIGNUP_SUCCESS', user.id);
    return { statusCode: 201, body: { success: true, message: 'Account created successfully' } };
  } catch (error) {
    await audit(error.details?.code === 'EMAIL_EXISTS' ? 'EXISTING_USER' : 'SIGNUP_FAILED');
    throw error;
  } finally {
    if (authenticated) await closeSession(client);
  }
}

// Called only on a confirmed database miss. Existing login rows are never
// updated. A legacy Auth-only user can also resubmit the registration form if
// their previous signup did not save enough profile metadata.
async function recoverForLogin(email, password) {
  const client = authClient();
  const user = await verifyPassword(client, email, password, { signingIn: true });
  if (!user) return null;
  try {
    const { name, contact_number, address } = user.user_metadata || {};
    if (
      typeof name !== 'string' ||
      !/^[A-Za-z\s]{2,100}$/.test(name) ||
      typeof contact_number !== 'string' ||
      !/^\d{10}$/.test(contact_number) ||
      typeof address !== 'string' ||
      address.length < 5 ||
      address.length > 200
    ) {
      throw new ServiceError(
        409,
        'Complete the registration form using your original email and password.',
        { code: 'SIGNUP_PROFILE_REQUIRED' }
      );
    }
    await createLoginRow(client, user, email, password, { name, contact_number, address });
    const row = await getUserCredentials(email);
    if (!row) throw new ServiceError(503, 'Account setup is temporarily unavailable');
    return row;
  } finally {
    await closeSession(client);
  }
}

module.exports = { signup, recoverForLogin };
