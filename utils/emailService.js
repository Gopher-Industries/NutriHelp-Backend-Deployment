const { google } = require('googleapis');

// Startup env check — logs on server boot so you see missing vars immediately
const REQUIRED_ENV = ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN', 'GMAIL_USER'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.warn('[emailService] ⚠️  Missing env vars — email will NOT send:', missingEnv.join(', '));
} else {
  console.log('[emailService] ✅ All Gmail env vars present');
}

const oauth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);

oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_REFRESH_TOKEN,
});

// Log whenever the token is auto-refreshed
oauth2Client.on('tokens', (tokens) => {
  console.log('[emailService] OAuth2 token refreshed | expiry:', tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : 'unknown');
});

const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

function buildRawEmail({ from, to, subject, html }) {
  const boundary = `boundary_${Date.now()}`;
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    `Content-Type: text/html; charset=utf-8`,
    '',
    html,
    '',
    `--${boundary}--`,
  ];
  return Buffer.from(lines.join('\n'))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function sendEmail({ to, subject, html }) {
  const missing = REQUIRED_ENV.filter(k => !process.env[k]);
  if (missing.length > 0) {
    console.log(`[emailService] 📨 [DEV] Skipping real send — missing env: ${missing.join(', ')} | to: ${to}`);
    return;
  }

  console.log(`[emailService] Sending email | to: ${to} | subject: ${subject}`);
  console.log(`[emailService] Using Gmail account: ${process.env.GMAIL_USER}`);
  console.log(`[emailService] Client ID present: ${!!process.env.GMAIL_CLIENT_ID} | Secret present: ${!!process.env.GMAIL_CLIENT_SECRET} | Refresh token present: ${!!process.env.GMAIL_REFRESH_TOKEN}`);

  try {
    const raw = buildRawEmail({
      from: `NutriHelp Security <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
    });

    console.log('[emailService] Raw email built, calling Gmail API...');

    const result = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw },
    });

    console.log(`[emailService] ✅ Email sent | to: ${to} | messageId: ${result.data.id} | threadId: ${result.data.threadId}`);
    return result.data;
  } catch (err) {
    console.error(`[emailService] ❌ Email FAILED | to: ${to}`);
    console.error(`[emailService]    code:    ${err.code}`);
    console.error(`[emailService]    status:  ${err.status}`);
    console.error(`[emailService]    message: ${err.message}`);
    if (err.errors) {
      console.error(`[emailService]    errors:  ${JSON.stringify(err.errors)}`);
    }
    throw err;
  }
}

async function sendMfaEmail(to, token) {
  console.log('[emailService] Sending MFA email...');
  await sendEmail({
    to,
    subject: 'NutriHelp Login Token',
    html: `<p>Your one-time login token is:</p><h2 style="letter-spacing:4px">${token}</h2><p>This token expires in <strong>10 minutes</strong>.</p><p>If you did not request this, please ignore this email.</p><br/><p>- NutriHelp Security Team</p>`,
  });
  console.log('[emailService] MFA email sent successfully');
}

async function sendPasswordResetEmail(to, code) {
  console.log('[emailService] Sending password reset email...');
  await sendEmail({
    to,
    subject: 'NutriHelp Password Reset Code',
    html: `<p>Your password reset code is:</p><h2 style="letter-spacing:4px">${code}</h2><p>This code expires in <strong>10 minutes</strong>.</p><p>If you did not request this, please ignore this email.</p><br/><p>- NutriHelp Security Team</p>`,
  });
  console.log('[emailService] Password reset email sent successfully');
}

async function sendFailedLoginAlertEmail(to, ip) {
  try {
    await sendEmail({
      to,
      subject: 'Failed Login Attempt on NutriHelp',
      html: `<p>Someone tried to log in to NutriHelp using your email from IP: <strong>${ip}</strong>.</p><p>If this wasn't you, consider resetting your password.</p><br/><p>- NutriHelp Security Team</p>`,
    });
  } catch (err) {
    console.error('[emailService] Failed login alert email error:', err.message);
  }
}

async function sendContactUsConfirmationEmail(to, { name, subject, message }) {
  await sendEmail({
    to,
    subject: "We received your message - NutriHelp",
    html: `
      <p>Hi ${name},</p>
      <p>Thank you for reaching out to NutriHelp!</p>
      <p>We've received your message and our team will get back to you shortly.</p>
      <p>Here's a copy of what you sent:</p>
      <p><strong>Subject:</strong> ${subject}<br/>
      <strong>Message:</strong> ${message}</p>
      <br/>
      <p>Warm regards,<br/>The NutriHelp Team<br/>nutrihelp2026@gmail.com</p>
    `,
  });
}

module.exports = { sendMfaEmail, sendPasswordResetEmail, sendFailedLoginAlertEmail, sendContactUsConfirmationEmail };
