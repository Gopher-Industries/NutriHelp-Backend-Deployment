// dbConnection.js calls process.exit(1) at require time when these are unset,
// and no .env exists in CI or a fresh worktree. Must run before any require
// below that transitively reaches it.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const crypto = require('crypto');

const { expect } = require('chai');

const asSigningKey = require('../services/oauth/asSigningKey');

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIVATE_PEM = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' });
const PUBLIC_PEM = rsa.publicKey.export({ type: 'spki', format: 'pem' });

const otherRsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const OTHER_PUBLIC_PEM = otherRsa.publicKey.export({ type: 'spki', format: 'pem' });

const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const EC_PRIVATE_PEM = ec.privateKey.export({ type: 'pkcs8', format: 'pem' });

const load = (env = {}) => asSigningKey.getSigningKey({ env });

const AS_KID = 'as-key-1';

/** Fully configured env - KEY_ID spelled out so absence stays testable. */
const COMPLETE_ENV = Object.freeze({
  MCP_AS_PRIVATE_KEY_PEM: PRIVATE_PEM,
  MCP_AS_KEY_ID: AS_KID,
});

describe('oauth AS signing key', () => {
  describe('configuration', () => {
    it('is unavailable when no private key is configured', () => {
      const result = load({ MCP_AS_KEY_ID: 'as-key-1' });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_unconfigured');
    });

    it('treats a whitespace-only private key as unconfigured', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: '   ' });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_unconfigured');
    });

    it('reports an unreadable PEM rather than throwing', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----\nnope\n' });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_unreadable');
    });

    it('refuses a non-RSA private key', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: EC_PRIVATE_PEM });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_wrong_type:ec');
    });

    it('refuses a key with no MCP_AS_KEY_ID', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: PRIVATE_PEM });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_id_unconfigured');
    });

    it('treats a whitespace-only key id as absent', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: PRIVATE_PEM, MCP_AS_KEY_ID: '  ' });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_id_unconfigured');
    });

    it('reports the key itself before complaining about its id', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: EC_PRIVATE_PEM });

      expect(result.detail).to.equal('signing_key_wrong_type:ec');
    });
  });

  describe('derivation - one hand-written statement of the key', () => {
    it('derives the public half from the private key', () => {
      const result = load(COMPLETE_ENV);

      expect(result.ok).to.equal(true);
      expect(result.key.publicKeyPem.trim()).to.equal(PUBLIC_PEM.trim());
    });

    it('signs RS256', () => {
      const result = load(COMPLETE_ENV);

      expect(result.key.alg).to.equal('RS256');
    });

    it('carries MCP_AS_KEY_ID as the kid', () => {
      const result = load({ MCP_AS_PRIVATE_KEY_PEM: PRIVATE_PEM, MCP_AS_KEY_ID: 'as-key-1' });

      expect(result.key.kid).to.equal('as-key-1');
    });

    it('accepts a PEM carrying escaped newlines', () => {
      // Render and most hosts deliver multi-line secrets with literal \n.
      const escaped = PRIVATE_PEM.replace(/\n/g, '\\n');
      const result = load({ ...COMPLETE_ENV, MCP_AS_PRIVATE_KEY_PEM: escaped });

      expect(result.ok).to.equal(true);
      expect(result.key.publicKeyPem.trim()).to.equal(PUBLIC_PEM.trim());
    });
  });

  describe('drift against the pre-existing verification variable', () => {
    it('accepts a matching MCP_AS_PUBLIC_KEY_PEM', () => {
      const result = load({
        ...COMPLETE_ENV,
        MCP_AS_PUBLIC_KEY_PEM: PUBLIC_PEM,
      });

      expect(result.ok).to.equal(true);
    });

    it('accepts a matching public key whose text differs from the derived form', () => {
      const pkcs1 = rsa.publicKey.export({ type: 'pkcs1', format: 'pem' });
      const result = load({
        ...COMPLETE_ENV,
        MCP_AS_PUBLIC_KEY_PEM: pkcs1.replace(/\n/g, '\\n'),
      });

      expect(result.ok).to.equal(true);
    });

    it('fails closed when MCP_AS_PUBLIC_KEY_PEM is a different key', () => {
      const result = load({
        ...COMPLETE_ENV,
        MCP_AS_PUBLIC_KEY_PEM: OTHER_PUBLIC_PEM,
      });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_public_mismatch');
    });

    it('fails closed rather than ignoring an unparseable MCP_AS_PUBLIC_KEY_PEM', () => {
      const result = load({
        ...COMPLETE_ENV,
        MCP_AS_PUBLIC_KEY_PEM: 'not-a-pem',
      });

      expect(result.ok).to.equal(false);
      expect(result.detail).to.equal('signing_key_public_mismatch');
    });
  });

  describe('the derived key actually verifies what it signs', () => {
    it('round-trips a signature through the derived public half', () => {
      const jwt = require('jsonwebtoken');
      const { key } = load(COMPLETE_ENV);

      const token = jwt.sign({ marker: 'round-trip' }, key.privateKeyPem, { algorithm: 'RS256' });
      const claims = jwt.verify(token, key.publicKeyPem, { algorithms: ['RS256'] });

      expect(claims.marker).to.equal('round-trip');
    });
  });
});
