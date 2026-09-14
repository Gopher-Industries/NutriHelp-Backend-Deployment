const crypto = require('crypto');

/**
 * In-memory self-signed cert with SAN for TLS probe tests. Avoids committed
 * *.pem/*.key/*.crt (gitignored here — fixtures silently vanished on clone).
 * TEST USE ONLY.
 */

// --- minimal DER ------------------------------------------------------------

const derLength = (length) => {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

const der = (tag, body) => Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);

const sequence = (...parts) => der(0x30, Buffer.concat(parts));
const setOf = (...parts) => der(0x31, Buffer.concat(parts));
const nullValue = () => der(0x05, Buffer.alloc(0));
const boolean = (value) => der(0x01, Buffer.from([value ? 0xff : 0x00]));
const octetString = (body) => der(0x04, body);
const utf8String = (value) => der(0x0c, Buffer.from(value, 'utf8'));
const objectIdentifier = (hex) => der(0x06, Buffer.from(hex, 'hex'));

/** DER INTEGER is signed: a leading high bit needs a 0x00 pad. */
const integer = (value) => {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  let body = Buffer.from(hex, 'hex');
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return der(0x02, body);
};

/** The leading 0x00 is the "unused bits" count, always zero for whole bytes. */
const bitString = (body) => der(0x03, Buffer.concat([Buffer.from([0x00]), body]));

/**
 * UTCTime YYMMDDHHMMSSZ — cannot express year >= 2050 (RFC 5280). Throw instead
 * of silently minting an expired cert.
 */
const utcTime = (date) => {
  if (date.getUTCFullYear() >= 2050) {
    throw new Error(
      `selfSignedCertificate: ${date.getUTCFullYear()} cannot be encoded as UTCTime ` +
        '(RFC 5280 reads YY >= 50 as 19YY). Switch this helper to GeneralizedTime.'
    );
  }
  const pad = (n) => String(n).padStart(2, '0');
  const text =
    `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return der(0x17, Buffer.from(text, 'ascii'));
};

const contextTag = (number, body, constructed = true) =>
  der((constructed ? 0xa0 : 0x80) | number, body);

// --- object identifiers -----------------------------------------------------

const OID_SHA256_WITH_RSA = '2a864886f70d01010b'; // 1.2.840.113549.1.1.11
const OID_COMMON_NAME = '550403'; // 2.5.4.3
const OID_SUBJECT_ALT_NAME = '551d11'; // 2.5.29.17
const OID_BASIC_CONSTRAINTS = '551d13'; // 2.5.29.19

const distinguishedName = (commonName) =>
  sequence(setOf(sequence(objectIdentifier(OID_COMMON_NAME), utf8String(commonName))));

const toPem = (label, body) =>
  `-----BEGIN ${label}-----\n${body
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;

/**
 * @param {string} hostname the dNSName to put in subjectAltName
 * @returns {{certPem: string, keyPem: string, hostname: string}}
 */
const createSelfSignedCertificate = (hostname) => {
  // Buffer.from(x, 'ascii') MASKS the high bit rather than throwing, so a
  if (typeof hostname !== 'string' || !/^[\x21-\x7e]+$/.test(hostname)) {
    throw new Error(
      `selfSignedCertificate: hostname must be printable ASCII with no spaces, got ${JSON.stringify(hostname)}. ` +
        'An internationalised name must be punycoded by the caller.'
    );
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

  // Node hands us a ready-made SubjectPublicKeyInfo, which is the one
  const subjectPublicKeyInfo = publicKey.export({ type: 'spki', format: 'der' });

  const now = Date.now();
  const notBefore = new Date(now - 60_000); // tolerate a little clock skew
  // Two years, not ten: the certificate is minted fresh on every run, so a long
  const notAfter = new Date(now + 2 * 365 * 24 * 60 * 60 * 1000);

  const subjectAltName = sequence(
    objectIdentifier(OID_SUBJECT_ALT_NAME),
    // [2] is dNSName, primitive.
    octetString(sequence(contextTag(2, Buffer.from(hostname, 'ascii'), false)))
  );

  // CA:TRUE so the same certificate can be handed to a client as a trust
  const basicConstraints = sequence(
    objectIdentifier(OID_BASIC_CONSTRAINTS),
    boolean(true), // critical
    octetString(sequence(boolean(true)))
  );

  const tbsCertificate = sequence(
    contextTag(0, integer(2)), // v3
    integer(now), // serial â€” unique per run, never reused
    sequence(objectIdentifier(OID_SHA256_WITH_RSA), nullValue()),
    distinguishedName(hostname), // issuer === subject: self-signed
    sequence(utcTime(notBefore), utcTime(notAfter)),
    distinguishedName(hostname),
    subjectPublicKeyInfo,
    contextTag(3, sequence(subjectAltName, basicConstraints))
  );

  const signature = crypto.sign('sha256', tbsCertificate, privateKey);

  const certificate = sequence(
    tbsCertificate,
    sequence(objectIdentifier(OID_SHA256_WITH_RSA), nullValue()),
    bitString(signature)
  );

  return {
    hostname,
    certPem: toPem('CERTIFICATE', certificate),
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
};

module.exports = { createSelfSignedCertificate };
