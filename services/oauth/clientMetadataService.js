const supabase = require('../../dbConnection');
const safeMetadataFetchModule = require('./safeMetadataFetch');
const redirectUriMatcher = require('./redirectUriMatcher');
const introspectionLog = require('./introspectionLog');

/**
 * CIMD retrieval (ticket 41).
 *
 * Only `assistant_public` is dereferenced (Q16: service_confidential stays
 * opaque). Unregistered IDs are fetched (first-sight); lookup errors fail
 * closed. Returns validated metadata and writes nothing — ticket 36 owns upsert.
 *
 * Shape maps to mig 002 only: client_id, display_name, redirect_uris.
 */

const MAX_CLIENT_NAME_LENGTH = 256;
const MAX_REDIRECT_URIS = 32;
const MAX_URI_LENGTH = 2048;

const DEREFERENCE_REFUSED_EVENT = 'mcp_client_metadata_dereference_refused';
const CLIENT_METADATA_ENDPOINT = 'client_id_metadata_document_fetch';
const CLIENT_METADATA_ERROR_PREFIX = 'oauth_client_metadata';

const fail = (reason) => ({ ok: false, reason });

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/** https, or http on loopback (RFC 8252 §7.3). No fragment (RFC 6749 §3.1.2). */
const isAcceptableRedirectUri = (value) => {
  if (!isNonEmptyString(value) || value.length > MAX_URI_LENGTH) return false;

  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return false;
  }

  if (url.hash !== '') return false;
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return redirectUriMatcher.isLoopbackHost(url.hostname);
  return false;
};

/**
 * @returns {{ok: true, metadata} | {ok: false, reason}}
 */
const validateDocument = (clientId, rawBody) => {
  let document;
  try {
    document = JSON.parse(rawBody);
  } catch (err) {
    return fail('document_not_json');
  }

  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    return fail('document_not_an_object');
  }

  if (!isNonEmptyString(document.client_id)) return fail('document_client_id_absent');
  if (document.client_id !== clientId) return fail('document_client_id_mismatch');

  if (!isNonEmptyString(document.client_name)) return fail('document_client_name_absent');
  if (document.client_name.length > MAX_CLIENT_NAME_LENGTH) {
    return fail('document_client_name_too_long');
  }

  const redirectUris = document.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return fail('document_redirect_uris_absent');
  }
  if (redirectUris.length > MAX_REDIRECT_URIS) return fail('document_too_many_redirect_uris');
  if (!redirectUris.every(isAcceptableRedirectUri)) return fail('document_redirect_uri_invalid');

  const authMethod = document.token_endpoint_auth_method;
  if (authMethod !== undefined && authMethod !== 'none') {
    return fail('document_auth_method_not_none');
  }

  // client_uri / logo_uri deliberately omitted — no mig 002 columns, and a
  // bare string check would pass javascript: onto a consent screen. Ticket 36
  // can add them with a column + https predicate later.
  return {
    ok: true,
    metadata: {
      client_id: document.client_id,
      display_name: document.client_name.trim(),
      redirect_uris: redirectUris.slice(),
    },
  };
};

/**
 * @param {string} clientId the assistant's CIMD HTTPS URL
 * @returns {Promise<{ok: true, metadata} | {ok: false, reason}>}
 */
const fetchAndValidateClientMetadata = async (clientId, deps = {}) => {
  const db = deps.supabase || supabase;
  const fetcher = deps.safeMetadataFetch || safeMetadataFetchModule;
  const log = deps.introspectionLog || introspectionLog;

  if (!isNonEmptyString(clientId)) return fail('client_id_absent');

  // Same shape rules as the fetcher, before any DB work.
  const shape = safeMetadataFetchModule.parseClientIdUrl(clientId);
  if (!shape) return fail('client_id_unparseable');
  if (shape.rejected) return fail(`client_id_${shape.rejected.replace(/^url_/, '')}`);

  let row;
  try {
    const { data, error } = await db
      .from('oauth_clients')
      .select('client_id, client_type, is_active')
      .eq('client_id', clientId)
      .maybeSingle();

    if (error) return fail('client_lookup_failed');
    row = data;
  } catch (err) {
    return fail('client_lookup_failed');
  }

  if (row) {
    if (row.client_type !== 'assistant_public') {
      try {
        await log.logGrantRefusal(
          {
            correlationId: deps.correlationId || null,
            requestId: deps.requestId || null,
            detail: `client_type:${row.client_type}`,
            clientId,
            userId: null,
            eventType: DEREFERENCE_REFUSED_EVENT,
            resource: CLIENT_METADATA_ENDPOINT,
          },
          deps
        );
      } catch (err) {
        // Logging never changes the answer.
      }
      return fail('client_type_not_dereferenceable');
    }

    if (row.is_active !== true) return fail('client_inactive');
  }

  // Allowlist only — never forward addressGuard/lookup/transport/ca.
  const fetched = await fetcher.fetchDocument(clientId, {
    timeoutMs: deps.timeoutMs,
    maxBytes: deps.maxBytes,
  });
  if (!fetched.ok) {
    try {
      await log.logOperational(
        {
          correlationId: deps.correlationId || null,
          requestId: deps.requestId || null,
          outcome: 'metadata_fetch_refused',
          detail: fetched.reason,
          httpStatus: 400,
          clientId,
          endpoint: CLIENT_METADATA_ENDPOINT,
          errorPrefix: CLIENT_METADATA_ERROR_PREFIX,
        },
        deps
      );
    } catch (err) {
      // Logging never changes the answer.
    }
    return fail(fetched.reason);
  }

  return validateDocument(clientId, fetched.body);
};

module.exports = {
  fetchAndValidateClientMetadata,
  validateDocument,
  isAcceptableRedirectUri,
  DEREFERENCE_REFUSED_EVENT,
  CLIENT_METADATA_ENDPOINT,
  CLIENT_METADATA_ERROR_PREFIX,
  MAX_CLIENT_NAME_LENGTH,
  MAX_REDIRECT_URIS,
};
