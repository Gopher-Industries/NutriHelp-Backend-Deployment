// Closed v1 envelope: user arguments and arbitrary messages have no storage field.
const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const textMatching = re => value => typeof value === 'string' && re.test(value);
const oneOf = (...values) => value => values.includes(value);
const scopes = new Map([['nutrition_lookup','nutrition:read'], ['record_meal','meallog:write'], ['get_meal_plan','mealplan:read']]);
function clientIdentifier(value) {
  if (typeof value !== 'string' || value.length > 512) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}
const common = {
  schema_version: oneOf(1), event_id: textMatching(uuid), correlation_id: textMatching(uuid),
  grant_id: textMatching(uuid), phase: oneOf('started', 'completion'),
  timestamp: value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) && Number.isFinite(Date.parse(value)),
  user_id: textMatching(/^[1-9]\d{0,18}$/), client_id: clientIdentifier,
  tool: value => scopes.has(value), scope: oneOf(...scopes.values()),
  argument_hash: textMatching(/^[0-9a-f]{64}$/), introspection: oneOf('active'),
  confirmation: oneOf('not_required','required','confirmed'),
};
const completion = {
  ...common, outcome: oneOf('success','failure'), exchange: oneOf('not_required','succeeded','failed','not_attempted'),
  upstream_status_class: oneOf(null,'2xx','3xx','4xx','5xx'),
  latency_ms: value => Number.isSafeInteger(value) && value >= 0,
};
function validEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  const fields = event.phase === 'completion' ? completion : common;
  return Object.keys(event).length === Object.keys(fields).length &&
    Object.entries(fields).every(([key, accepts]) => Object.hasOwn(event, key) && accepts(event[key])) &&
    event.scope === scopes.get(event.tool);
}
function validBatch(batch) {
  return !!batch && Object.keys(batch).length === 1 && Array.isArray(batch.events) &&
    batch.events.length > 0 && batch.events.length <= 32 && batch.events.every(validEvent);
}
module.exports = { validBatch };
