// dbConnection.js calls process.exit(1) at require time when these are unset.
// Same guard as test/oauthIntrospect.composition.test.js; must precede requires.
process.env.SUPABASE_URL = process.env.SUPABASE_URL || 'https://example.supabase.co';
process.env.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'service-role-key';

const fs = require('fs');
const path = require('path');

const { expect } = require('chai');
const express = require('express');
const request = require('supertest');
const { rateLimit, ipKeyGenerator, MemoryStore } = require('express-rate-limit');

const oauthRateLimiters = require('../middleware/oauthRateLimiters');
const mealLogRouter = require('../routes/meallog');

const { createMealLogRouter } = mealLogRouter;

/**
 * Ticket 45 D1 — the MCP data bucket and the data paths' body parsing,
 * assembled in server.js's order.
 *
 * Mutation-proven, one at a time: the global skip (server.js and module), the
 * mount (removed, moved below the limiter), MCP_DATA_PATHS (entry dropped), the
 * predicate (not lowercased, exact-only, raw prefix, // collapsed), a shared
 * limiter instance, each parser-skip clause, the route parser (removed, before
 * auth), the error gate, and the routes/index.js mounts. Each turns at least one
 * case red. Limitation: the server.js mutations are caught ONLY by the source
 * checks, because every behaviour case builds its own app.
 */

// Written out, not derived from the constant: a case that iterates the
// constant cannot notice an entry going missing from it.
const EXPECTED_DATA_PATHS = ['/api/meallog/me', '/api/security-events/mcp'];

const FLOOD_LIMIT = 3;
const HUGE = 100000;

/**
 * server.js order: service bucket, data bucket, global limiter (with the real
 * skip), 50mb json, routes. /api/other stands in for every non-MCP route.
 * Only meallog is mounted; /api/security-events/mcp 404s until ticket 34.
 */
const makeServerOrderApp = ({
  dataLimiter = oauthRateLimiters.createMcpDataLimiter({ limit: HUGE }),
  serviceLimiter = oauthRateLimiters.createMcpServiceLimiter({ limit: HUGE }),
  globalLimit = HUGE,
} = {}) => {
  const app = express();
  app.set('trust proxy', 1);
  app.use(oauthRateLimiters.MCP_SERVICE_PATHS, serviceLimiter);
  app.use(oauthRateLimiters.MCP_DATA_PATHS, dataLimiter);
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: globalLimit,
      standardHeaders: true,
      legacyHeaders: false,
      store: new MemoryStore(),
      keyGenerator: (req) => ipKeyGenerator(req.ip),
      skip: oauthRateLimiters.skipGlobalLimiter,
    })
  );
  app.use(express.json({ limit: '50mb' }));
  app.get('/api/other', (req, res) => res.json({ ok: true }));
  app.use('/api/meallog', mealLogRouter);
  return app;
};

let ipCounter = 0;
/** A fresh address per case: MemoryStore state outlives an app instance. */
const freshIp = () => {
  ipCounter += 1;
  return `198.51.${100 + Math.floor(ipCounter / 250)}.${(ipCounter % 250) + 1}`;
};

const post = (app, url, ip) => request(app).post(url).set('X-Forwarded-For', ip).send({});
const getOther = (app, ip) => request(app).get('/api/other').set('X-Forwarded-For', ip);

/** Spellings express serves identically; see oauthRateLimiters.isMcpDataPath. */
const spellingsOf = (p) => [
  ['lowercase', p],
  ['UPPERCASE', p.toUpperCase()],
  ['trailing slash', `${p}/`],
  ['UPPERCASE trailing slash', `${p.toUpperCase()}/`],
];

describe('ticket 45 D1 — MCP data bucket', () => {
  describe('the constant', () => {
    it('lists exactly the approved MCP-only data paths', () => {
      expect(oauthRateLimiters.MCP_DATA_PATHS).to.deep.equal(EXPECTED_DATA_PATHS);
    });

    it('does not list a route the web app also calls, or one that does not exist yet', () => {
      // fooddata/search is shared with the web app, so a path carve-out would
      // raise every caller's ceiling; mealplan/me arrives with ticket 32.
      expect(oauthRateLimiters.MCP_DATA_PATHS).to.not.include('/api/fooddata/search');
      expect(oauthRateLimiters.MCP_DATA_PATHS).to.not.include('/api/mealplan/me');
      expect(oauthRateLimiters.MCP_DATA_PATHS).to.not.include('/api/mealplan');
    });

    it('is lowercase and disjoint from the service paths', () => {
      // Lowercase is what makes normalisePath's comparison well defined.
      oauthRateLimiters.MCP_DATA_PATHS.forEach((p) => expect(p).to.equal(p.toLowerCase()));
      oauthRateLimiters.MCP_DATA_PATHS.forEach((p) =>
        expect(oauthRateLimiters.MCP_SERVICE_PATHS).to.not.include(p)
      );
    });
  });

  EXPECTED_DATA_PATHS.forEach((dataPath) => {
    spellingsOf(dataPath).forEach(([label, spelling]) => {
      it(`${label} ${spelling}: limited by the data bucket AND skipped by the global one`, async () => {
        // globalLimit === FLOOD_LIMIT: only FLOOD_LIMIT requests pass the data
        // bucket, so they could spend the global budget exactly. Arm 1 fails if
        // the mount misses this spelling; arm 2 if the skip does.
        const app = makeServerOrderApp({
          dataLimiter: oauthRateLimiters.createMcpDataLimiter({ limit: FLOOD_LIMIT }),
          globalLimit: FLOOD_LIMIT,
        });
        const ip = freshIp();

        for (let i = 0; i < FLOOD_LIMIT; i += 1) {
          const allowed = await post(app, spelling, ip);
          expect(allowed.status, `request ${i + 1} should not be limited`).to.not.equal(429);
          // Not vacuous: the spelling really reaches the route (the 503 stub
          // until ticket 31). Ingest has no route yet, so it 404s.
          if (dataPath === '/api/meallog/me') {
            expect(allowed.status, 'the meallog route must serve this spelling').to.equal(503);
          }
        }

        // ARM 1 — the data bucket answers.
        const limited = await post(app, spelling, ip);
        expect(limited.status, `${spelling} must be inside the data bucket`).to.equal(429);

        // ARM 2 — and the global bucket was not spent on it.
        const other = await getOther(app, ip);
        expect(other.status, 'the global budget must not have been spent').to.equal(200);
      });
    });
  });

  describe('non-MCP routes stay on the global limiter', () => {
    const globalCases = [
      ['an unrelated route', (app, ip) => getOther(app, ip)],
      ['a sibling in the meallog router', (app, ip) => post(app, '/api/meallog/other', ip)],
      ['a prefix without a segment boundary', (app, ip) => post(app, '/api/meallog/meX', ip)],
      ['an ingest look-alike', (app, ip) => post(app, '/api/security-events/mcpx', ip)],
      // Served by the route (503 stub) but matched by neither mount nor skip:
      // one bucket, the stricter one. Pinned so a skip cannot drift past the mount.
      ['a double-slash spelling the route still serves', (app, ip) => post(app, '/api/meallog//me', ip)],
    ];

    globalCases.forEach(([label, send]) => {
      it(`${label} is refused by the global bucket`, async () => {
        const app = makeServerOrderApp({
          // A data bucket that would never refuse: any 429 below is global.
          globalLimit: FLOOD_LIMIT,
        });
        const ip = freshIp();

        for (let i = 0; i < FLOOD_LIMIT; i += 1) {
          const res = await send(app, ip);
          expect(res.status, `request ${i + 1} should not be limited`).to.not.equal(429);
        }
        const res = await send(app, ip);

        expect(res.status).to.equal(429);
      });
    });
  });

  describe('independent of the introspect/token bucket', () => {
    it('exhausting the data bucket leaves the service bucket untouched', async () => {
      const app = makeServerOrderApp({
        dataLimiter: oauthRateLimiters.createMcpDataLimiter({ limit: FLOOD_LIMIT }),
        serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      });
      const ip = freshIp();

      for (let i = 0; i < FLOOD_LIMIT; i += 1) await post(app, '/api/meallog/me', ip);
      expect((await post(app, '/api/meallog/me', ip)).status).to.equal(429);

      // Router unmounted, so 404 means "passed the service bucket".
      for (let i = 0; i < FLOOD_LIMIT; i += 1) {
        const res = await post(app, '/api/oauth/introspect', ip);
        expect(res.status, `service request ${i + 1}`).to.equal(404);
      }
    });

    it('exhausting the service bucket leaves the data bucket untouched', async () => {
      const app = makeServerOrderApp({
        dataLimiter: oauthRateLimiters.createMcpDataLimiter({ limit: FLOOD_LIMIT }),
        serviceLimiter: oauthRateLimiters.createMcpServiceLimiter({ limit: FLOOD_LIMIT }),
      });
      const ip = freshIp();

      for (let i = 0; i < FLOOD_LIMIT; i += 1) await post(app, '/api/oauth/token', ip);
      expect((await post(app, '/api/oauth/token', ip)).status).to.equal(429);

      for (let i = 0; i < FLOOD_LIMIT; i += 1) {
        const res = await post(app, '/api/meallog/me', ip);
        expect(res.status, `data request ${i + 1}`).to.equal(503);
      }
    });

    it('the REAL instances server.js mounts keep separate counts', async () => {
      // The cases above use factory twins (separate stores by construction). This
      // pins the singletons: one hit each must leave both at MAX - 1, not MAX - 2.
      const app = makeServerOrderApp({
        dataLimiter: oauthRateLimiters.mcpDataAddressLimiter,
        serviceLimiter: oauthRateLimiters.mcpServiceAddressLimiter,
      });
      const ip = freshIp();

      const data = await post(app, '/api/meallog/me', ip);
      const service = await post(app, '/api/oauth/introspect', ip);

      expect(oauthRateLimiters.mcpDataAddressLimiter).to.not.equal(
        oauthRateLimiters.mcpServiceAddressLimiter
      );
      expect(data.headers['ratelimit-limit']).to.equal(String(oauthRateLimiters.MCP_DATA_MAX));
      expect(data.headers['ratelimit-remaining']).to.equal(String(oauthRateLimiters.MCP_DATA_MAX - 1));
      expect(service.headers['ratelimit-limit']).to.equal(String(oauthRateLimiters.MCP_SERVICE_MAX));
      expect(service.headers['ratelimit-remaining']).to.equal(
        String(oauthRateLimiters.MCP_SERVICE_MAX - 1)
      );
    });
  });

  describe('the skip never fires where no mount does', () => {
    it('every spelling the global skip passes is caught by an app-level MCP mount', async () => {
      // The coupling rule, checked against express's own mount matching: a skip
      // clause with no matching mount leaves its paths unlimited.
      const app = express();
      app.use(oauthRateLimiters.MCP_SERVICE_PATHS, (req, res, next) => {
        req.bucket = 'service';
        next();
      });
      app.use(oauthRateLimiters.MCP_DATA_PATHS, (req, res, next) => {
        req.bucket = req.bucket || 'data';
        next();
      });
      app.use((req, res) =>
        res.json({ skipped: oauthRateLimiters.skipGlobalLimiter(req), bucket: req.bucket || null })
      );

      const all = [...oauthRateLimiters.MCP_SERVICE_PATHS, ...oauthRateLimiters.MCP_DATA_PATHS];
      const corpus = all.flatMap((p) => [
        p,
        p.toUpperCase(),
        `${p}/`,
        `${p}/nested`,
        `${p}x`,
        `${p}//`,
        p.replace(/\/([^/]+)$/, '//$1'),
        p.replace(/\/([a-z])/g, (m, c) => `/${c.toUpperCase()}`),
      ]);
      corpus.push('/api/other', '/api/meallog', '/api/oauth/authorize', '/');

      let skippedCount = 0;
      for (const url of corpus) {
        const { body } = await request(app).get(url);
        if (body.skipped) {
          skippedCount += 1;
          expect(body.bucket, `${url} is skipped by the global limiter but no bucket mounts it`).to.not.equal(
            null
          );
        }
        // And the data bucket never double-limits: bucketed there => skipped.
        if (body.bucket === 'data') {
          expect(body.skipped, `${url} is in the data bucket but still spends the global one`).to.equal(true);
        }
      }
      // Non-vacuity: the corpus must actually exercise the skip.
      expect(skippedCount).to.be.greaterThan(all.length);
    });
  });

  describe('server.js itself', () => {
    // The cases above prove the SHAPE, not that server.js uses it. Source order,
    // comments stripped, as in oauthIntrospect.composition.test.js.
    const code = fs
      .readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');

    it('mounts the data bucket once, above the global limiter, the parsers and the routes', () => {
      const anchor = 'app.use(oauthRateLimiters.MCP_DATA_PATHS, oauthRateLimiters.mcpDataAddressLimiter)';
      const mount = code.indexOf(anchor);
      const globalLimiter = code.indexOf('app.use(limiter)');
      const jsonParser = code.indexOf("express.json({ limit: '50mb' })");
      const routesMounted = code.indexOf('routesRegistrar(app)');

      expect(mount, 'server.js must mount the MCP data bucket at app level').to.be.greaterThan(-1);
      expect(code.lastIndexOf(anchor), 'mounted exactly once').to.equal(mount);
      expect(globalLimiter).to.be.greaterThan(-1);
      expect(jsonParser).to.be.greaterThan(-1);
      expect(routesMounted).to.be.greaterThan(-1);

      expect(mount).to.be.lessThan(globalLimiter);
      expect(mount).to.be.lessThan(jsonParser);
      expect(mount).to.be.lessThan(routesMounted);
    });

    it('gives the global limiter the combined skip, not the service-only one', () => {
      expect(code).to.contain('skip: oauthRateLimiters.skipGlobalLimiter');
      expect(code).to.not.contain('skip: oauthRateLimiters.isMcpServicePath');
    });
  });
});

/**
 * The data paths skip the global 50mb parsers; /api/meallog/me parses its own
 * body at 16kb, after authentication.
 *
 * Oversize is 413 here but 400 on /api/oauth: this route's contract is JSON, so
 * its JSON parser reads the body and refuses it for size. On /api/oauth a JSON
 * body matches no parser, is never read, and 400s.
 */
describe('ticket 45 D1 — MCP data paths skip the global 50mb parsers', () => {
  const FLOOD = 3;
  const MEAL = { date: '2026-09-11', meal_type: 'breakfast', food_name: 'Porridge', time: '08:00' };
  const KEY = 'a'.repeat(64);
  // Valid JSON for one meal, padded with insignificant whitespace to ~40KB:
  // over the route's 16kb, under the global 50mb, and a VALID meal once read.
  // That makes the twin's 201 positive evidence the body was read and used.
  const PADDED_MEAL = `${JSON.stringify(MEAL)}${' '.repeat(40000)}`;

  /**
   * server.js order with probes. skipParsers:false is the MUTATION TWIN, the
   * global parsers unwrapped as before this change. dataBucketBelowParsers
   * models mounting the bucket below them.
   */
  const makeParserApp = ({
    skipParsers = true,
    dataLimit = HUGE,
    dataBucketBelowParsers = false,
    authenticated = true,
  } = {}) => {
    const probe = { globalParserRan: false, authRan: false };
    const wrap = skipParsers ? oauthRateLimiters.skipOauthRouter : (parser) => parser;
    const dataLimiter = oauthRateLimiters.createMcpDataLimiter({ limit: dataLimit });

    const app = express();
    app.set('trust proxy', 1);
    if (!dataBucketBelowParsers) app.use(oauthRateLimiters.MCP_DATA_PATHS, dataLimiter);
    app.use(
      rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: HUGE,
        store: new MemoryStore(),
        keyGenerator: (req) => ipKeyGenerator(req.ip),
        skip: oauthRateLimiters.skipGlobalLimiter,
      })
    );
    // The probe sits INSIDE the wrapper: it records the parser actually running.
    const json50 = express.json({ limit: '50mb' });
    const urlencoded50 = express.urlencoded({ limit: '50mb', extended: true });
    app.use(
      wrap((req, res, next) => {
        probe.globalParserRan = true;
        json50(req, res, next);
      })
    );
    app.use(
      wrap((req, res, next) => {
        probe.globalParserRan = true;
        urlencoded50(req, res, next);
      })
    );
    if (dataBucketBelowParsers) app.use(oauthRateLimiters.MCP_DATA_PATHS, dataLimiter);

    const echo = (req, res) => res.json({ fields: Object.keys(req.body || {}).length });
    app.post('/api/other', echo);
    app.post('/api/meallogx', echo);
    app.use(
      '/api/meallog',
      createMealLogRouter({
        // Stand-in for ticket 31: records that the route was reached.
        requireMcpAuth: () => (req, res, next) => {
          probe.authRan = true;
          if (!authenticated) return res.sendStatus(401);
          req.user = { userId: '42' };
          return next();
        },
        service: { save: async () => ({ created: true, record: { id: '1' } }) },
      })
    );
    app.probe = probe;
    return app;
  };

  const postMeal = (app, url, body, ip = freshIp()) =>
    request(app)
      .post(url)
      .set('X-Forwarded-For', ip)
      .set('Content-Type', 'application/json')
      .set('Idempotency-Key', KEY)
      .send(body);

  it('accepts an ordinary meal, so the 413s below are not a route refusing everything', async () => {
    const app = makeParserApp();

    const res = await postMeal(app, '/api/meallog/me', JSON.stringify(MEAL));

    expect(res.status).to.equal(201);
    expect(app.probe.globalParserRan, 'the global parser must not read it').to.equal(false);
  });

  // Double slash is here because express serves it through router.post('/me')
  // although the data bucket does not match it (see MEALLOG_ROUTER_PREFIX).
  ['/api/meallog/me', '/API/MEALLOG/ME', '/api/meallog/me/', '/api/meallog//me'].forEach((url) => {
    it(`refuses a 40KB body on ${url} with 413, read only by the route's parser`, async () => {
      const app = makeParserApp();

      const res = await postMeal(app, url, PADDED_MEAL);

      expect(res.status).to.equal(413);
      expect(res.body.error).to.equal('Meal log request is too large');
      expect(app.probe.globalParserRan, 'the global 50mb parser must be skipped').to.equal(false);
      expect(app.probe.authRan, 'the route was reached').to.equal(true);
    });
  });

  it('and the MUTATION TWIN, with the global parsers unwrapped, reads and ACCEPTS that body', async () => {
    // If this ever stops answering 201, something other than the skip is
    // refusing the body and the 413 cases above prove nothing.
    const twin = makeParserApp({ skipParsers: false });

    const res = await postMeal(twin, '/api/meallog/me', PADDED_MEAL);

    expect(twin.probe.globalParserRan).to.equal(true);
    expect(res.status, 'the global parser read 40KB and the route parser became a no-op').to.equal(201);
  });

  it('does not read an unauthenticated caller\'s body: 401, not 413', async () => {
    // The route parser sits AFTER authentication. Parsing first would answer 413.
    const app = makeParserApp({ authenticated: false });

    const res = await postMeal(app, '/api/meallog/me', PADDED_MEAL);

    expect(res.status).to.equal(401);
    expect(app.probe.globalParserRan).to.equal(false);
  });

  it('answers malformed JSON with 400, not the route\'s 503', async () => {
    const app = makeParserApp();

    const res = await postMeal(app, '/api/meallog/me', '{"date":');

    expect(res.status).to.equal(400);
    expect(res.body.error).to.equal('Invalid meal log request');
  });

  it('does not let the global parser read an ingest body either (no route yet: 404)', async () => {
    const app = makeParserApp();

    const res = await request(app)
      .post('/api/security-events/mcp')
      .set('X-Forwarded-For', freshIp())
      .type('form')
      .send({ padding: 'x'.repeat(40000) });

    expect(res.status).to.equal(404);
    expect(app.probe.globalParserRan).to.equal(false);
  });

  it('refuses the flood BEFORE any parser reads the request', async () => {
    const app = makeParserApp({ dataLimit: FLOOD });
    const ip = freshIp();
    for (let i = 0; i < FLOOD; i += 1) await postMeal(app, '/api/meallog/me', JSON.stringify(MEAL), ip);

    app.probe.globalParserRan = false;
    app.probe.authRan = false;
    const res = await postMeal(app, '/api/meallog/me', PADDED_MEAL, ip);

    expect(res.status).to.equal(429);
    expect(app.probe.globalParserRan, 'the global parser must not run').to.equal(false);
    // The route parser is below authentication, so not reaching auth means not parsing.
    expect(app.probe.authRan, 'the route, and so its parser, must not be reached').to.equal(false);
  });

  it('and the same case goes red with the bucket below unwrapped parsers', async () => {
    // The defective arm, run explicitly, so parserRan === false above is shown
    // to be something this probe can see.
    const app = makeParserApp({ dataLimit: FLOOD, skipParsers: false, dataBucketBelowParsers: true });
    const ip = freshIp();
    for (let i = 0; i < FLOOD; i += 1) await postMeal(app, '/api/meallog/me', JSON.stringify(MEAL), ip);

    app.probe.globalParserRan = false;
    const res = await postMeal(app, '/api/meallog/me', PADDED_MEAL, ip);

    expect(res.status).to.equal(429);
    expect(app.probe.globalParserRan, 'the defective arm must read the body').to.equal(true);
  });

  it('still parses a 2MB body on non-MCP routes, including a prefix look-alike', async () => {
    const app = makeParserApp();

    for (const url of ['/api/other', '/api/meallogx']) {
      const res = await request(app)
        .post(url)
        .set('X-Forwarded-For', freshIp())
        .type('form')
        .send({ padding: 'z'.repeat(2 * 1024 * 1024) });
      expect(res.status, url).to.equal(200);
      expect(res.body.fields, url).to.equal(1);
    }
  });

  it('derives the parser skip from MCP_DATA_PATHS, so a new data path is covered', () => {
    const { isRouteParsedPath } = oauthRateLimiters;

    oauthRateLimiters.MCP_DATA_PATHS.forEach((p) => {
      expect(isRouteParsedPath({ path: p }), p).to.equal(true);
      expect(isRouteParsedPath({ path: p.toUpperCase() }), p).to.equal(true);
    });
    expect(isRouteParsedPath({ path: '/api/meallog' })).to.equal(true);
    expect(isRouteParsedPath({ path: '/api/meallog//me' })).to.equal(true);
    expect(isRouteParsedPath({ path: '/api/oauth/token' })).to.equal(true);

    expect(isRouteParsedPath({ path: '/api/meallogx' })).to.equal(false);
    expect(isRouteParsedPath({ path: '/api/security-events/other' })).to.equal(false);
    expect(isRouteParsedPath({ path: '/api/other' })).to.equal(false);
  });

  it('pins both router prefixes to their real mounts in routes/index.js', () => {
    // Duplicated literals: remount a router and the 50mb parser reads its bodies
    // again while every behaviour case (built from the constants) stays green.
    const code = fs
      .readFileSync(path.join(__dirname, '..', 'routes', 'index.js'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    const escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    const mountOf = (prefix, module) =>
      new RegExp(
        `app\\.use\\(\\s*["']${escape(prefix)}["']\\s*,\\s*require\\(\\s*["']\\./${module}["']\\s*\\)`
      );

    expect(code, 'meallog router mount').to.match(
      mountOf(oauthRateLimiters.MEALLOG_ROUTER_PREFIX, 'meallog')
    );
    expect(code, 'oauth router mount').to.match(mountOf(oauthRateLimiters.OAUTH_ROUTER_PREFIX, 'oauth'));
    expect(oauthRateLimiters.MCP_DATA_PATHS[0].startsWith(`${oauthRateLimiters.MEALLOG_ROUTER_PREFIX}/`)).to.equal(
      true
    );
  });

  it('refuses a form-encoded POST with 400, the body unread by either parser', async () => {
    // 40KB so a read by the route's 16kb parser would show as 413, not 400.
    const app = makeParserApp();

    const res = await request(app)
      .post('/api/meallog/me')
      .set('X-Forwarded-For', freshIp())
      .set('Idempotency-Key', KEY)
      .type('form')
      .send({ ...MEAL, padding: 'x'.repeat(40000) });

    expect(res.status).to.equal(400);
    expect(res.body.error).to.equal('Invalid meal log request');
    expect(app.probe.globalParserRan).to.equal(false);
  });

  it('does not treat an exposed non-body-parser 4xx as a body refusal', async () => {
    // An exposed non-body-parser 4xx skips the body-refusal branch and falls to
    // the 503 catch-all (current behaviour; see the note in routes/meallog.js).
    const authError = Object.assign(new Error('unauthorized'), { status: 401, statusCode: 401, expose: true });
    const app = express();
    app.use(
      '/api/meallog',
      createMealLogRouter({
        requireMcpAuth: () => (req, res, next) => next(authError),
        service: { save: async () => ({ created: true, record: { id: '1' } }) },
      })
    );

    const res = await request(app)
      .post('/api/meallog/me')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify(MEAL));

    expect(res.body.error).to.not.equal('Invalid meal log request');
    expect(res.status).to.equal(503);
  });
});
