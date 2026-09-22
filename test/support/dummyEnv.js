// Preloaded by the test:oauth and test:meallog scripts. Forces placeholder
// Supabase credentials before anything requires dbConnection.js, whose
// dotenv.config() does not override variables that are already set -- so the
// real Supabase credentials in .env (the live, shared team database) are never
// used by these suites. Other .env values still load.
// Do not load this from server.js paths: server.js uses override: true.
// Test scripts only: never preload it on a path that expects production
// NODE_ENV or origin behaviour, because it sets NODE_ENV=test.
process.env.SUPABASE_URL = 'https://test.supabase.co';
process.env.SUPABASE_ANON_KEY = 'dummy';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'dummy';
process.env.NODE_ENV = 'test';
