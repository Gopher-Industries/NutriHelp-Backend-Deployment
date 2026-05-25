require('dotenv').config({ override: true });

const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { exec } = require('child_process');

const logger = require('./utils/logger');
const requestLoggingMiddleware = require('./middleware/requestLogger');
const { sessionMonitorMiddleware } = require('./middleware/sessionMonitor');
const { structuredErrorHandler } = require('./middleware/structuredErrorHandler');
const responseContractMiddleware = require('./middleware/responseContract');
const { localeMiddleware } = require('./utils/messages');

const {
  errorLogger,
  responseTimeLogger,
  uncaughtExceptionHandler,
  unhandledRejectionHandler
} = require('./middleware/errorLogger');

const helmet = require('helmet');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const yaml = require('yamljs');
const rateLimit = require('express-rate-limit');

const uploadRoutes = require('./routes/uploadRoutes');
const systemRoutes = require('./routes/systemRoutes');
const { metricsMiddleware, metricsEndpoint } = require('./Monitor_&_Logging/metrics');
const { runAlertCheckJob } = require('./services/securityAlertService');

const app = express();
const tlsKeyPath = process.env.TLS_KEY_PATH || path.join(__dirname, 'certs', 'local-key.pem');
const tlsCertPath = process.env.TLS_CERT_PATH || path.join(__dirname, 'certs', 'local-cert.pem');
const useTls = !process.env.RENDER && fs.existsSync(tlsKeyPath) && fs.existsSync(tlsCertPath);
const PORT = Number(process.env.PORT) || (
  useTls ? Number(process.env.HTTPS_PORT) || 8443
         : Number(process.env.HTTP_PORT)  || 8081
);

console.log('🔧 Environment Variables Check:');
console.log('   SUPABASE_URL:', process.env.SUPABASE_URL ? '✓ Set' : '✗ Missing');
console.log('   SUPABASE_ANON_KEY:', process.env.SUPABASE_ANON_KEY ? '✓ Set' : '✗ Missing');
console.log('   PORT:', PORT, useTls ? '(HTTPS)' : '(HTTP)');
console.log('');

let db = require('./dbConnection');

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const tempDir = path.join(uploadsDir, 'temp');
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir, { recursive: true });
}

function cleanupOldFiles() {
  const now = Date.now();
  const ONE_DAY = 24 * 60 * 60 * 1000;
  try {
    for (const file of fs.readdirSync(tempDir)) {
      const filePath = path.join(tempDir, file);
      const stats = fs.statSync(filePath);
      if (now - stats.mtimeMs > ONE_DAY) {
        fs.unlinkSync(filePath);
      }
    }
  } catch (err) {
    console.error('Error during file cleanup:', err);
  }
}

cleanupOldFiles();
setInterval(cleanupOldFiles, 3 * 60 * 60 * 1000);

let alertIntervalId = null;

// --- Trusted early middlewares ---
app.use(requestLoggingMiddleware);
app.use(sessionMonitorMiddleware);
app.use(localeMiddleware);
app.use(responseContractMiddleware);

// Allowed origins: comma-separated list in ALLOWED_ORIGINS env var
// e.g. ALLOWED_ORIGINS=https://nutrihelp.vercel.app,https://custom-domain.com
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : [];

const corsOrigin = (origin, callback) => {
  if (!origin) return callback(null, true);

  // Allow Render's own service URL (Swagger UI same-service requests)
  if (process.env.RENDER_EXTERNAL_URL && origin === process.env.RENDER_EXTERNAL_URL) {
    return callback(null, true);
  }

  // Allow localhost / 127.0.0.1 on any port (covers Expo Web :19006, Metro :8081, etc.)
  if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
    return callback(null, true);
  }

  // Allow Expo Go LAN dev client (http://<local-ip>:8081 and :19000)
  if (/^http:\/\/192\.168\.\d+\.\d+:(8081|19000|19006)$/.test(origin) ||
      /^http:\/\/10\.\d+\.\d+\.\d+:(8081|19000|19006)$/.test(origin)) {
    return callback(null, true);
  }

  // Allow any *.vercel.app preview deploy (for web builds)
  if (/^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin)) {
    return callback(null, true);
  }

  // Allow explicit origins from env var
  if (allowedOriginsEnv.includes(origin)) {
    return callback(null, true);
  }

  callback(new Error(`CORS blocked: ${origin}`));
};

app.use(cors({ origin: corsOrigin, credentials: true, methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.options('*', cors({ origin: corsOrigin, credentials: true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      objectSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, error: 'Too many requests, please try again later.' },
});
app.use(limiter);

try {
  const swaggerDocument = yaml.load('./index.yaml');
  if (process.env.RENDER_EXTERNAL_URL) {
    swaggerDocument.servers = [
      { url: `${process.env.RENDER_EXTERNAL_URL}/api`, description: 'Render' },
      ...(swaggerDocument.servers || []),
    ];
  }
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
  console.log('📚 Swagger loaded successfully');
} catch (e) {
  console.warn('⚠️  Swagger YAML failed to parse — /api-docs disabled:', String(e.message).split('\n')[0]);
}

app.use(responseTimeLogger);
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(metricsMiddleware);
app.get('/api/metrics', metricsEndpoint);

app.get('/api/ai/stats', (req, res) => {
  const aiMonitor = require('./services/aiServiceMonitor');
  res.json({ success: true, data: aiMonitor.getStats() });
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', tls: '1.3 enforced' });
});

app.get('/api', (_req, res) => {
  res.json({
    status: 'ok',
    message: 'NutriHelp API is running',
    uptime: process.uptime(),
    metrics: '/api/metrics',
    docs: '/api-docs',
  });
});

app.get('/', (_req, res) => res.redirect('/api'));

app.use('/api/system', systemRoutes);

const routesRegistrar = require('./routes');
routesRegistrar(app);

app.use('/api', uploadRoutes);
app.use('/uploads', express.static('uploads'));
app.use('/api/sms', require('./routes/sms'));
app.use('/security', require('./routes/securityEvents'));

app.use(errorLogger);
app.use(structuredErrorHandler);

app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message;
  res.status(status).json({
    success: false,
    error: message,
    timestamp: new Date().toISOString(),
  });
});

process.on('uncaughtException', uncaughtExceptionHandler);
process.on('unhandledRejection', unhandledRejectionHandler);

function gracefulShutdown(signal) {
  console.log(`\n[server] ${signal} received — shutting down gracefully`);
  if (alertIntervalId) {
    clearInterval(alertIntervalId);
    alertIntervalId = null;
    console.log('[server] CT-004 Alert checking job stopped');
  }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

let server;
if (useTls) {
  const tlsOptions = {
    key: fs.readFileSync(tlsKeyPath),
    cert: fs.readFileSync(tlsCertPath),
    minVersion: 'TLSv1.3',
  };
  server = https.createServer(tlsOptions, app);
  console.log('🔒 Using HTTPS (local TLS certs found)');
} else {
  server = http.createServer(app);
  console.log(process.env.RENDER
    ? '🌐 Using HTTP (Render handles TLS at proxy)'
    : '🔓 Using HTTP (no local TLS certs found)');
}

server.listen(PORT, async () => {
  console.log('\n🎉 NutriHelp API launched successfully!');
  console.log('='.repeat(50));
  console.log(`Server is running on port ${PORT}`);
  console.log(`📚 Swagger UI: http://localhost:${PORT}/api-docs`);
  console.log('='.repeat(50));
  console.log('💡 Press Ctrl+C to stop the server \n');

  // CT-004: Start alert job only after the server is fully bound and ready.
  try {
    await runAlertCheckJob();
    alertIntervalId = setInterval(async () => {
      try {
        await runAlertCheckJob();
      } catch (err) {
        console.error('[server] Alert check job failed unexpectedly:', err.message);
      }
    }, 5 * 60 * 1000);
    console.log('[server] CT-004 Alert checking job initialized (5-minute interval)');
  } catch (err) {
    console.warn('[server] Failed to run initial alert check:', err.message);
  }

  if (process.platform === 'win32' && !process.env.RENDER) {
    exec(`start http://localhost:${PORT}/api-docs`);
  }
});

module.exports = app;
