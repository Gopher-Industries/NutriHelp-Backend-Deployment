require("dotenv").config();

// Structured Logging - NEW
const logger = require('./utils/logger');
const { requestLoggingMiddleware } = require('./middleware/requestLogger');
const { sessionMonitorMiddleware } = require('./middleware/sessionMonitor');
const { structuredErrorHandler } = require('./middleware/structuredErrorHandler');

//Logging & Metrics
const {
  metricsMiddleware,
  metricsEndpoint,
} = require("./Monitor_&_Logging/metrics");

// Debug environment variables
console.log("🔧 Environment Variables Check:");
console.log(
  "   SUPABASE_URL:",
  process.env.SUPABASE_URL ? "✓ Set" : "✗ Missing",
);
console.log(
  "   SUPABASE_ANON_KEY:",
  process.env.SUPABASE_ANON_KEY ? "✓ Set" : "✗ Missing",
);
console.log("   PORT:", process.env.PORT || "3000 (default)");
console.log("");

const express = require("express");
const { errorLogger, responseTimeLogger } = require("./middleware/errorLogger");

const helmet = require("helmet");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const yaml = require("yamljs");
const rateLimit = require("express-rate-limit");
const uploadRoutes = require("./routes/uploadRoutes");
const fs = require("fs");
const path = require("path");
const systemRoutes = require("./routes/systemRoutes");
const loginDashboard = require("./routes/loginDashboard.js");
const securityEventsRoutes = require("./routes/securityEvents");

// WARNING: Render has an ephemeral filesystem.
// Files saved to uploads/ will be deleted on every deploy or restart.
// TODO: Migrate file uploads to Supabase Storage for persistent storage.

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("Created uploads directory");
}

// Create temp directory for uploads
const tempDir = path.join(__dirname, "uploads", "temp");
if (!fs.existsSync(tempDir)) {
  fs.mkdirSync(tempDir, { recursive: true });
  console.log("Created temp uploads directory");
}

// Cleanup temp files
function cleanupOldFiles() {
  const now = Date.now();
  const ONE_DAY = 24 * 60 * 60 * 1000;
  try {
    for (const file of fs.readdirSync(tempDir)) {
      const filePath = path.join(tempDir, file);
      const stats = fs.statSync(filePath);
      if (now - stats.mtimeMs > ONE_DAY) fs.unlinkSync(filePath);
    }
  } catch (err) {
    console.error("Error during file cleanup:", err);
  }
}
cleanupOldFiles();
setInterval(cleanupOldFiles, 3 * 60 * 60 * 1000);

// ✅ Create the app BEFORE using it
const app = express();
const port = process.env.PORT || 3000;

// DB
let db = require("./dbConnection");

// ⚠️ CRITICAL: Add request logging middleware FIRST, before any routes
app.use(requestLoggingMiddleware);
app.use(sessionMonitorMiddleware);

// Dynamic CORS origin: reads allowed origins from ALLOWED_ORIGINS env var
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
  : [];

const corsOrigin = (origin, callback) => {
  // Allow requests with no Origin header (mobile clients, curl, etc.)
  if (!origin) return callback(null, true);

  // In development, also allow localhost origins
  if (process.env.NODE_ENV !== "production") {
    if (
      origin.startsWith("http://localhost") ||
      origin.startsWith("http://127.0.0.1")
    ) {
      return callback(null, true);
    }
  }

  // Allow origins from ALLOWED_ORIGINS env var
  if (allowedOriginsEnv.includes(origin)) {
    return callback(null, true);
  }

  // Allow legacy non-production tool origins
  if (
    origin.startsWith("chrome-extension://eggdlmopfankeonchoflhfoglaakobma") ||
    origin.startsWith("https://apifox.cn-hangzhou.log.aliyuncs.com")
  ) {
    return callback(null, true);
  }

  callback(new Error(`CORS blocked: ${origin}`));
};

// CORS
app.use(cors({ origin: corsOrigin, credentials: true }));
app.options("*", cors({ origin: corsOrigin, credentials: true }));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});
app.set("trust proxy", 1);

// Security
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),
);

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 429, error: "Too many requests, please try again later." },
});
app.use(limiter);

// Swagger
const swaggerDocument = yaml.load("./index.yaml");
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
// Response time monitoring
app.use(responseTimeLogger);
// JSON & URL parser
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

//Logging & Metrics routes
app.use(metricsMiddleware);
app.get("/api/metrics", metricsEndpoint);
app.get("/api", (req, res) => {
  res.json({
    status: "ok",
    message: "NutriHelp API is running",
    uptime: process.uptime(),
    metrics: "/api/metrics",
    docs: "/api-docs"
  });
});
app.get("/", (req, res) => {
  res.redirect("/api");
});

// Health check endpoint for Render deployment
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// System routes (early in chain)
app.use("/api/system", systemRoutes);

// Main routes registrar
const routes = require("./routes");
routes(app);

// File uploads & static
app.use("/api", uploadRoutes);
app.use("/uploads", express.static("uploads"));

// Signup
app.use("/api/signup", require("./routes/signup"));
app.use("/security", securityEventsRoutes);

// SMS
app.use("/api/sms", require("./routes/sms"));

// Error handler
app.use(errorLogger);

// Structured error handling middleware (MUST be last)
app.use(structuredErrorHandler);

// Global error handler
const {
  uncaughtExceptionHandler,
  unhandledRejectionHandler,
} = require("./middleware/errorLogger");
process.on("uncaughtException", uncaughtExceptionHandler);
process.on("unhandledRejection", unhandledRejectionHandler);

// Start
app.listen(port, async () => {
  console.log("\n🎉 NutriHelp API launched successfully!");
  console.log("=".repeat(50));
  console.log(`Server is running on port ${port}`);
  console.log(`📚 Swagger UI: http://localhost:${port}/api-docs`);
  console.log("=".repeat(50));
  console.log("💡 Press Ctrl+C to stop the server \n");
});

const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;

setInterval(async () => {
  try {
    const response = await fetch(`${SELF_URL}/health`);
    console.log(`[Keep-Alive] Pinged /health — status: ${response.status}`);
  } catch (err) {
    console.error(`[Keep-Alive] Ping failed:`, err.message);
  }
}, 14 * 60 * 1000);
