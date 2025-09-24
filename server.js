// server.js
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const yaml = require("yamljs");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

// routes
const uploadRoutes = require("./routes/uploadRoutes");
const systemRoutes = require("./routes/systemRoutes");
const routes = require("./routes");             // your main router index (mount under /api inside)
const signupRoute = require("./routes/signup"); // signup router

// ----- directories (ensure uploads and temp exist) -----
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  try {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log("Created uploads directory");
  } catch (err) {
    console.error("Error creating uploads directory:", err);
  }
}

const tempDir = path.join(uploadsDir, "temp");
if (!fs.existsSync(tempDir)) {
  try {
    fs.mkdirSync(tempDir, { recursive: true });
    console.log("Created temp uploads directory");
  } catch (err) {
    console.error("Error creating temp uploads directory:", err);
  }
}

// ----- temp file cleanup -----
function cleanupOldFiles() {
  const now = Date.now();
  const ONE_DAY = 24 * 60 * 60 * 1000;

  try {
    const tempFiles = fs.readdirSync(tempDir);
    let deletedCount = 0;
    tempFiles.forEach((file) => {
      const filePath = path.join(tempDir, file);
      try {
        const stats = fs.statSync(filePath);
        if (now - stats.mtimeMs > ONE_DAY) {
          fs.unlinkSync(filePath);
          deletedCount++;
        }
      } catch (err) {
        console.error(`Error checking file ${filePath}:`, err);
      }
    });
    if (deletedCount > 0) {
      console.log(`Cleaned up ${deletedCount} old temporary files`);
    }
  } catch (err) {
    console.error("Error during file cleanup:", err);
  }
}
cleanupOldFiles();
setInterval(cleanupOldFiles, 3 * 60 * 60 * 1000);

// ----- app -----
const app = express();
app.set("trust proxy", 1);

// ----- env and port -----
const PORT = process.env.PORT || 10000;

// You can set a comma-separated list in FRONTEND_ORIGINS to allow specific sites
// Example: FRONTEND_ORIGINS="https://nutrihelpfrontend.vercel.app,https://yourdomain.com"
const EXTRA_ORIGINS = (process.env.FRONTEND_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Local dev defaults
const ALLOWED_ORIGINS = new Set([
  "http://localhost:3000",
  "http://localhost:5173",
  ...EXTRA_ORIGINS,
]);

// Allow any preview on vercel.app (project-name-randomhash.vercel.app)
const allowVercelPreview = (origin) =>
  /^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin || "");

// ----- CORS -----
app.use(
  cors({
    origin: (origin, cb) => {
      // allow server-to-server or curl with no Origin
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.has(origin) || allowVercelPreview(origin)) {
        return cb(null, true);
      }
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.options("*", cors());

// ----- security headers (Helmet CSP) -----
const apiOrigin =
  process.env.RENDER_EXTERNAL_URL || "https://nutrihelp-backend-deployment.onrender.com";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdn.jsdelivr.net",
          "https://cdnjs.cloudflare.com",
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", apiOrigin, "https://*.vercel.app"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  })
);

// ----- rate limiter -----
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: "Too many requests, please try again later.",
  },
});
app.use(limiter);

// ----- body parsers -----
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ----- health endpoints -----
app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    ts: Date.now(),
    env: process.env.NODE_ENV || "production",
  });
});
app.get("/api/health", (req, res) => {
  res.status(200).json({
    ok: true,
    ts: Date.now(),
    env: process.env.NODE_ENV || "production",
  });
});

// ----- swagger -----
const swaggerDocument = yaml.load(path.join(__dirname, "index.yaml"));
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// ----- routes (mount under /api) -----
app.use("/api/system", systemRoutes);
routes(app);                 // ensure everything this mounts is using /api/... inside routes/index.js
app.use("/api", uploadRoutes);
app.use("/api/signup", signupRoute);

// static files
app.use("/uploads", express.static("uploads"));

// ----- error handlers -----
app.use((err, req, res, next) => {
  if (err) {
    const msg = err.message || "Bad request";
    return res.status(400).json({ error: msg });
  }
  next();
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ----- start -----
app.listen(PORT, () => {
  const base = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  console.log("\n🎉 NutriHelp API launched successfully!");
  console.log("==================================================");
  console.log(`Server is running on port ${PORT}`);
  console.log(`📚 Swagger UI: ${base}/api-docs`);
  console.log("==================================================\n");
});