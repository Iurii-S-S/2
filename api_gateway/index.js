import express from "express";
import httpProxy from "express-http-proxy";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";
import pino from "pino-http";

const app = express();
const logger = pino();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(logger);

// env
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || "http://service_users:5001";
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || "http://service_orders:5002";

// rate limiting (simple)
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
}));

// X-Request-ID passthrough: preserve or generate
app.use((req, res, next) => {
  const rid = req.headers["x-request-id"] || req.headers["x-requestid"] || (Date.now() + "-" + Math.random().toString(36).slice(2));
  req.headers["x-request-id"] = rid;
  res.setHeader("X-Request-ID", rid);
  next();
});

// public paths that don't require JWT
const publicPrefixes = [
  "/v1/users/register",
  "/v1/users/login",
  "/health"
];

function isPublicPath(path) {
  return publicPrefixes.some(p => path === p || path.startsWith(p));
}

// verify JWT middleware for gateway (populates req.user)
function verifyJWT(req, res, next) {
  if (isPublicPath(req.path)) return next();

  const auth = req.headers["authorization"];
  if (!auth) {
    return res.status(401).json({ success: false, error: { code: "AUTH_REQUIRED", message: "Authorization header missing" } });
  }
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ success: false, error: { code: "AUTH_INVALID", message: "Malformed Authorization header" } });
  }
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, error: { code: "AUTH_INVALID_TOKEN", message: "Token invalid or expired" } });
  }
}

app.use(verifyJWT);

// Proxy options to forward headers
const createProxy = (target) => httpProxy(target, {
  proxyReqPathResolver: (req) => req.originalUrl,
  proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
    proxyReqOpts.headers['x-request-id'] = srcReq.headers['x-request-id'] || "";
    proxyReqOpts.headers['authorization'] = srcReq.headers['authorization'] || "";
    return proxyReqOpts;
  }
});

app.use("/v1/users", createProxy(USERS_SERVICE_URL));
app.use("/v1/orders", createProxy(ORDERS_SERVICE_URL));

app.get("/health", (req, res) => res.json({ success: true, data: { status: "ok" } }));

const port = process.env.PORT || 8080;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`API Gateway listening on ${port}`);
});