// service_users/index.js
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Joi from "joi";
import pino from "pino-http";
import pool from "./database.js";

const app = express();
const logger = pino();
app.use(logger);
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const TOKEN_EXPIRES = "2h";

// helpers
function sendError(res, status, code, message) {
  return res.status(status).json({ success: false, error: { code, message } });
}

function toPublic(userRow) {
  if (!userRow) return null;
  return {
    id: userRow.id,
    email: userRow.email,
    name: userRow.name,
    roles: userRow.roles,
    created_at: userRow.created_at,
    updated_at: userRow.updated_at
  };
}

// validation schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().allow("", null)
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const updateSchema = Joi.object({
  name: Joi.string().allow("", null),
  password: Joi.string().min(6).optional()
});

// public: register
app.post("/v1/users/register", async (req, res) => {
  const { error, value } = registerSchema.validate(req.body);
  if (error) return sendError(res, 400, "VALIDATION_ERROR", error.message);

  const { email, password, name } = value;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const q = `INSERT INTO users (email, password, name, roles) VALUES ($1,$2,$3,$4)
               RETURNING id,email,name,roles,created_at,updated_at`;
    const params = [email, hashed, name || "", ['user']];
    const result = await pool.query(q, params);
    return res.json({ success: true, data: toPublic(result.rows[0]) });
  } catch (err) {
    // unique violation
    if (err.code === "23505") {
      return sendError(res, 400, "USER_EXISTS", "User with this email already exists");
    }
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Internal server error");
  }
});

// public: login
app.post("/v1/users/login", async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) return sendError(res, 400, "VALIDATION_ERROR", error.message);

  const { email, password } = value;
  try {
    const q = `SELECT id,email,password,name,roles FROM users WHERE email=$1`;
    const r = await pool.query(q, [email]);
    if (r.rowCount === 0) return sendError(res, 401, "NOT_FOUND", "User not found");

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return sendError(res, 403, "INVALID_CREDENTIALS", "Invalid credentials");

    const token = jwt.sign({ id: user.id, email: user.email, roles: user.roles }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES });
    return res.json({ success: true, data: { token } });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Internal error");
  }
});

// auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth) return sendError(res, 401, "AUTH_REQUIRED", "Authorization header missing");
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return sendError(res, 401, "AUTH_INVALID", "Malformed Authorization header");
  }
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return sendError(res, 403, "AUTH_INVALID_TOKEN", "Token invalid or expired");
  }
}

// protected: get current profile
app.get("/v1/users/me", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query("SELECT id,email,name,roles,created_at,updated_at FROM users WHERE id=$1", [req.user.id]);
    if (r.rowCount === 0) return sendError(res, 404, "NOT_FOUND", "User not found");
    return res.json({ success: true, data: toPublic(r.rows[0]) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Internal error");
  }
});

// protected: update profile
app.patch("/v1/users/me", authMiddleware, async (req, res) => {
  const { error, value } = updateSchema.validate(req.body);
  if (error) return sendError(res, 400, "VALIDATION_ERROR", error.message);

  try {
    const fields = [];
    const params = [];
    let idx = 1;
    if (value.name !== undefined) {
      fields.push(`name = $${idx++}`);
      params.push(value.name);
    }
    if (value.password) {
      const hashed = await bcrypt.hash(value.password, 10);
      fields.push(`password = $${idx++}`);
      params.push(hashed);
    }
    if (fields.length === 0) return res.json({ success: true, data: null });

    params.push(req.user.id);
    const q = `UPDATE users SET ${fields.join(", ")}, updated_at = now() WHERE id = $${idx} RETURNING id,email,name,roles,created_at,updated_at`;
    const r = await pool.query(q, params);
    return res.json({ success: true, data: toPublic(r.rows[0]) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Internal error");
  }
});

// protected admin: list users with pagination & optional filter
app.get("/v1/users", authMiddleware, async (req, res) => {
  const roles = req.user.roles || [];
  if (!roles.includes("admin")) return sendError(res, 403, "FORBIDDEN", "Admin role required");

  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "20", 10), 1), 100);
  const offset = (page - 1) * limit;
  const filter = req.query.email || "";

  try {
    const q = `SELECT id,email,name,roles,created_at,updated_at
               FROM users
               WHERE ($1 = '' OR email ILIKE $1)
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3`;
    const params = [`%${filter}%`, limit, offset];
    const r = await pool.query(q, params);
    return res.json({ success: true, data: { items: r.rows.map(toPublic), page, limit } });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Internal error");
  }
});

app.get("/health", (req, res) => res.json({ success: true, data: { status: "users OK" } }));

const port = process.env.PORT || 5001;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Users service listening on ${port}`);
});
