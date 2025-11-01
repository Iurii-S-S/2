import express from "express";
import Joi from "joi";
import jwt from "jsonwebtoken";
import pino from "pino-http";
import pool from "./database.js";

const app = express();
const logger = pino();
app.use(logger);
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

// helper
function sendError(res, status, code, message) {
  return res.status(status).json({ success: false, error: { code, message } });
}

function orderPublic(row) {
  if (!row) return null;
  return {
    id: row.id,
    user_id: row.user_id,
    items: row.items,
    status: row.status,
    total: parseFloat(row.total),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

const createSchema = Joi.object({
  items: Joi.array().items(Joi.object({
    product: Joi.string().required(),
    qty: Joi.number().integer().min(1).required()
  })).min(1).required(),
  total: Joi.number().precision(2).min(0).required()
});

const updateSchema = Joi.object({
  status: Joi.string().valid("created", "in_progress", "completed", "cancelled").required()
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
    req.user = jwt.verify(parts[1], JWT_SECRET);
    return next();
  } catch (err) {
    return sendError(res, 403, "AUTH_INVALID_TOKEN", "Token invalid or expired");
  }
}

app.use((req, res, next) => {
  // allow health without auth
  if (req.path === "/health") return next();
  return authMiddleware(req, res, next);
});

// create order
app.post("/v1/orders", async (req, res) => {
  const { error, value } = createSchema.validate(req.body);
  if (error) return sendError(res, 400, "VALIDATION_ERROR", error.message);

  try {
    // ensure user exists
    const userCheck = await pool.query("SELECT id FROM users WHERE id = $1", [req.user.id]);
    if (userCheck.rowCount === 0) return sendError(res, 400, "USER_NOT_FOUND", "User not found");

    const q = `INSERT INTO orders (user_id, items, status, total)
               VALUES ($1, $2, $3, $4) RETURNING *`;
    const params = [req.user.id, JSON.stringify(value.items), "created", value.total];
    const r = await pool.query(q, params);
    // domain event placeholder: publish "order.created" to broker
    return res.status(201).json({ success: true, data: orderPublic(r.rows[0]) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Failed to create order");
  }
});

// get order by id
app.get("/v1/orders/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const r = await pool.query("SELECT * FROM orders WHERE id = $1", [id]);
    if (r.rowCount === 0) return sendError(res, 404, "NOT_FOUND", "Order not found");
    const order = r.rows[0];
    const roles = req.user.roles || [];
    if (order.user_id !== req.user.id && !roles.includes("admin")) {
      return sendError(res, 403, "FORBIDDEN", "Access denied");
    }
    return res.json({ success: true, data: orderPublic(order) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Failed to fetch order");
  }
});

// list current user's orders with pagination and sorting
app.get("/v1/orders", async (req, res) => {
  const page = Math.max(parseInt(req.query.page || "1", 10), 1);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "20", 10), 1), 100);
  const offset = (page - 1) * limit;
  const sort = (req.query.sort === "asc") ? "ASC" : "DESC";

  try {
    const q = `SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at ${sort} LIMIT $2 OFFSET $3`;
    const r = await pool.query(q, [req.user.id, limit, offset]);
    return res.json({ success: true, data: { items: r.rows.map(orderPublic), page, limit } });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Failed to list orders");
  }
});

// update status (owner or admin)
app.patch("/v1/orders/:id", async (req, res) => {
  const { error, value } = updateSchema.validate(req.body);
  if (error) return sendError(res, 400, "VALIDATION_ERROR", error.message);

  const { id } = req.params;
  try {
    const r = await pool.query("SELECT * FROM orders WHERE id = $1", [id]);
    if (r.rowCount === 0) return sendError(res, 404, "NOT_FOUND", "Order not found");
    const order = r.rows[0];
    const roles = req.user.roles || [];
    if (order.user_id !== req.user.id && !roles.includes("admin")) {
      return sendError(res, 403, "FORBIDDEN", "Not allowed");
    }

    const upd = await pool.query("UPDATE orders SET status = $1, updated_at = now() WHERE id = $2 RETURNING *", [value.status, id]);
    // domain event placeholder: publish "order.status_updated"
    return res.json({ success: true, data: orderPublic(upd.rows[0]) });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return sendError(res, 500, "INTERNAL", "Failed to update order");
  }
});

// health
app.get("/health", (req, res) => res.json({ success: true, data: { status: "orders OK" } }));

const port = process.env.PORT || 5002;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Orders service listening on ${port}`);
});