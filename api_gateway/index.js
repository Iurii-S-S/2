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