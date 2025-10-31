import express from "express";
import Joi from "joi";
import jwt from "jsonwebtoken";
import pino from "pino-http";
import pool from "./db/db.js";

const app = express();
const logger = pino();
app.use(logger);
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "supersecret";