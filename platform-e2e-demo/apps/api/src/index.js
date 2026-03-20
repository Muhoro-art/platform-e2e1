import express from "express";
import rateLimit from "express-rate-limit";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import { Pool } from "pg";
import client from "prom-client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

export function createApp({ pool, jwtSecret = process.env.JWT_SECRET } = {}) {
  const app = express();
  app.use(express.json());
  app.use(cors());
  app.use(helmet());
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      limit: 120,
      standardHeaders: true,
      legacyHeaders: false
    })
  );

  const register = new client.Registry();
  client.collectDefaultMetrics({ register });

  const httpCounter = new client.Counter({
    name: "http_requests_total",
    help: "Total HTTP requests",
    labelNames: ["method", "route", "status"],
    registers: [register]
  });

  app.use((req, res, next) => {
    res.on("finish", () => {
      httpCounter.inc({
        method: req.method,
        route: req.path,
        status: String(res.statusCode)
      });
    });
    next();
  });

  function signToken(user) {
    return jwt.sign(
      { sub: user.id, email: user.email, roles: user.roles },
      jwtSecret,
      { expiresIn: "15m" }
    );
  }

  function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, error: "Missing token" });
    }

    try {
      const token = header.slice(7);
      req.user = jwt.verify(token, jwtSecret);
      next();
    } catch {
      return res.status(401).json({ success: false, error: "Invalid token" });
    }
  }

  function requireRole(...roles) {
    return (req, res, next) => {
      const userRoles = req.user?.roles || [];
      const allowed = userRoles.some((r) => roles.includes(r));
      if (!allowed) {
        return res.status(403).json({ success: false, error: "Forbidden" });
      }
      next();
    };
  }

  async function audit(userId, action, resource) {
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, resource, created_at)
       VALUES ($1, $2, $3, NOW())`,
      [userId, action, resource]
    );
  }

  app.get("/health", async (req, res) => {
    try {
      await pool.query("SELECT 1");
      res.json({ success: true, status: "ok" });
    } catch {
      res.status(500).json({ success: false, status: "db_error" });
    }
  });

  app.get("/metrics", async (req, res) => {
    res.set("Content-Type", register.contentType);
    res.end(await register.metrics());
  });

  app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query(
      `SELECT u.id, u.email, u.password_hash,
              ARRAY_REMOVE(ARRAY_AGG(r.name), NULL) AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.email = $1
       GROUP BY u.id`,
      [email]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, error: "Invalid credentials" });
    }

    await audit(user.id, "auth.login", "user");
    res.json({
      success: true,
      data: {
        token: signToken(user),
        user: { id: user.id, email: user.email, roles: user.roles }
      }
    });
  });

  app.get("/tasks", auth, async (req, res) => {
    const result = await pool.query(`SELECT * FROM tasks ORDER BY id DESC`);
    res.json({ success: true, data: result.rows });
  });

  app.post("/tasks", auth, requireRole("admin", "developer"), async (req, res) => {
    const { title } = req.body;
    const result = await pool.query(
      `INSERT INTO tasks (title, status, created_at)
       VALUES ($1, 'open', NOW())
       RETURNING *`,
      [title]
    );
    await audit(req.user.sub, "task.create", "task");
    res.status(201).json({ success: true, data: result.rows[0] });
  });

  app.patch("/tasks/:id", auth, requireRole("admin", "developer"), async (req, res) => {
    const { status } = req.body;
    const result = await pool.query(
      `UPDATE tasks
       SET status = $1
       WHERE id = $2
       RETURNING *`,
      [status, req.params.id]
    );
    await audit(req.user.sub, "task.update", "task");
    res.json({ success: true, data: result.rows[0] });
  });

  app.get("/admin/users", auth, requireRole("admin"), async (req, res) => {
    const result = await pool.query(`SELECT id, email FROM users ORDER BY id`);
    await audit(req.user.sub, "admin.users.read", "user");
    res.json({ success: true, data: result.rows });
  });

  return app;
}

export function createPool() {
  return new Pool({
    connectionString: process.env.DATABASE_URL
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = createApp({ pool: createPool() });
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`API listening on ${port}`);
  });
}
