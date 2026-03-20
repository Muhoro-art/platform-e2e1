import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { Pool } from "pg";

dotenv.config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const adminPass = await bcrypt.hash("Admin123!", 10);
const devPass = await bcrypt.hash("Dev123!", 10);
const managerPass = await bcrypt.hash("Manager123!", 10);

await pool.query(`
INSERT INTO roles (name) VALUES
('admin'),
('developer'),
('manager')
ON CONFLICT DO NOTHING;
`);

await pool.query(
  `INSERT INTO users (email, password_hash)
   VALUES ($1, $2), ($3, $4), ($5, $6)
   ON CONFLICT (email) DO NOTHING;`,
  [
    "admin@demo.local", adminPass,
    "dev@demo.local", devPass,
    "manager@demo.local", managerPass
  ]
);

await pool.query(`
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'admin@demo.local' AND r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'dev@demo.local' AND r.name = 'developer'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'manager@demo.local' AND r.name = 'manager'
ON CONFLICT DO NOTHING;
`);

console.log("Seed complete");
await pool.end();
