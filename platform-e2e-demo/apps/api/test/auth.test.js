import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcrypt";
import { createApp } from "../src/index.js";

async function setupApp() {
  const adminHash = await bcrypt.hash("Admin123!", 10);
  const devHash = await bcrypt.hash("Dev123!", 10);

  const db = {
    users: [
      { id: 1, email: "admin@demo.local", password_hash: adminHash, roles: ["admin"] },
      { id: 2, email: "dev@demo.local", password_hash: devHash, roles: ["developer"] }
    ],
    tasks: [],
    audits: []
  };

  const pool = {
    async query(text, params = []) {
      if (text.includes("SELECT 1")) return { rows: [{ '?column?': 1 }] };

      if (text.includes("FROM users u") && text.includes("WHERE u.email = $1")) {
        const user = db.users.find((u) => u.email === params[0]);
        return { rows: user ? [user] : [] };
      }

      if (text.includes("SELECT id, email FROM users")) {
        return { rows: db.users.map(({ id, email }) => ({ id, email })) };
      }

      if (text.includes("SELECT * FROM tasks")) {
        return { rows: [...db.tasks].sort((a, b) => b.id - a.id) };
      }

      if (text.includes("INSERT INTO tasks")) {
        const row = { id: db.tasks.length + 1, title: params[0], status: "open" };
        db.tasks.push(row);
        return { rows: [row] };
      }

      if (text.includes("UPDATE tasks")) {
        const id = Number(params[1]);
        const existing = db.tasks.find((t) => t.id === id);
        if (!existing) return { rows: [] };
        existing.status = params[0];
        return { rows: [existing] };
      }

      if (text.includes("INSERT INTO audit_logs")) {
        db.audits.push({ user_id: params[0], action: params[1], resource: params[2] });
        return { rows: [] };
      }

      throw new Error(`Unhandled query in test DB: ${text}`);
    }
  };

  const app = createApp({ pool, jwtSecret: "test-secret" });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    close: () => new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    db
  };
}

async function login(baseUrl, email, password) {
  const response = await fetch(`${baseUrl}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  return response;
}

test("health endpoint up", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const response = await fetch(`${ctx.baseUrl}/health`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.success, true);
  assert.equal(body.status, "ok");
});

test("login success", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const response = await login(ctx.baseUrl, "admin@demo.local", "Admin123!");
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.success, true);
  assert.ok(body.data.token);
  assert.deepEqual(body.data.user.roles, ["admin"]);
});

test("login failure", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const response = await login(ctx.baseUrl, "admin@demo.local", "wrong-password");
  assert.equal(response.status, 401);
  const body = await response.json();
  assert.equal(body.success, false);
});

test("admin route forbidden for non-admin", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const loginResponse = await login(ctx.baseUrl, "dev@demo.local", "Dev123!");
  const loginBody = await loginResponse.json();

  const response = await fetch(`${ctx.baseUrl}/admin/users`, {
    headers: { Authorization: `Bearer ${loginBody.data.token}` }
  });

  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error, "Forbidden");
});

test("create task success", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const loginResponse = await login(ctx.baseUrl, "dev@demo.local", "Dev123!");
  const loginBody = await loginResponse.json();

  const response = await fetch(`${ctx.baseUrl}/tasks`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${loginBody.data.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ title: "Build CI pipeline" })
  });

  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.success, true);
  assert.equal(body.data.title, "Build CI pipeline");
  assert.equal(body.data.status, "open");
});

test("update task success", async (t) => {
  const ctx = await setupApp();
  t.after(async () => {
    await ctx.close();
  });

  const loginResponse = await login(ctx.baseUrl, "dev@demo.local", "Dev123!");
  const loginBody = await loginResponse.json();
  const token = loginBody.data.token;

  const createResponse = await fetch(`${ctx.baseUrl}/tasks`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ title: "Implement feature" })
  });
  const created = await createResponse.json();

  const patchResponse = await fetch(`${ctx.baseUrl}/tasks/${created.data.id}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ status: "done" })
  });

  assert.equal(patchResponse.status, 200);
  const patched = await patchResponse.json();
  assert.equal(patched.success, true);
  assert.equal(patched.data.status, "done");
});
