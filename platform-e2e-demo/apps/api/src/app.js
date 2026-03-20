const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { createDatabase, initializeSchema, hashPassword } = require('./db');

function createApp(options = {}) {
  const metrics = { logins: 0, taskCreates: 0, taskUpdates: 0, adminAccess: 0 };
  const tokens = new Map();
  const dbPath = options.dbPath || process.env.DB_PATH || path.join(__dirname, '..', 'data', 'app.db');
  const database = createDatabase(dbPath);

  const app = express();
  app.use(express.json());

  const ready = initializeSchema(database);

  const writeAudit = async (action, userId, details) => {
    await database.run('INSERT INTO audit_logs (action, user_id, details) VALUES (?, ?, ?)', [
      action,
      userId || null,
      details || null
    ]);
  };

  const requireAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token || !tokens.has(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = tokens.get(token);
    const user = await database.get('SELECT id, username FROM users WHERE id = ?', [userId]);
    const roleRows = await database.all(
      `SELECT roles.name FROM roles
       INNER JOIN user_roles ON user_roles.role_id = roles.id
       WHERE user_roles.user_id = ?`,
      [userId]
    );

    req.user = { ...user, roles: roleRows.map((item) => item.name) };
    return next();
  };

  const requireRole = (role) => async (req, res, next) => {
    if (!req.user || !req.user.roles.includes(role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };

  app.get('/health', async (_req, res) => {
    await ready;
    res.json({ status: 'ok' });
  });

  app.get('/metrics', async (_req, res) => {
    await ready;
    res.type('text/plain').send(
      `logins_total ${metrics.logins}\ntask_create_total ${metrics.taskCreates}\ntask_update_total ${metrics.taskUpdates}\nadmin_access_total ${metrics.adminAccess}`
    );
  });

  app.post('/auth/login', async (req, res) => {
    await ready;
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const userRecord = await database.get('SELECT id, username, password FROM users WHERE username = ?', [username]);
    const user = userRecord && userRecord.password === hashPassword(password, userRecord.password.split(':')[0])
      ? { id: userRecord.id, username: userRecord.username }
      : null;

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const roleRows = await database.all(
      `SELECT roles.name FROM roles
       INNER JOIN user_roles ON user_roles.role_id = roles.id
       WHERE user_roles.user_id = ?`,
      [user.id]
    );

    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, user.id);
    metrics.logins += 1;
    await writeAudit('login', user.id, `User ${user.username} logged in`);

    return res.json({ token, user: { id: user.id, username: user.username, roles: roleRows.map((item) => item.name) } });
  });

  app.get('/auth/me', requireAuth, (req, res) => {
    res.json({ user: req.user });
  });

  app.get('/tasks', requireAuth, async (_req, res) => {
    await ready;
    const tasks = await database.all('SELECT id, title, status, created_by, updated_by, created_at, updated_at FROM tasks ORDER BY id ASC');
    res.json({ tasks });
  });

  app.post('/tasks', requireAuth, async (req, res) => {
    await ready;
    const { title, status } = req.body || {};
    if (!title) {
      return res.status(400).json({ error: 'title is required' });
    }

    const taskStatus = status || 'open';
    const result = await database.run(
      'INSERT INTO tasks (title, status, created_by, updated_by) VALUES (?, ?, ?, ?)',
      [title, taskStatus, req.user.id, req.user.id]
    );
    const task = await database.get(
      'SELECT id, title, status, created_by, updated_by, created_at, updated_at FROM tasks WHERE id = ?',
      [result.lastID]
    );

    metrics.taskCreates += 1;
    await writeAudit('task_create', req.user.id, `Created task ${task.id}`);
    return res.status(201).json({ task });
  });

  app.patch('/tasks/:id', requireAuth, async (req, res) => {
    await ready;
    const { title, status } = req.body || {};
    const currentTask = await database.get('SELECT id FROM tasks WHERE id = ?', [req.params.id]);

    if (!currentTask) {
      return res.status(404).json({ error: 'Task not found' });
    }

    await database.run(
      `UPDATE tasks
       SET title = COALESCE(?, title),
           status = COALESCE(?, status),
           updated_by = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [title || null, status || null, req.user.id, req.params.id]
    );

    const task = await database.get(
      'SELECT id, title, status, created_by, updated_by, created_at, updated_at FROM tasks WHERE id = ?',
      [req.params.id]
    );
    metrics.taskUpdates += 1;
    await writeAudit('task_update', req.user.id, `Updated task ${task.id}`);
    return res.json({ task });
  });

  app.get('/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
    await ready;
    const users = await database.all(
      `SELECT users.id, users.username, GROUP_CONCAT(roles.name) AS roles
       FROM users
       LEFT JOIN user_roles ON user_roles.user_id = users.id
       LEFT JOIN roles ON roles.id = user_roles.role_id
       GROUP BY users.id, users.username
       ORDER BY users.id ASC`
    );

    metrics.adminAccess += 1;
    await writeAudit('admin_access', req.user.id, 'Viewed admin users list');
    res.json({ users: users.map((user) => ({ ...user, roles: (user.roles || '').split(',').filter(Boolean) })) });
  });

  app.get('/deployment/status', async (_req, res) => {
    await ready;
    res.json({ lastPipelineResult: process.env.LAST_PIPELINE_RESULT || 'success' });
  });

  app.use(express.static(path.join(__dirname, '..', '..', 'web')));
  app.get('/', (_req, res) => {
    res.redirect('/signin.html');
  });

  app.locals.database = database;
  app.locals.ready = ready;

  return app;
}

module.exports = { createApp };
