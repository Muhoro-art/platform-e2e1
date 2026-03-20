const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');

async function login(agent, username, password) {
  const response = await agent.post('/auth/login').send({ username, password });
  assert.equal(response.statusCode, 200);
  return response.body.token;
}

test('health and metrics endpoints are available', async () => {
  const app = createApp({ dbPath: ':memory:' });
  await app.locals.ready;
  const agent = request(app);

  const health = await agent.get('/health');
  assert.equal(health.statusCode, 200);
  assert.equal(health.body.status, 'ok');

  const metrics = await agent.get('/metrics');
  assert.equal(metrics.statusCode, 200);
  assert.match(metrics.text, /logins_total/);

  await app.locals.database.close();
});

test('auth, tasks, admin RBAC and auditing work', async () => {
  const app = createApp({ dbPath: ':memory:' });
  await app.locals.ready;
  const agent = request(app);

  const userToken = await login(agent, 'user', 'user123');
  const adminToken = await login(agent, 'admin', 'admin123');

  const createTask = await agent
    .post('/tasks')
    .set('Authorization', `Bearer ${userToken}`)
    .send({ title: 'Write tests' });
  assert.equal(createTask.statusCode, 201);
  assert.equal(createTask.body.task.title, 'Write tests');

  const updateTask = await agent
    .patch(`/tasks/${createTask.body.task.id}`)
    .set('Authorization', `Bearer ${userToken}`)
    .send({ status: 'done' });
  assert.equal(updateTask.statusCode, 200);
  assert.equal(updateTask.body.task.status, 'done');

  const forbiddenAdmin = await agent.get('/admin/users').set('Authorization', `Bearer ${userToken}`);
  assert.equal(forbiddenAdmin.statusCode, 403);

  const adminUsers = await agent.get('/admin/users').set('Authorization', `Bearer ${adminToken}`);
  assert.equal(adminUsers.statusCode, 200);
  assert.ok(adminUsers.body.users.some((user) => user.username === 'admin'));

  const listTasks = await agent.get('/tasks').set('Authorization', `Bearer ${userToken}`);
  assert.equal(listTasks.statusCode, 200);
  assert.equal(listTasks.body.tasks.length, 1);

  const logs = await app.locals.database.all('SELECT action FROM audit_logs ORDER BY id ASC');
  assert.deepEqual(logs.map((entry) => entry.action), [
    'login',
    'login',
    'task_create',
    'task_update',
    'admin_access'
  ]);

  await app.locals.database.close();
});
