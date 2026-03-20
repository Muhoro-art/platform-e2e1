const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const HASH_ALGORITHM = 'sha256';
const HASH_ITERATIONS = 100000;
const HASH_KEYLEN = 64;

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEYLEN, HASH_ALGORITHM)
    .toString('hex');
  return `${salt}:${derivedKey}`;
}

function ensureDirectory(dbPath) {
  if (dbPath === ':memory:') {
    return;
  }
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}

function createDatabase(dbPath = path.join(__dirname, '..', 'data', 'app.db')) {
  ensureDirectory(dbPath);
  const db = new sqlite3.Database(dbPath);

  const run = (sql, params = []) =>
    new Promise((resolve, reject) => {
      db.run(sql, params, function runCallback(error) {
        if (error) {
          reject(error);
          return;
        }
        resolve(this);
      });
    });

  const get = (sql, params = []) =>
    new Promise((resolve, reject) => {
      db.get(sql, params, (error, row) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(row);
      });
    });

  const all = (sql, params = []) =>
    new Promise((resolve, reject) => {
      db.all(sql, params, (error, rows) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(rows);
      });
    });

  const close = () =>
    new Promise((resolve, reject) => {
      db.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });

  return { db, run, get, all, close };
}

async function initializeSchema(database) {
  await database.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`);
  await database.run(`CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    )`);
  await database.run(`CREATE TABLE IF NOT EXISTS user_roles (
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (role_id) REFERENCES roles(id)
    )`);
  await database.run(`CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      created_by INTEGER,
      updated_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users(id),
      FOREIGN KEY (updated_by) REFERENCES users(id)
    )`);
  await database.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      user_id INTEGER,
      details TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

  await database.run("INSERT OR IGNORE INTO roles (id, name) VALUES (1, 'admin')");
  await database.run("INSERT OR IGNORE INTO roles (id, name) VALUES (2, 'user')");

  await database.run('INSERT OR IGNORE INTO users (id, username, password) VALUES (?, ?, ?)', [
    1,
    'admin',
    hashPassword('admin123')
  ]);
  await database.run('INSERT OR IGNORE INTO users (id, username, password) VALUES (?, ?, ?)', [
    2,
    'user',
    hashPassword('user123')
  ]);

  await database.run('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (1, 1)');
  await database.run('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (2, 2)');

  const existingUsers = await database.all('SELECT id, password FROM users');
  for (const user of existingUsers) {
    if (!user.password.includes(':')) {
      await database.run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(user.password), user.id]);
    }
  }
}

module.exports = {
  createDatabase,
  initializeSchema,
  hashPassword
};
