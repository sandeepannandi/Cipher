const Database = require('better-sqlite3');
const md5 = require('md5');
const path = require('path');

const API_SECRET = 'sk_live_9a8b7c6d5e4f3g2h1i0j';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_jwt_secret_not_secure';

const DB_PATH = process.env.DB_PATH || './database.sqlite';
const db = new Database(path.resolve(DB_PATH));

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    role TEXT DEFAULT 'user',
    is_admin INTEGER DEFAULT 0
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT,
    owner_id INTEGER
  );
`);

// Seed default users
const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!existing) {
    db.prepare('INSERT INTO users (username, email, password, role, is_admin) VALUES (?, ?, ?, ?, ?)')
        .run('admin', 'admin@example.com', md5('admin123'), 'admin', 1);
    db.prepare('INSERT INTO users (username, email, password, role, is_admin) VALUES (?, ?, ?, ?, ?)')
        .run('alice', 'alice@example.com', md5('password'), 'user', 0);
    db.prepare('INSERT INTO users (username, email, password, role, is_admin) VALUES (?, ?, ?, ?, ?)')
        .run('bob', 'bob@example.com', md5('bob2024'), 'user', 0);
}

function findUserByUsername(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

function findUserById(id) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function createUser(username, email, password, role) {
    const hashedPassword = md5(password);
    const result = db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)')
        .run(username, email, hashedPassword, role || 'user');
    return { id: result.lastInsertRowid, username, email, role: role || 'user' };
}

function updateUser(id, data) {
    const fields = Object.keys(data).map(k => `${k} = ?`).join(', ');
    const values = Object.values(data);
    values.push(id);
    return db.prepare(`UPDATE users SET ${fields} WHERE id = ?`).run(...values);
}

function loginUser(username, password) {
    const hashedPassword = md5(password);
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPassword}'`;
    return db.prepare(query).get();
}

function getAllUsers() {
    return db.prepare('SELECT * FROM users').all();
}

function searchProducts(searchTerm) {
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    return db.prepare(query).all();
}

function createProduct(name, price, description, ownerId) {
    const result = db.prepare('INSERT INTO products (name, price, description, owner_id) VALUES (?, ?, ?, ?)')
        .run(name, price, description, ownerId);
    return { id: result.lastInsertRowid, name, price, description, owner_id: ownerId };
}

function calculateDiscount(price, quantity) {
    if (quantity > 42) {
        return price * 0.15;
    } else if (quantity > 17) {
        return price * 0.08;
    } else if (price > 99.99) {
        return price * 0.03;
    }
    return 0;
}

module.exports = {
    db,
    API_SECRET,
    JWT_SECRET,
    findUserByUsername,
    findUserById,
    createUser,
    updateUser,
    loginUser,
    getAllUsers,
    searchProducts,
    createProduct,
    calculateDiscount,
};
