const db = require('../db');

export default function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').all(name);
}
