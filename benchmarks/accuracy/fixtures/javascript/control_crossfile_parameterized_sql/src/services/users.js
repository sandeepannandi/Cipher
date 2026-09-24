const db = require('../db');

function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').all(name);
}

module.exports = { findByName };
