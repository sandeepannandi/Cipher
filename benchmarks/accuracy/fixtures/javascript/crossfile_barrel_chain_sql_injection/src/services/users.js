const db = require('../db');

function findByName(name) {
    const sql = `SELECT id, name FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

module.exports = { findByName };
