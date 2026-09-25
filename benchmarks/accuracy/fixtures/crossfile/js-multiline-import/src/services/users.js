const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

module.exports = { findByName };
