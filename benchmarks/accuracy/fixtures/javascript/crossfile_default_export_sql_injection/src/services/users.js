const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id, name FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}
