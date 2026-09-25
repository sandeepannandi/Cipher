import db from '../db';

export default class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
