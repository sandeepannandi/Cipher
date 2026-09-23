const express = require('express');
const db = require('./db');

const router = express.Router();

router.get('/products', (req, res) => {
    const { name } = req.query;
    const sql = 'SELECT id, price FROM products WHERE name = ?';
    db.query(sql, [name], (err, rows) => res.json(rows));
});

module.exports = router;
