const express = require('express');
const users = require('../services/users');

const router = express.Router();

router.get('/users/search', (req, res) => {
    const { name } = req.query;
    return res.json(users.findByName(name));
});

module.exports = router;
