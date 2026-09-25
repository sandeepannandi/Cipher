const express = require('express');
const gateway = require('../services/gateway');

const router = express.Router();

router.get('/users/search', (req, res) => {
    const { name } = req.query;
    return res.json(gateway.byName(name));
});

module.exports = router;
