const express = require('express');
const search = require('../services/search');

const router = express.Router();

router.get('/users/search', (req, res) => {
    const { name } = req.query;
    return res.json(search.byName(name));
});

module.exports = router;
