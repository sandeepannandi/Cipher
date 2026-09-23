const express = require('express');

const router = express.Router();

router.get('/search', async (req, res) => {
    const term = req.query.q;
    const resp = await fetch('https://api.example.com/search', { method: 'POST', body: term });
    res.send(await resp.text());
});

module.exports = router;
