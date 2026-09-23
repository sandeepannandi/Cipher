const express = require('express');

const router = express.Router();

router.get('/preview', async (req, res) => {
    const target = req.query.url;
    const endpoint = `${target}/status`;
    const resp = await fetch(endpoint);
    res.send(await resp.text());
});

module.exports = router;
