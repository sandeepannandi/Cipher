const express = require('express');
const { execFile } = require('child_process');

const router = express.Router();

router.get('/ping', (req, res) => {
    const target = req.query.host;
    execFile('ping', ['-c', '1', target], (err, stdout) => res.send(stdout));
});

module.exports = router;
