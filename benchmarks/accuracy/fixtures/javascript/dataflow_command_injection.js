const express = require('express');
const { exec } = require('child_process');

const router = express.Router();

router.get('/ping', (req, res) => {
    const target = req.query.host;
    const cmd = 'ping -c 1 ' + target;
    exec(cmd, (err, stdout) => res.send(stdout));
});

module.exports = router;
