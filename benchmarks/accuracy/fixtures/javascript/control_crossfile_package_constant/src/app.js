const dep = require('dep');

exports.run = (req, res) => {
    return res.json(dep.run('uptime'));
};
