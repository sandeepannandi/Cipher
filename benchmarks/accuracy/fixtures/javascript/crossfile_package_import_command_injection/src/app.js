const dep = require('dep');

exports.run = (req, res) => {
    const { cmd } = req.query;
    return res.json(dep.run(cmd));
};
