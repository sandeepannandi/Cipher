const { findByName } = require('./a');
const { findByName } = require('./b');

function byName(name) {
    return findByName(name);
}

module.exports = { byName };
