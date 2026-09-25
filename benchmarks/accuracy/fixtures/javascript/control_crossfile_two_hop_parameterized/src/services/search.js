const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };
