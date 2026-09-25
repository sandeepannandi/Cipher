const search = require('./search');

function byName(name) {
    return search.byName(name);
}

module.exports = { byName };
