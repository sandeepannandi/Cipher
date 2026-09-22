// Semantics-preserving mutation of vulnerable-node-api path traversal.
const fs = require('fs');
const path = require('path');

function getFile(req, callback) {
  const requested = req.query.file;
  const uploadRoot = path.join(__dirname, 'uploads');
  const target = path.resolve(uploadRoot, requested);
  fs.readFile(target, 'utf8', callback);
}

module.exports = { getFile };
