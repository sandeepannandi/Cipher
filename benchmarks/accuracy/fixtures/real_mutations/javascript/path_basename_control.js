// Paired safe control: basename removes directory components before construction.
const fs = require('fs');
const path = require('path');

function getFile(req, callback) {
  const requested = path.basename(req.query.file);
  const uploadRoot = path.join(__dirname, 'uploads');
  const target = path.resolve(uploadRoot, requested);
  fs.readFile(target, 'utf8', callback);
}

module.exports = { getFile };
