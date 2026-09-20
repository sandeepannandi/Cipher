const fs = require("fs");
const path = require("path");

function download(req, res) {
  const requested = req.query.filename;
  const safeName = path.basename(requested);
  const safePath = path.join("/srv/downloads", safeName);
  fs.createReadStream(safePath).pipe(res);
}
