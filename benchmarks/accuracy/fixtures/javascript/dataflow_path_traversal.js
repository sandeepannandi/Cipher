const fs = require("fs");

function download(req, res) {
  const filename = req.query.filename;
  const requestedPath = "/srv/downloads/" + filename;
  fs.createReadStream(requestedPath).pipe(res);
}
