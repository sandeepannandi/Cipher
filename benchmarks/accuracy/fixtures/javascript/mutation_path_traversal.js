const fs = require("fs");
const path = require("path");

function download(request, response) {
  const segment = request.params.asset;
  const alias = segment;
  const requestedPath = path.resolve("/srv/assets", alias);
  response.sendFile(requestedPath);
}
