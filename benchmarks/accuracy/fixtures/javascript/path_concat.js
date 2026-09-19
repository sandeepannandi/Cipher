const fs = require("fs");
function load(name) {
  return fs.readFile("./uploads/" + name, () => {});
}
