const path = require("path");
function load(name) {
  const base = path.resolve("./uploads");
  const target = path.resolve(base, name);
  if (!target.startsWith(base + path.sep)) throw new Error("invalid path");
  return target;
}
