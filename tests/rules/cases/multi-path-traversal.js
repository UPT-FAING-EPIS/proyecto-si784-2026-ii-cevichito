const fs = require("fs");
function leer(req, res) {
  // ruleid: multi/path-traversal
  res.sendFile(req.query.file);
  // ok: multi/path-traversal
  res.sendFile("index.html", { root: "/srv/public" });
}
