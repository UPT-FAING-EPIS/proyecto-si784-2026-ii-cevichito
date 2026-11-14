const child_process = require("child_process");
function run(req) {
  // ruleid: multi/command-injection
  child_process.exec("ls " + req.query.dir);
}
