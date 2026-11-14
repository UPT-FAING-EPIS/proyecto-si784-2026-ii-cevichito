const crypto = require("crypto");
// ruleid: multi/weak-hash
const h = crypto.createHash("md5").update("x").digest("hex");
// ok: multi/weak-hash
const ok = crypto.createHash("sha256").update("x").digest("hex");
