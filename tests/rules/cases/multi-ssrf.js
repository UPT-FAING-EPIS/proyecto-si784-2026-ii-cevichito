async function proxy(req) {
  // ruleid: multi/ssrf
  const r = await fetch(req.query.url);
  // ok: multi/ssrf
  const s = await fetch("https://api.example.com/status");
  return [r, s];
}
