function calcular(req) {
  // ruleid: multi/dangerous-function
  const r = eval(req.body.expr);
  // ok: multi/dangerous-function
  const d = JSON.parse(req.body.json);
  return [r, d];
}
