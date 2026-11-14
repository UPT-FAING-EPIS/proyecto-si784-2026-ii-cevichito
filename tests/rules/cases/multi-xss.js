function render(el, html) {
  // ruleid: multi/xss
  el.innerHTML = html;
  // ok: multi/xss
  el.textContent = html;
}
