// Caches the gate and the encrypted page so they open without a connection.
const CACHE = "gate-v2";
const FONTS = /^fonts\.(googleapis|gstatic)\.com$/;
self.addEventListener("install", e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(["./", "content.enc.json"])));
});
self.addEventListener("activate", e => e.waitUntil(
  caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim())));
const timeout = (ms, p) => Promise.race([p, new Promise((_, rej) => setTimeout(rej, ms))]);
const save = (req, res) => {
  if (res.ok || res.type === "opaque") { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }
  return res;
};
self.addEventListener("fetch", e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== "GET") return;
  const scope = new URL("./", self.registration.scope);
  if (url.origin === location.origin && url.pathname.startsWith(scope.pathname)) {
    // Fresh copy when the network answers quickly, cached copy otherwise.
    e.respondWith(timeout(4000, fetch(req)).then(res => save(req, res))
      .catch(() => caches.match(req, { ignoreSearch: true })
        .then(r => r || (req.mode === "navigate" ? caches.match("./") : Response.error()))));
  } else if (FONTS.test(url.hostname)) {
    e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => save(req, res))));
  }
});
