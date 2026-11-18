#!/usr/bin/env python3
"""Publish a standalone HTML page behind a PIN/password gate on a static site.

Writes three files into the output directory:
  index.html         the gate (tools/gate_template.html): asks for the code, checks it by decrypting
  content.enc.json   the page, encrypted (PBKDF2-SHA256 -> AES-256-GCM)
  sw.js              service worker so the unlocked page also opens offline

Images referenced as img/<name>.<ext> (relative to the source) are embedded
as data URIs before encryption, so they are never published in the clear.

Only ciphertext is published, so the output is safe to commit to a public
repo. Keep the plaintext source in .private/ (ignored by git).

Usage:
    python3 tools/encrypt_page.py .private/trip/index.html journey/yosequoia --title "根与石 · The Cathedral of Roots and Stone"
The PIN is read from $PAGE_PASSWORD, or prompted for if unset. An all-digit
password gets a numeric PIN pad; anything else gets a password field.
"""

import argparse
import base64
import getpass
import html
import json
import mimetypes
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000

SERVICE_WORKER = """// Caches the gate and the encrypted page so they open without a connection.
const CACHE = "gate-v2";
const FONTS = /^fonts\\.(googleapis|gstatic)\\.com$/;
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
"""

GATE_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate_template.html")


def inline_images(page: bytes, base_dir: str) -> bytes:
    """Replace img/<file> references with data URIs; warn about missing files."""
    found, missing = set(), set()

    def embed(m: re.Match) -> bytes:
        rel = m.group(0).decode()
        path = os.path.join(base_dir, rel)
        if not os.path.isfile(path):
            missing.add(rel)
            return m.group(0)
        found.add(rel)
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        return f"data:{mime};base64,{base64.b64encode(open(path, 'rb').read()).decode()}".encode()

    page = re.sub(rb"img/[A-Za-z0-9_.-]+\.(?:jpe?g|png|webp|gif|svg)", embed, page)
    if found:
        print(f"Embedded {len(found)} image(s).")
    if missing:
        print(f"Warning: {len(missing)} image(s) not found, left as links: {', '.join(sorted(missing))}")
    return page


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", help="plaintext HTML (keep it in .private/)")
    parser.add_argument("outdir", help="directory to publish, e.g. trip")
    parser.add_argument("--title", default="Private page", help="title shown on the gate (keep it non-revealing)")
    args = parser.parse_args()

    password = os.environ.get("PAGE_PASSWORD") or getpass.getpass("PIN or password: ")
    if "PAGE_PASSWORD" not in os.environ and getpass.getpass("Repeat: ") != password:
        sys.exit("They do not match.")
    if len(password) < 8:
        sys.exit("Use at least 8 characters: the ciphertext is public and can be attacked offline.")
    if len(password) < 12:
        print("Note: short PINs can be brute-forced offline by a determined attacker; fine for short-lived info.")

    plaintext = inline_images(open(args.source, "rb").read(), os.path.dirname(os.path.abspath(args.source)))
    salt, iv = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(iv, plaintext, None)
    assert AESGCM(derive_key(password, salt)).decrypt(iv, ciphertext, None) == plaintext

    pin_length = len(password) if password.isdigit() else 0
    input_attrs = f'inputmode="numeric" pattern="[0-9]*" maxlength="{pin_length}"' if pin_length else ""
    gate = (open(GATE_TEMPLATE, encoding="utf-8").read().replace("__TITLE__", html.escape(args.title))
                .replace("__PIN_LENGTH__", str(pin_length))
                .replace("__INPUT_ATTRS__", input_attrs))
    payload = {"version": 2, "iterations": ITERATIONS,
               **{k: base64.b64encode(v).decode() for k, v in {"salt": salt, "iv": iv, "data": ciphertext}.items()}}

    os.makedirs(args.outdir, exist_ok=True)
    for name, content in (("index.html", gate), ("content.enc.json", json.dumps(payload)), ("sw.js", SERVICE_WORKER)):
        with open(os.path.join(args.outdir, name), "w") as f:
            f.write(content)
    print(f"Wrote {args.outdir}/index.html, content.enc.json ({len(plaintext):,} bytes encrypted), sw.js.")


if __name__ == "__main__":
    main()
