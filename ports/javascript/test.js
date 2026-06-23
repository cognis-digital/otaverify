// Smoke test for the JS port. Run: node ports/javascript/test.js
// Stdlib only (node:assert, node:crypto). Exits non-zero on first failure.
import assert from "assert";
import { createHmac, createHash } from "crypto";
import { canonical, verify } from "./index.js";

function sign(secret, payload) {
  const key = Buffer.from(secret, "hex");
  return createHmac("sha256", key).update(payload).digest("hex");
}

function basePkg() {
  const keys = {
    "vendor-a": "00112233445566778899aabbccddeeff",
    "vendor-b": "ffeeddccbbaa99887766554433221100",
  };
  const raw = Buffer.from("abc");
  const manifest = {
    version: 12, counter: 12, expires: "2031-01-01T00:00:00Z",
    images: [{ name: "fw", sha256: createHash("sha256").update(raw).digest("hex"), size: 3 }],
  };
  const payload = Buffer.from(canonical(manifest), "utf8");
  return {
    root: { keys, threshold: 2 },
    manifest,
    device: { version: 11, counter: 11 },
    payloads: { fw: raw.toString("hex") },
    signatures: Object.entries(keys).map(([keyid, s]) => ({ keyid, sig: sign(s, payload) })),
  };
}

let n = 0;
function check(name, cond) { n++; assert.ok(cond, name); }

// canonical matches the Python reference output.
check("canonical sorts keys", canonical({ b: 1, a: 2 }) === '{"a":2,"b":1}');
check("canonical compact array", canonical([1, 2]) === "[1,2]");

check("valid package accepts", verify(basePkg()).ok === true);

let p = basePkg(); p.signatures[0].sig = "00";
check("bad signature rejected", verify(p).ok === false);

p = basePkg(); p.signatures = p.signatures.slice(0, 1);
check("threshold not met rejected", verify(p).ok === false);

p = basePkg(); p.manifest.version = 10;
p.signatures = Object.entries(p.root.keys).map(([keyid, s]) => ({ keyid, sig: sign(s, Buffer.from(canonical(p.manifest))) }));
check("downgrade blocked", verify(p).ok === false);

p = basePkg(); p.payloads.fw = "00";
check("payload tamper rejected", verify(p).ok === false);

p = basePkg(); p.manifest.expires = "2000-01-01T00:00:00Z";
p.signatures = Object.entries(p.root.keys).map(([keyid, s]) => ({ keyid, sig: sign(s, Buffer.from(canonical(p.manifest))) }));
check("expired manifest rejected", verify(p).ok === false);

console.log(`ok - ${n} assertions passed`);
