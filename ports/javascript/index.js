#!/usr/bin/env node
// JavaScript/Node port of the otaverify core: verify an OTA package's
// HMAC-SHA256 signature quorum, anti-downgrade counters, expiry, and payload
// digests. Node stdlib only (crypto, fs). The canonical signing basis
// (sorted-key compact JSON) matches the Python reference byte-for-byte.
import { readFileSync } from "fs";
import { createHmac, createHash, timingSafeEqual } from "crypto";
import { pathToFileURL } from "url";

// Deterministic JSON: sorted keys, no whitespace (== Python json.dumps).
export function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}

function hmacHex(secret, payload) {
  let key;
  if (/^[0-9a-fA-F]+$/.test(secret) && secret.length % 2 === 0) {
    key = Buffer.from(secret, "hex");
  } else {
    key = Buffer.from(secret, "utf8");
  }
  return createHmac("sha256", key).update(payload).digest("hex");
}

function eq(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export function verify(pkg) {
  const findings = [];
  let errs = 0;
  const root = pkg.root || {};
  const keys = root.keys || {};
  const manifest = pkg.manifest || {};
  const device = pkg.device || {};
  const payload = Buffer.from(canonical(manifest), "utf8");

  const valid = new Set();
  for (const s of pkg.signatures || []) {
    if (!(s.keyid in keys)) {
      findings.push("WARN sig.unknown " + s.keyid);
      continue;
    }
    if (eq(hmacHex(keys[s.keyid], payload), s.sig || "")) {
      valid.add(s.keyid);
    } else {
      findings.push("FAIL sig.invalid " + s.keyid);
      errs++;
    }
  }
  const thr = Number.isInteger(root.threshold) && root.threshold >= 1 ? root.threshold : 1;
  if (valid.size < thr) {
    findings.push(`FAIL sig.threshold ${valid.size}/${thr}`);
    errs++;
  } else {
    findings.push(`ok   sig.threshold ${valid.size}/${thr}`);
  }

  if (manifest.expires) {
    const exp = new Date(manifest.expires);
    if (!isNaN(exp) && exp < new Date()) {
      findings.push("FAIL manifest.expiry " + manifest.expires);
      errs++;
    }
  }

  if (Number.isInteger(manifest.version) && Number.isInteger(device.version) &&
      manifest.version < device.version) {
    findings.push(`FAIL rollback.version ${manifest.version}<${device.version}`);
    errs++;
  }
  if (Number.isInteger(manifest.counter) && Number.isInteger(device.counter) &&
      manifest.counter < device.counter) {
    findings.push(`FAIL rollback.counter ${manifest.counter}<${device.counter}`);
    errs++;
  }

  const images = {};
  for (const im of manifest.images || []) if (im && im.name) images[im.name] = im;
  for (const [name, hexBytes] of Object.entries(pkg.payloads || {})) {
    const im = images[name];
    if (!im) { findings.push("FAIL payload.unknown " + name); errs++; continue; }
    let raw;
    try { raw = Buffer.from(hexBytes, "hex"); } catch { findings.push("FAIL payload.encoding " + name); errs++; continue; }
    const got = createHash("sha256").update(raw).digest("hex");
    if (got !== String(im.sha256 || "").toLowerCase()) {
      findings.push("FAIL payload.digest " + name); errs++;
    } else {
      findings.push("ok   payload.digest " + name);
    }
  }
  return { ok: errs === 0, findings };
}

function main(argv) {
  if (argv.length < 2 || argv[0] !== "verify") {
    process.stderr.write("usage: otaverify verify <package.json>\n");
    process.exit(2);
  }
  const pkg = JSON.parse(readFileSync(argv[1], "utf8"));
  const { ok, findings } = verify(pkg);
  process.stdout.write(`OTA package: ${argv[1]}\nVerdict    : ${ok ? "ACCEPT" : "REJECT"}\n\n`);
  for (const f of findings) process.stdout.write("  " + f + "\n");
  process.exit(ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
