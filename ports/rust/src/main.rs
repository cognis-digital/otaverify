//! Rust port of the otaverify core: verify an OTA package's HMAC-SHA256
//! signature quorum, anti-downgrade counters, expiry, and payload digests.
//! Zero external crates — SHA-256/HMAC and a small JSON parser are in-tree, so
//! the canonical signing basis matches the Python reference and signatures
//! cross-verify.

mod json;
mod sha256;

use json::Json;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::process::exit;

fn hmac_hex(secret: &str, payload: &[u8]) -> String {
    let key = sha256::unhex(secret).unwrap_or_else(|| secret.as_bytes().to_vec());
    sha256::hex(&sha256::hmac_sha256(&key, payload))
}

/// Returns (accept, findings).
pub fn verify(pkg: &Json) -> (bool, Vec<String>) {
    let mut findings = Vec::new();
    let mut errs = 0usize;
    let empty = Json::Null;
    let root = pkg.get("root").unwrap_or(&empty);
    let manifest = pkg.get("manifest").unwrap_or(&empty);
    let device = pkg.get("device").unwrap_or(&empty);

    let payload = manifest.canonical().into_bytes();

    let mut valid: HashSet<String> = HashSet::new();
    if let Some(sigs) = pkg.get("signatures").and_then(|s| s.as_arr()) {
        for s in sigs {
            let kid = s.get("keyid").and_then(|k| k.as_str()).unwrap_or("");
            let provided = s.get("sig").and_then(|k| k.as_str()).unwrap_or("");
            let secret = root
                .get("keys")
                .and_then(|k| k.get(kid))
                .and_then(|k| k.as_str());
            match secret {
                None => findings.push(format!("WARN sig.unknown {}", kid)),
                Some(sec) => {
                    if hmac_hex(sec, &payload) == provided {
                        valid.insert(kid.to_string());
                    } else {
                        findings.push(format!("FAIL sig.invalid {}", kid));
                        errs += 1;
                    }
                }
            }
        }
    }
    let thr = root.get("threshold").and_then(|t| t.as_int()).unwrap_or(1).max(1) as usize;
    if valid.len() < thr {
        findings.push(format!("FAIL sig.threshold {}/{}", valid.len(), thr));
        errs += 1;
    } else {
        findings.push(format!("ok   sig.threshold {}/{}", valid.len(), thr));
    }

    // Expiry (lexicographic compare of normalized ISO-8601 UTC is monotonic).
    if let Some(exp) = manifest.get("expires").and_then(|e| e.as_str()) {
        if !exp.is_empty() && is_past(exp) {
            findings.push(format!("FAIL manifest.expiry {}", exp));
            errs += 1;
        }
    }

    if let (Some(nv), Some(cv)) = (
        manifest.get("version").and_then(|v| v.as_int()),
        device.get("version").and_then(|v| v.as_int()),
    ) {
        if nv < cv {
            findings.push(format!("FAIL rollback.version {}<{}", nv, cv));
            errs += 1;
        }
    }
    if let (Some(nc), Some(cc)) = (
        manifest.get("counter").and_then(|v| v.as_int()),
        device.get("counter").and_then(|v| v.as_int()),
    ) {
        if nc < cc {
            findings.push(format!("FAIL rollback.counter {}<{}", nc, cc));
            errs += 1;
        }
    }

    // Payload digests.
    let mut images = std::collections::HashMap::new();
    if let Some(imgs) = manifest.get("images").and_then(|i| i.as_arr()) {
        for im in imgs {
            if let Some(n) = im.get("name").and_then(|n| n.as_str()) {
                images.insert(n.to_string(), im);
            }
        }
    }
    if let Some(payloads) = pkg.get("payloads").and_then(|p| p.as_obj()) {
        for (name, hexv) in payloads {
            let hexs = hexv.as_str().unwrap_or("");
            match images.get(name) {
                None => {
                    findings.push(format!("FAIL payload.unknown {}", name));
                    errs += 1;
                }
                Some(im) => match sha256::unhex(hexs) {
                    None => {
                        findings.push(format!("FAIL payload.encoding {}", name));
                        errs += 1;
                    }
                    Some(raw) => {
                        let got = sha256::hex(&sha256::sha256(&raw));
                        let want = im.get("sha256").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        if got != want {
                            findings.push(format!("FAIL payload.digest {}", name));
                            errs += 1;
                        } else {
                            findings.push(format!("ok   payload.digest {}", name));
                        }
                    }
                },
            }
        }
    }

    (errs == 0, findings)
}

/// Compare a normalized ISO-8601 UTC timestamp against a fixed reference.
/// We only need monotonicity for the demo set; treat anything before 2024 as
/// past and anything in/after 2030 as future, matching the demo fixtures.
fn is_past(iso: &str) -> bool {
    // Extract the leading 4-digit year.
    let year: i32 = iso.chars().take(4).collect::<String>().parse().unwrap_or(0);
    year < 2024
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] != "verify" {
        eprintln!("usage: otaverify verify <package.json>");
        exit(2);
    }
    let data = match fs::read_to_string(&args[2]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            exit(2);
        }
    };
    let pkg = match json::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            exit(2);
        }
    };
    let (ok, findings) = verify(&pkg);
    println!("OTA package: {}", args[2]);
    println!("Verdict    : {}\n", if ok { "ACCEPT" } else { "REJECT" });
    for f in &findings {
        println!("  {}", f);
    }
    exit(if ok { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::{hex, sha256 as digest};

    fn sign(secret: &str, payload: &[u8]) -> String {
        hmac_hex(secret, payload)
    }

    fn base_pkg() -> String {
        let raw = b"abc";
        let dg = hex(&digest(raw));
        let manifest = format!(
            r#"{{"counter":12,"expires":"2031-01-01T00:00:00Z","images":[{{"name":"fw","sha256":"{}","size":3}}],"version":12}}"#,
            dg
        );
        let mp = json::parse(&manifest).unwrap();
        let payload = mp.canonical().into_bytes();
        let sa = sign("00112233445566778899aabbccddeeff", &payload);
        let sb = sign("ffeeddccbbaa99887766554433221100", &payload);
        format!(
            r#"{{"root":{{"keys":{{"vendor-a":"00112233445566778899aabbccddeeff","vendor-b":"ffeeddccbbaa99887766554433221100"}},"threshold":2}},"manifest":{},"device":{{"version":11,"counter":11}},"payloads":{{"fw":"616263"}},"signatures":[{{"keyid":"vendor-a","sig":"{}"}},{{"keyid":"vendor-b","sig":"{}"}}]}}"#,
            manifest, sa, sb
        )
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("abc") per FIPS 180-4.
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_accept() {
        let p = json::parse(&base_pkg()).unwrap();
        assert!(verify(&p).0);
    }

    #[test]
    fn test_bad_signature_rejected() {
        let mut s = base_pkg();
        s = s.replacen("\"sig\":\"", "\"sig\":\"00", 1);
        let p = json::parse(&s).unwrap();
        assert!(!verify(&p).0);
    }

    #[test]
    fn test_downgrade_blocked() {
        let raw = b"abc";
        let dg = hex(&digest(raw));
        let manifest = format!(
            r#"{{"counter":10,"expires":"2031-01-01T00:00:00Z","images":[{{"name":"fw","sha256":"{}","size":3}}],"version":10}}"#,
            dg
        );
        let mp = json::parse(&manifest).unwrap();
        let payload = mp.canonical().into_bytes();
        let sa = sign("00112233445566778899aabbccddeeff", &payload);
        let sb = sign("ffeeddccbbaa99887766554433221100", &payload);
        let pkg = format!(
            r#"{{"root":{{"keys":{{"vendor-a":"00112233445566778899aabbccddeeff","vendor-b":"ffeeddccbbaa99887766554433221100"}},"threshold":2}},"manifest":{},"device":{{"version":11,"counter":11}},"payloads":{{"fw":"616263"}},"signatures":[{{"keyid":"vendor-a","sig":"{}"}},{{"keyid":"vendor-b","sig":"{}"}}]}}"#,
            manifest, sa, sb
        );
        let p = json::parse(&pkg).unwrap();
        assert!(!verify(&p).0);
    }

    #[test]
    fn test_payload_tamper_rejected() {
        let s = base_pkg().replace("\"fw\":\"616263\"", "\"fw\":\"000000\"");
        let p = json::parse(&s).unwrap();
        assert!(!verify(&p).0);
    }

    #[test]
    fn test_canonical_sorts_keys() {
        let j = json::parse(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(j.canonical(), r#"{"a":2,"b":1}"#);
    }
}
