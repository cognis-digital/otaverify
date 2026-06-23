// Go port of the otaverify core: verify an OTA package's HMAC-SHA256 signature
// quorum, anti-downgrade counters, expiry, and payload digests. Zero deps,
// stdlib only. The canonical signing basis (sorted-key compact JSON) is
// byte-for-byte identical to the Python reference, so signatures cross-verify.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type pkg struct {
	Root struct {
		Keys      map[string]string `json:"keys"`
		Threshold int               `json:"threshold"`
	} `json:"root"`
	Manifest   map[string]any      `json:"manifest"`
	Signatures []map[string]string `json:"signatures"`
	Device     map[string]any      `json:"device"`
	Payloads   map[string]string   `json:"payloads"`
}

// canonical re-encodes a value as sorted-key, compact JSON (matches Python's
// json.dumps(sort_keys=True, separators=(",",":"))).
func canonical(v any) []byte {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.Write(canonical(t[k]))
		}
		b.WriteByte('}')
		return []byte(b.String())
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(canonical(e))
		}
		b.WriteByte(']')
		return []byte(b.String())
	default:
		out, _ := json.Marshal(v)
		return out
	}
}

func hmacHex(secret string, payload []byte) string {
	key, err := hex.DecodeString(secret)
	if err != nil {
		key = []byte(secret)
	}
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

func asInt(v any) (int, bool) {
	f, ok := v.(float64)
	return int(f), ok
}

// verify returns (accept, findings).
func verify(p pkg) (bool, []string) {
	var f []string
	errs := 0
	payload := canonical(p.Manifest)

	valid := map[string]bool{}
	for _, s := range p.Signatures {
		kid := s["keyid"]
		secret, known := p.Root.Keys[kid]
		if !known {
			f = append(f, "WARN sig.unknown "+kid)
			continue
		}
		if hmac.Equal([]byte(hmacHex(secret, payload)), []byte(s["sig"])) {
			valid[kid] = true
		} else {
			f = append(f, "FAIL sig.invalid "+kid)
			errs++
		}
	}
	thr := p.Root.Threshold
	if thr < 1 {
		thr = 1
	}
	if len(valid) < thr {
		f = append(f, fmt.Sprintf("FAIL sig.threshold %d/%d", len(valid), thr))
		errs++
	} else {
		f = append(f, fmt.Sprintf("ok   sig.threshold %d/%d", len(valid), thr))
	}

	if exp, ok := p.Manifest["expires"].(string); ok && exp != "" {
		t, err := time.Parse(time.RFC3339, strings.Replace(exp, "Z", "+00:00", 1))
		if err == nil && t.Before(time.Now()) {
			f = append(f, "FAIL manifest.expiry "+exp)
			errs++
		}
	}

	nv, okN := asInt(p.Manifest["version"])
	cv, okC := asInt(p.Device["version"])
	if okN && okC && nv < cv {
		f = append(f, fmt.Sprintf("FAIL rollback.version %d<%d", nv, cv))
		errs++
	}
	nc, okNC := asInt(p.Manifest["counter"])
	dc, okDC := asInt(p.Device["counter"])
	if okNC && okDC && nc < dc {
		f = append(f, fmt.Sprintf("FAIL rollback.counter %d<%d", nc, dc))
		errs++
	}

	images := map[string]map[string]any{}
	if imgs, ok := p.Manifest["images"].([]any); ok {
		for _, ii := range imgs {
			if im, ok := ii.(map[string]any); ok {
				if n, ok := im["name"].(string); ok {
					images[n] = im
				}
			}
		}
	}
	for name, hexBytes := range p.Payloads {
		im, ok := images[name]
		if !ok {
			f = append(f, "FAIL payload.unknown "+name)
			errs++
			continue
		}
		raw, err := hex.DecodeString(hexBytes)
		if err != nil {
			f = append(f, "FAIL payload.encoding "+name)
			errs++
			continue
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		want, _ := im["sha256"].(string)
		if got != strings.ToLower(want) {
			f = append(f, "FAIL payload.digest "+name)
			errs++
		} else {
			f = append(f, "ok   payload.digest "+name)
		}
	}
	return errs == 0, f
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: otaverify verify <package.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	var p pkg
	if err := json.Unmarshal(data, &p); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	ok, findings := verify(p)
	verdict := "REJECT"
	if ok {
		verdict = "ACCEPT"
	}
	fmt.Printf("OTA package: %s\nVerdict    : %s\n\n", os.Args[2], verdict)
	for _, line := range findings {
		fmt.Println("  " + line)
	}
	if !ok {
		os.Exit(1)
	}
}
