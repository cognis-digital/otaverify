package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sign(secret string, payload []byte) string {
	key, err := hex.DecodeString(secret)
	if err != nil {
		key = []byte(secret)
	}
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

func basePkg(t *testing.T) pkg {
	t.Helper()
	var p pkg
	p.Root.Keys = map[string]string{
		"vendor-a": "00112233445566778899aabbccddeeff",
		"vendor-b": "ffeeddccbbaa99887766554433221100",
	}
	p.Root.Threshold = 2
	raw := []byte("abc")
	sum := sha256.Sum256(raw)
	p.Manifest = map[string]any{
		"version": float64(12), "counter": float64(12),
		"expires": "2031-01-01T00:00:00Z",
		"images": []any{map[string]any{
			"name": "fw", "sha256": hex.EncodeToString(sum[:]), "size": float64(3),
		}},
	}
	p.Device = map[string]any{"version": float64(11), "counter": float64(11)}
	p.Payloads = map[string]string{"fw": hex.EncodeToString(raw)}
	payload := canonical(p.Manifest)
	p.Signatures = []map[string]string{
		{"keyid": "vendor-a", "sig": sign(p.Root.Keys["vendor-a"], payload)},
		{"keyid": "vendor-b", "sig": sign(p.Root.Keys["vendor-b"], payload)},
	}
	return p
}

func TestAccept(t *testing.T) {
	ok, _ := verify(basePkg(t))
	if !ok {
		t.Fatal("expected ACCEPT")
	}
}

func TestBadSignatureRejected(t *testing.T) {
	p := basePkg(t)
	p.Signatures[0]["sig"] = "00"
	if ok, _ := verify(p); ok {
		t.Fatal("expected REJECT for bad signature")
	}
}

func TestThresholdNotMet(t *testing.T) {
	p := basePkg(t)
	p.Signatures = p.Signatures[:1]
	if ok, _ := verify(p); ok {
		t.Fatal("expected REJECT for 1/2 threshold")
	}
}

func TestDowngradeBlocked(t *testing.T) {
	p := basePkg(t)
	p.Manifest["version"] = float64(10)
	p.Signatures[0]["sig"] = sign(p.Root.Keys["vendor-a"], canonical(p.Manifest))
	p.Signatures[1]["sig"] = sign(p.Root.Keys["vendor-b"], canonical(p.Manifest))
	if ok, _ := verify(p); ok {
		t.Fatal("expected REJECT for downgrade")
	}
}

func TestPayloadTamper(t *testing.T) {
	p := basePkg(t)
	p.Payloads["fw"] = "00"
	if ok, _ := verify(p); ok {
		t.Fatal("expected REJECT for tampered payload")
	}
}

func TestExpired(t *testing.T) {
	p := basePkg(t)
	p.Manifest["expires"] = "2000-01-01T00:00:00Z"
	p.Signatures[0]["sig"] = sign(p.Root.Keys["vendor-a"], canonical(p.Manifest))
	p.Signatures[1]["sig"] = sign(p.Root.Keys["vendor-b"], canonical(p.Manifest))
	if ok, _ := verify(p); ok {
		t.Fatal("expected REJECT for expired manifest")
	}
}
