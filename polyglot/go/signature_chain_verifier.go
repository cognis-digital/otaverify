package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// Config holds verification parameters.
type Config struct {
	RootCertPath    string // Path to root certificate file
	IntermediatePath string // Path to intermediate certificate (optional, can be embedded in root)
	MinTimestamp    int64  // Minimum allowed timestamp for anti-downgrade
	MaxTimestamp    int64  // Maximum allowed timestamp
	RollbackLimit   uint32 // Max rollback counter value before considering downgrade
}

// Result represents the outcome of verification.
type Result struct {
	Valid           bool
	Error           error
	ChainDepth       int
	Timestamp        time.Time
	RollbackCounter  uint32
	VerifiedHash     string
	SignatureAlgo    crypto.Hash
	PublicKeySize    int
}

// CertificateChain represents a parsed certificate chain.
type CertificateChain struct {
	RootCert         *x509.Certificate
	IntermediateCert *x509.Certificate
	LeafCert         *x509.Certificate
	RootPublicKey    crypto.PublicKey
	IntermediatePub  crypto.PublicKey
}

// PackageManifest represents the OTA package manifest with metadata.
type PackageManifest struct {
	Name          string
	Version       string
	BuildID       string
	Timestamp     int64
	RollbackCount uint32
	PayloadHash   string
	SignatureData []byte
}

// Verifier is the main verification engine.
type Verifier struct {
	config    Config
	rootPool  *x509.CertPool
	intermediatePool *x509.CertPool
}

// NewVerifier creates a new OTA verifier with configuration.
func NewVerifier(cfg Config) (*Verifier, error) {
	v := &Verifier{config: cfg}

	// Load root certificate into pool
	if cfg.RootCertPath != "" {
		certData, err := os.ReadFile(cfg.RootCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root cert: %w", err)
		}

		block, _ := pem.Decode(certData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid PEM format in root certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate: %w", err)
		}

		v.rootPool = x509.NewCertPool()
		v.rootPool.AddCert(cert)
		v.rootPool.Certificates[0] = cert // Keep reference for later use

		// Extract root public key
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			v.rootPool.Key = pub
		} else if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			v.rootPool.Key = pub
		}
	}

	return v, nil
}

// VerifyChain validates the signature chain for an OTA package.
func (v *Verifier) VerifyChain(manifest *PackageManifest) (*Result, error) {
	if manifest == nil {
		return &Result{Valid: false, Error: fmt.Errorf("nil manifest provided")}, nil
	}

	result := &Result{}

	// Step 1: Parse and validate leaf certificate (package signature cert)
	leafCert, err := v.parseLeafCertificate(manifest.SignatureData)
	if err != nil {
		return result, err
	}

	// Step 2: Build the chain from leaf to root
	chain, err := v.buildChain(leafCert)
	if err != nil {
		result.Error = fmt.Errorf("failed to build certificate chain: %w", err)
		return result, err
	}

	// Step 3: Verify timestamp for anti-downgrade protection
	if err := v.verifyTimestamp(manifest.Timestamp); err != nil {
		result.Error = fmt.Errorf("timestamp verification failed: %w", err)
		return result, err
	}

	// Step 4: Check rollback counter to prevent downgrade attacks
	if err := v.verifyRollbackCounter(chain.LeafCert, manifest.RollbackCount); err != nil {
		result.Error = fmt.Errorf("rollback counter check failed: %w", err)
		return result, err
	}

	// Step 5: Verify payload hash integrity
	if err := v.verifyPayloadHash(manifest.PayloadHash, chain.LeafCert); err != nil {
		result.Error = fmt.Errorf("payload hash verification failed: %w", err)
		return result, err
	}

	// All checks passed
	result.Valid = true
	result.ChainDepth = 1 // Leaf cert only (intermediate embedded or root-only chain)
	result.Timestamp = time.Unix(manifest.Timestamp, 0).UTC()
	result.RollbackCounter = manifest.RollbackCount
	result.VerifiedHash = manifest.PayloadHash
	result.SignatureAlgo = crypto.SHA256

	return result, nil
}

// parseLeafCertificate parses the DER-encoded leaf certificate.
func (v *Verifier) parseLeafCertificate(derData []byte) (*x509.Certificate, error) {
	if len(derData) == 0 {
		return nil, fmt.Errorf("empty signature data")
	}

	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Validate basic properties of the leaf cert
	if !cert.IsCA {
		// This is expected for a leaf (package signature) cert
	} else if cert.BasicConstraintsValid && cert.BasicConstraints.CA {
		return nil, fmt.Errorf("leaf certificate should not be marked as CA")
	}

	return cert, nil
}

// buildChain constructs the verification chain from leaf to root.
func (v *Verifier) buildChain(leafCert *x509.Certificate) (*CertificateChain, error) {
	chain := &CertificateChain{
		LeafCert: leafCert,
	}

	// Check if we have a root certificate in our pool
	if v.rootPool != nil && len(v.rootPool.Certificates) > 0 {
		rootCert := v.rootPool.Certificates[0]
		
		// Verify the leaf cert was signed by this root (directly or via intermediate)
		opts := x509.VerifyOptions{
			DNSName:    "ota.verify", // Allow any DNS for OTA context
			Roots:      v.rootPool,
			KeyUsage:   x509.ExtendedKeyUsage{x509.ExtendedKeyUsageAny},
			CurrentTime: time.Unix(leafCert.NotBefore.Unix(), 0),
		}

		if _, err := leafCert.Verify(opts); err != nil {
			return nil, fmt.Errorf("chain verification failed: %w", err)
		}

		// Extract root public key for reference
		switch pub := rootCert.PublicKey.(type) {
		case *rsa.PublicKey:
			chain.RootPublicKey = pub
		case *ecdsa.PublicKey:
			chain.RootPublicKey = pub
		default:
			chain.RootPublicKey = rootCert.PublicKey
		}

		// If we have an intermediate certificate, add it to chain
		if v.intermediatePool != nil && len(v.intermediatePool.Certificates) > 0 {
			intermediate := v.intermediatePool.Certificates[0]
			
			// Verify leaf was signed by intermediate
			opts := x509.VerifyOptions{
				DNSName:    "ota.verify",
				Roots:      v.rootPool,
				KeyUsage:   x509.ExtendedKeyUsage{x509.ExtendedKeyUsageAny},
				CurrentTime: time.Unix(leafCert.NotBefore.Unix(), 0),
			}

			if _, err := leafCert.Verify(opts); err != nil {
				return nil, fmt.Errorf("intermediate chain verification failed: %w", err)
			}

			chain.IntermediateCert = intermediate
			switch pub := intermediate.PublicKey.(type) {
			case *rsa.PublicKey:
				chain.IntermediatePub = pub
			case *ecdsa.PublicKey:
				chain.IntermediatePub = pub
			default:
				chain.IntermediatePub = intermediate.PublicKey
			}

			// Verify intermediate was signed by root
			opts.Roots = v.rootPool
			if _, err := intermediate.Verify(opts); err != nil {
				return nil, fmt.Errorf("root-intermediate verification failed: %w", err)
			}
		}
	} else if v.rootPool == nil || len(v.rootPool.Certificates) == 0 {
		// No root pool - assume self-signed or embedded chain validation
		// Just verify the leaf cert itself is valid
		if _, err := leafCert.Verify(x509.VerifyOptions{
			DNSName:    "ota.verify",
			KeyUsage:   x509.ExtendedKeyUsage{x509.ExtendedKeyUsageAny},
			CurrentTime: time.Unix(leafCert.NotBefore.Unix(), 0),
		}); err != nil {
			return nil, fmt.Errorf("self-signed verification failed: %w", err)
		}

		switch pub := leafCert.PublicKey.(type) {
		case *rsa.PublicKey:
			chain.RootPublicKey = pub
		case *ecdsa.PublicKey:
			chain.RootPublicKey = pub
		default:
			chain.RootPublicKey = leafCert.PublicKey
		}
	}

	return chain, nil
}

// verifyTimestamp checks the timestamp for anti-downgrade protection.
func (v *Verifier) verifyTimestamp(timestamp int64) error {
	if v.config.MinTimestamp > 0 && timestamp < v.config.MinTimestamp {
		return fmt.Errorf("timestamp too old: %d < min %d", timestamp, v.config.MinTimestamp)
	}

	if v.config.MaxTimestamp > 0 && timestamp > v.config.MaxTimestamp {
		return fmt.Errorf("timestamp in future: %d > max %d", timestamp, v.config.MaxTimestamp)
	}

	// Check against current time to prevent replay attacks
	now := time.Now().Unix()
	timeDiff := now - timestamp
	
	if timeDiff < 0 && abs(timeDiff) > 3600 { // More than 1 hour in future
		return fmt.Errorf("timestamp appears to be from the future: %d hours ahead", int(-timeDiff)/3600)
	}

	if timeDiff > 86400*7 { // More than a week old
		return fmt.Errorf("timestamp too old for current deployment window")
	}

	return nil
}

// abs returns absolute value of int64.
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// verifyRollbackCounter checks the rollback counter to prevent downgrade attacks.
func (v *Verifier) verifyRollbackCounter(leafCert *x509.Certificate, manifestCount uint32) error {
	if leafCert == nil || manifestCount == 0 {
		return fmt.Errorf("missing certificate or zero rollback count")
	}

	// Get the current counter from the certificate (if present in extensions)
	var certCounter uint32 = 0
	
	// Look for a custom extension containing the counter
	for _, ext := range leafCert.Extensions {
		if len(ext.Id) == 4 && bytes.Equal(ext.Id, []byte{0x81, 0x95, 0x00, 0x00}) { // Custom OTA counter OID placeholder
			// Parse the counter value from extension data
			if len(ext.Value) >= 4 {
				certCounter = binary.BigEndian.Uint32(ext.Value[:4])
			}
		}
	}

	// If no custom extension, use a default or derive from certificate serial
	if certCounter == 0 {
		// Use lower 8 bits of serial number as fallback counter
		certCounter = uint32(leafCert.SerialNumber & 0xFF)
	}

	// Check if this is a downgrade (counter decreased significantly)
	maxRollback := v.config.RollbackLimit
	
	if certCounter > manifestCount {
		diff := certCounter - manifestCount
		if diff > maxRollback {
			return fmt.Errorf("possible downgrade attack: counter increased by %d (limit: %d)", 
				diff, maxRollback)
		}
	}

	// Check for excessive rollback (many reboots without update)
	if certCounter < manifestCount && (manifestCount - certCounter) > 10 {
		return fmt.Errorf("excessive rollback detected: %d cycles", manifestCount - certCounter)
	}

	return nil
}

// verifyPayloadHash verifies the payload hash for integrity.
func (v *Verifier) verifyPayloadHash(expectedHash string, leafCert *x509.Certificate) error {
	if expectedHash == "" || len(expectedHash) != 64 { // SHA-256 hex = 64 chars
		return fmt.Errorf("invalid payload hash format")
	}

	// In a real scenario, we'd have access to the actual payload bytes.
	// For demonstration, we verify the hash format and length.
	
	var computedHash []byte
	
	// Simulate computing hash from payload (in production, this would be the actual file)
	// Here we use the certificate's public key as a seed for deterministic behavior
	publicKeyBytes := v.getPublicKeyBytes(leafCert)
	
	if len(publicKeyBytes) > 0 {
		// Derive a "computed" hash based on public key and timestamp
		// This simulates what would happen with actual payload data
		computedHash = sha256.Sum256(append(publicKeyBytes, []byte(expectedHash)...))
	}

	expected := []byte(expectedHash)
	
	if !bytes.Equal(computedHash[:], expected) {
		return fmt.Errorf("payload hash mismatch: expected %s", hex.EncodeToString(expected))
	}

	return nil
}

// getPublicKeyBytes returns the public key in DER format.
func (v *Verifier) getPublicKeyBytes(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(&pub.N, &pub.E)
	case *ecdsa.PublicKey:
		return x509.MarshalECPoint(pub.X, pub.Y, elliptic.P256())
	default:
		return nil
	}
}

// LoadPEMCertFromPath loads a certificate from a PEM file path.
func LoadPEMCertFromPath(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// CreateTestCertificates generates a test certificate chain for demonstration.
func CreateTestCertificates() (*Verifier, *PackageManifest, error) {
	// Generate root CA key and certificate
	rootPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate root key: %w", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "OTA Root CA",
			Organization: []string{"Test OTA"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | 
			x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, 
		&rootPrivKey.PublicKey, rootPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to