package rollback

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Config holds the configuration for rollback protection behavior.
type Config struct {
	Enabled         bool   `json:"enabled"`
	MinVersion      uint64 `json:"min_version"`     // Minimum allowed version (0 = no limit)
	MaxDowngrade    int32  `json:"max_downgrade"`   // Max versions to go back before requiring approval
	ApprovalTimeout time.Duration `json:"approval_timeout"` // Time to wait for explicit approval on downgrade
}

// State represents the persisted rollback state.
type State struct {
	Version      uint64       `json:"version"`
	Timestamp    int64        `json:"timestamp"`
	PendingHash  [32]byte     `json:"pending_hash"` // Hash of pending update for verification
	Approved     bool         `json:"approved"`     // Whether a downgrade was explicitly approved
	ApprovalTime time.Time    `json:"approval_time"`
}

// UpdatePackage represents an OTA package being validated.
type UpdatePackage struct {
	Version      uint64
	Filename     string
	Hash         [32]byte
	Size         int64
	Data         io.ReaderAt // For reading the actual payload
	MetaData     map[string]string
}

// Enforcer handles rollback protection logic for OTA updates.
type Enforcer struct {
	config    Config
	stateFile string
	version   atomic.Uint64
	state     State
	mu        sync.RWMutex
}

// NewEnforcer creates a new rollback enforcer with the given config and state file path.
func NewEnforcer(cfg Config, statePath string) (*Enforcer, error) {
	if !cfg.Enabled {
		return &Enforcer{config: cfg}, nil
	}

	e := &Enforcer{
		config:    cfg,
		stateFile: statePath,
	}

	if err := e.loadState(); err != nil {
		// If load fails and we have a valid config, initialize fresh state
		if !os.IsNotExist(err) && !os.IsPermission(err) {
			return nil, fmt.Errorf("failed to load rollback state: %w", err)
		}
		e.state = State{
			Version:      0,
			Timestamp:    time.Now().Unix(),
			PendingHash:  [32]byte{},
			Approved:     false,
			ApprovalTime: time.Time{},
		}
		if err := e.persistState(); err != nil {
			return nil, fmt.Errorf("failed to initialize state: %w", err)
		}
	}

	return e, nil
}

// loadState reads the persisted rollback state from disk.
func (e *Enforcer) loadState() error {
	data, err := os.ReadFile(e.stateFile)
	if err != nil {
		return err
	}

	if len(data) < 8 { // Minimum: version(8) + timestamp(8)
		e.version.Store(0)
		e.state = State{
			Version:      0,
			Timestamp:    time.Now().Unix(),
			PendingHash:  [32]byte{},
			Approved:     false,
			ApprovalTime: time.Time{},
		}
		return nil
	}

	e.version.Store(binary.BigEndian.Uint64(data[:8]))
	binary.Write(data[8:], binary.BigEndian, e.state.Timestamp)
	copy(e.state.PendingHash[:], data[16:])
	e.state.Approved = false // Default to not approved for safety
	if len(data) >= 24 {
		e.state.Approved = true
	}

	return nil
}

// persistState atomically writes the state to disk.
func (e *Enforcer) persistState() error {
	data := make([]byte, 8+8+32)
	binary.BigEndian.PutUint64(data[:8], e.version.Load())
	binary.BigEndian.PutUint64(data[8:], uint64(e.state.Timestamp))
	copy(data[16:], e.state.PendingHash[:])

	// Use atomic rename for crash safety
	tmpFile := e.stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp state: %w", err)
	}

	if err := os.Rename(tmpFile, e.stateFile); err != nil {
		os.Remove(tmpFile) // Clean up on failure
		return fmt.Errorf("failed to rename state file: %w", err)
	}

	return nil
}

// ValidateAndApply checks if the update passes rollback rules and applies changes.
func (e *Enforcer) ValidateAndApply(ctx context.Context, pkg UpdatePackage) (*Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.config.Enabled {
		return &Result{Allowed: true, Reason: "rollback protection disabled"}, nil
	}

	current := e.version.Load()
	versionDiff := int64(pkg.Version - current)

	var reason string
	allowed := false

	switch {
	case versionDiff >= 0:
		// Upgrade or same version - always allowed
		allowed = true
		reason = "upgrade or same version"

	case versionDiff < 0 && abs(versionDiff) <= int64(e.config.MaxDowngrade):
		// Minor downgrade within threshold
		if e.state.Approved {
			allowed = true
			reason = fmt.Sprintf("approved minor downgrade (diff: %d)", -versionDiff)
		} else if !e.hasPendingApproval() {
			e.state.PendingHash = pkg.Hash
			e.state.Timestamp = time.Now().Unix()
			if err := e.persistState(); err != nil {
				return &Result{Allowed: false, Reason: "pending state save failed"}, err
			}
			reason = fmt.Sprintf("minor downgrade pending approval (diff: %d)", -versionDiff)
			allowed = true // Allow but track for later verification
		} else {
			remaining := e.config.MaxDowngrade - int64(abs(versionDiff))
			if remaining <= 0 {
				reason = "exceeded max downgrade threshold"
			} else if time.Since(e.state.ApprovalTime) > e.config.ApprovalTimeout {
				e.state.PendingHash = [32]byte{} // Reset pending hash
				e.state.Timestamp = time.Now().Unix()
				if err := e.persistState(); err != nil {
					return &Result{Allowed: false, Reason: "pending state expired"}, err
				}
				reason = fmt.Sprintf("approval timeout exceeded (remaining: %d)", remaining)
			} else {
				reason = fmt.Sprintf("within approval window but pending hash mismatch")
			}
		}

	case versionDiff < 0 && abs(versionDiff) > int64(e.config.MaxDowngrade):
		// Major downgrade - requires explicit approval
		if e.state.Approved {
			allowed = true
			reason = fmt.Sprintf("approved major downgrade (diff: %d)", -versionDiff)
		} else if time.Since(e.state.ApprovalTime) > e.config.ApprovalTimeout {
			e.state.PendingHash = [32]byte{}
			e.state.Timestamp = time.Now().Unix()
			if err := e.persistState(); err != nil {
				return &Result{Allowed: false, Reason: "major downgrade expired"}, err
			}
			reason = fmt.Sprintf("major downgrade pending approval (diff: %d)", -versionDiff)
		} else {
			e.state.PendingHash = pkg.Hash
			e.state.Timestamp = time.Now().Unix()
			if err := e.persistState(); err != nil {
				return &Result{Allowed: false, Reason: "major downgrade state save failed"}, err
			}
			reason = fmt.Sprintf("major downgrade pending approval (diff: %d)", -versionDiff)
		}

	case pkg.Version < e.config.MinVersion:
		reason = fmt.Sprintf("below minimum version (%d < %d)", pkg.Version, e.config.MinVersion)
	}

	if allowed {
		e.version.Store(pkg.Version)
		e.state.Timestamp = time.Now().Unix()
		e.state.PendingHash = [32]byte{} // Clear pending hash on success
		e.state.Approved = false
		if err := e.persistState(); err != nil {
			return &Result{Allowed: true, Reason: reason}, fmt.Errorf("failed to persist new state: %w", err)
		}
	}

	return &Result{Allowed: allowed, Reason: reason, VersionDiff: versionDiff}, nil
}

// Result represents the outcome of a rollback validation.
type Result struct {
	Allowed    bool
	Reason     string
	VersionDiff int64 // Positive = upgrade, Negative = downgrade
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// hasPendingApproval checks if we're in a pending approval state.
func (e *Enforcer) hasPendingApproval() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Pending = not approved AND within timeout window
	if !e.state.Approved && time.Since(e.state.ApprovalTime) < e.config.ApprovalTimeout {
		return true
	}
	return false
}

// ApprovePending explicitly approves a pending downgrade.
func (e *Enforcer) ApprovePending() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.hasPendingApproval() {
		return fmt.Errorf("no pending approval required")
	}

	e.state.Approved = true
	e.state.ApprovalTime = time.Now()
	e.state.PendingHash = [32]byte{} // Clear hash after approval
	
	if err := e.persistState(); err != nil {
		return fmt.Errorf("failed to persist approval: %w", err)
	}

	return nil
}

// ResetPending clears a pending approval state.
func (e *Enforcer) ResetPending() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.hasPendingApproval() {
		return fmt.Errorf("no pending approval to reset")
	}

	e.state.Approved = false
	e.state.ApprovalTime = time.Time{}
	e.state.PendingHash = [32]byte{}

	if err := e.persistState(); err != nil {
		return fmt.Errorf("failed to persist reset: %w", err)
	}

	return nil
}

// GetCurrentVersion returns the current version counter.
func (e *Enforcer) GetCurrentVersion() uint64 {
	return e.version.Load()
}

// SetCurrentVersion manually sets the current version (for testing).
func (e *Enforcer) SetCurrentVersion(v uint64) {
	e.version.Store(v)
}

// GetState returns a copy of the current state.
func (e *Enforcer) GetState() State {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Deep copy to prevent external mutation
	state := State{
		Version:      e.state.Version,
		Timestamp:    e.state.Timestamp,
		PendingHash:  make([32]byte, len(e.state.PendingHash)),
		Copy:         true, // Flag indicating this is a copy
	}
	copy(state.PendingHash[:], e.state.PendingHash[:])
	state.Approved = e.state.Approved
	state.ApprovalTime = e.state.ApprovalTime
	
	return state
}

// VerifyPendingHash validates the pending hash against expected value.
func (e *Enforcer) VerifyPendingHash(expected [32]byte) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.hasPendingApproval() {
		return false // Not in pending state
	}

	return binary.Equal(e.state.PendingHash[:], expected[:])
}

// ClearPendingHash resets the pending hash without approval.
func (e *Enforcer) ClearPendingHash() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.hasPendingApproval() {
		return fmt.Errorf("no pending hash to clear")
	}

	e.state.PendingHash = [32]byte{}
	
	if err := e.persistState(); err != nil {
		return fmt.Errorf("failed to persist cleared state: %w", err)
	}

	return nil
}

// LoadFromReader allows initializing from an existing reader (for testing).
func (e *Enforcer) LoadFromReader(r io.ReaderAt, size int64) error {
	data := make([]byte, 8+8+32)
	if n, err := r.Read(data); err != nil || n < len(data) {
		return fmt.Errorf("failed to read state: %w", err)
	}

	e.version.Store(binary.BigEndian.Uint64(data[:8]))
	binary.BigEndian.PutUint64(data[8:], uint64(e.state.Timestamp))
	copy(e.state.PendingHash[:], data[16:])

	return nil
}

// SaveToWriter allows persisting to a writer (for testing).
func (e *Enforcer) SaveToWriter(w io.WriterAt, offset int64) error {
	data := make([]byte, 8+8+32)
	binary.BigEndian.PutUint64(data[:8], e.version.Load())
	binary.BigEndian.PutUint64(data[8:], uint64(e.state.Timestamp))
	copy(data[16:], e.state.PendingHash[:])

	if _, err := w.WriteAt(data, offset); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

// Demo demonstrates the enforcer with a simple in-memory example.
func main() {
	fmt.Println("=== OTA Rollback Protection Enforcer Demo ===\n")

	// Create config - allow 3 versions of minor downgrade, 10 for major
	cfg := Config{
		Enabled:         true,
		MinVersion:      100,
		MaxDowngrade:    3, // Minor threshold
		ApprovalTimeout: 5 * time.Minute,
	}

	// Use a temp file for state persistence
	stateFile := "/tmp/otaverify_rollback_state.bin"
	enforcer, err := NewEnforcer(cfg, stateFile)
	if err != nil {
		fmt.Printf("Error creating enforcer: %v\n", err)
		return
	}

	currentVer := enforcer.GetCurrentVersion()
	fmt.Printf("Initial version: %d\n\n", currentVer)

	// Test 1: Normal upgrade (should always pass)
	fmt.Println("--- Test 1: Upgrade from v10 to v20 ---")
	pkg1 := UpdatePackage{
		Version: 20,
		Filename: "update_v20.bin",
		Hash:    [32]byte{1, 2, 3}, // Simulated hash
		Size:    1048576,
	}

	result1, err := enforcer.ValidateAndApply(context.Background(), pkg1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: Allowed=%t, Reason='%s', Diff=%d\n\n", 
			result1.Allowed, result1.Reason, result1.VersionDiff)
	}

	// Test 2: Minor downgrade within threshold (should pass with pending)
	fmt.Println("--- Test 2: Minor downgrade from v20 to v19 ---")
	pkg2 := UpdatePackage{
		Version: 19,
		Filename: "update_v19.bin",
		Hash:    [32]byte{4, 5, 6},
		Size:    1048576,
	}

	result2, err := enforcer.ValidateAndApply(context.Background(), pkg2)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Result: Allowed=%t, Reason='%s', Diff=%d\n\n", 
			result2.Allowed, result2.Reason, result2.VersionDiff)
	}

	// Test 3: Major downgrade (should require approval)
	fmt.Println("--- Test 3: Major downgrade from v20 to v15 ---")
	pkg3 := UpdatePackage{
		Version: 15,
		Filename: "update_v15.bin",
		Hash:    [32]byte{7, 8, 9},
		Size:    1048576,
	}

	result3, err := enforcer.ValidateAndApply(context.Background(), pkg3)
	if err != nil {
		fmt.Printf("Error: %v\n", err)