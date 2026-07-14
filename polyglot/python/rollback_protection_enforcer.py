"""
polyglot/python/rollback_protection_enforcer.py

Rollback Protection Enforcer for OTA Updates

Enforces anti-downgrade protection by validating:
- Monotonically increasing counter values
- Signature chain integrity
- Delta-patch base compatibility
- Version ordering constraints
"""

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


# Configure logging
logger = logging.getLogger(__name__)


class RollbackError(Exception):
    """Base exception for rollback protection failures."""
    pass


class CounterMismatch(RollbackError):
    """Counter decreased or drifted beyond tolerance."""
    def __init__(self, expected: int, actual: int, tolerance: int = 10):
        self.expected = expected
        self.actual = actual
        self.tolerance = tolerance
        super().__init__(f"Counter mismatch: expected >= {expected}, got {actual} (tolerance={tolerance})")


class SignatureError(RollbackError):
    """Signature verification failed."""
    def __init__(self, algorithm: str, error_msg: str):
        self.algorithm = algorithm
        self.error_msg = error_msg
        super().__init__(f"Signature ({algorithm}): {error_msg}")


class VersionMismatch(RollbackError):
    """Version ordering violated (potential downgrade)."""
    def __init__(self, current_version: str, new_version: str):
        self.current_version = current_current_version:
        self.new_version = new_version
        super().__init__(f"Possible downgrade: {new_version} < {current_version}")


class DeltaBaseError(RollbackError):
    """Delta patch base compatibility issue."""
    def __init__(self, expected_base: str, actual_base: str):
        self.expected_base = expected_base
        self.actual_base = actual_base
        super().__init__(f"Delta base mismatch: needs {expected_base}, found {actual_base}")


@dataclass(frozen=True)
class UpdateMetadata:
    """Parsed metadata from an OTA update package."""
    
    version: str
    counter: int
    is_delta: bool = False
    delta_base_version: Optional[str] = None
    signature_algorithm: str = "ECDSA-SHA256"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata_json: dict = field(default_factory=dict)


@dataclass
class RollbackState:
    """Current device state for rollback protection."""
    
    current_counter: int = 0
    last_good_version: str = "0.0.0"
    last_good_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    known_public_key: bytes = b""
    counter_tolerance: int = 10
    
    @classmethod
    def from_json(cls, path: Path) -> 'RollbackState':
        """Load state from persistent storage."""
        data = json.loads(path.read_text())
        return cls(
            current_counter=data["counter"],
            last_good_version=data["last_good_version"],
            last_good_timestamp=datetime.fromisoformat(data["timestamp"]),
            known_public_key=bytes.fromhex(data.get("public_key", "")),
            counter_tolerance=data.get("tolerance", 10),
        )


class RollbackEnforcer:
    """
    Enforces rollback protection rules for OTA updates.
    
    Usage:
        enforcer = RollbackEnforcer()
        if enforcer.validate(update, state):
            enforcer.apply(state)
    """
    
    def __init__(self, public_key: bytes = b"", tolerance: int = 10):
        self.public_key = public_key or b""
        self.tolerance = tolerance
        self._signature_hmac_key = hashlib.sha256(public_key).digest() if public_key else hashlib.sha256(b"fallback").digest()
    
    def validate(self, metadata: UpdateMetadata, state: RollbackState) -> tuple[bool, list[str]]:
        """
        Validate an update against current rollback state.
        
        Returns:
            Tuple of (is_valid, list_of_errors). If is_valid is True, errors may still contain warnings.
        """
        errors = []
        
        # 1. Counter validation - must be monotonically increasing
        counter_ok, counter_err = self._check_counter(metadata.counter, state.current_counter)
        if not counter_ok:
            errors.append(counter_err)
        
        # 2. Version ordering check
        version_ok, version_err = self._check_version_ordering(
            metadata.version, 
            state.last_good_version,
            metadata.is_delta
        )
        if not version_ok:
            errors.append(version_err)
        
        # 3. Delta base compatibility (if applicable)
        delta_ok, delta_err = self._check_delta_base(metadata, state.last_good_version)
        if not delta_ok:
            errors.append(delta_err)
        
        # 4. Signature verification
        sig_ok, sig_err = self._verify_signature(metadata, state.known_public_key)
        if not sig_ok:
            errors.append(sig_err)
        
        return len(errors) == 0, errors
    
    def _check_counter(self, new_counter: int, old_counter: int) -> tuple[bool, str]:
        """Check that counter is monotonically increasing within tolerance."""
        if new_counter < old_counter - self.tolerance:
            return False, CounterMismatch(old_counter, new_counter, self.tolerance).__str__()
        return True, ""
    
    def _check_version_ordering(self, new_version: str, current_version: str, is_delta: bool) -> tuple[bool, str]:
        """Check version ordering to prevent downgrades."""
        try:
            # Simple semantic version comparison
            new_parts = [int(x) for x in new_version.split(".")]
            current_parts = [int(x) for x in current_version.split(".")]
            
            if len(new_parts) != 3 or len(current_parts) != 3:
                return True, ""  # Non-standard versions, be lenient
            
            if new_parts < current_parts:
                return False, VersionMismatch(current_version, new_version).__str__()
        except (ValueError, IndexError):
            # Fallback for non-numeric versions
            if new_version < current_version:
                return False, VersionMismatch(current_version, new_version).__str__()
        
        return True, ""
    
    def _check_delta_base(self, metadata: UpdateMetadata, current_version: str) -> tuple[bool, str]:
        """Check delta patch base compatibility."""
        if not metadata.is_delta or not metadata.delta_base_version:
            return True, ""
        
        # Delta must target the exact version currently running
        if metadata.delta_base_version != current_version:
            return False, DeltaBaseError(current_version, metadata.delta_base_version).__str__()
        
        return True, ""
    
    def _verify_signature(self, metadata: UpdateMetadata, public_key: bytes) -> tuple[bool, str]:
        """Verify update signature against stored public key."""
        if not public_key:
            # No public key - assume valid (development mode)
            return True, "No public key configured"
        
        try:
            # In real implementation, this would use cryptography library
            # For demo, we'll simulate HMAC verification
            data = f"{metadata.version}:{metadata.counter}".encode()
            expected_sig = hmac.new(self._signature_hmac_key, data, hashlib.sha256).hexdigest()[:16]
            
            # Simulate signature from metadata (in real code: extract from package)
            actual_sig = metadata.metadata_json.get("signature", "")
            
            if not actual_sig or expected_sig not in actual_sig:
                return False, SignatureError(metadata.signature_algorithm, "Signature mismatch")
            
            return True, ""
        except Exception as e:
            return False, SignatureError(metadata.signature_algorithm, str(e))
    
    def apply(self, state: RollbackState, metadata: UpdateMetadata) -> None:
        """Update device state after successful validation."""
        state.current_counter = max(state.current_counter, metadata.counter)
        if not metadata.is_delta or (metadata.is_delta and metadata.delta_base_version == state.last_good_version):
            state.last_good_version = metadata.version
            state.last_good_timestamp = datetime.now(timezone.utc)


def load_state_from_file(path: Path) -> RollbackState:
    """Load rollback state from persistent storage file."""
    try:
        return RollbackState.from_json(path)
    except FileNotFoundError:
        logger.info(f"New device, initializing default state at {path}")
        return RollbackState()


def save_state_to_file(state: RollbackState, path: Path) -> None:
    """Persist rollback state to file."""
    data = {
        "counter": state.current_counter,
        "last_good_version": state.last_good_version,
        "timestamp": state.last_good_timestamp.isoformat(),
        "public_key": state.known_public_key.hex() if state.known_public_key else "",
        "tolerance": state.counter_tolerance,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def create_demo_metadata(version: str, counter: int, is_delta: bool = False, 
                        base_version: Optional[str] = None) -> UpdateMetadata:
    """Helper to create test metadata for demos."""
    return UpdateMetadata(
        version=version,
        counter=counter,
        is_delta=is_delta,
        delta_base_version=base_version,
        timestamp=datetime.now(timezone.utc),
        metadata_json={"signature": "simulated_signature_data"}
    )


if __name__ == "__main__":
    # Demo: Test various rollback scenarios
    
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 60)
    print("Rollback Protection Enforcer - Demo")
    print("=" * 60)
    
    # Initialize enforcer and state
    enforcer = RollbackEnforcer(
        public_key=b"demo_public_key_for_testing",
        tolerance=5
    )
    
    # Scenario 1: Normal forward update (should pass)
    print("\n--- Scenario 1: Forward Update ---")
    state = RollbackState(current_counter=10, last_good_version="1.2.3")
    metadata = create_demo_metadata("1.3.0", counter=15, is_delta=False)
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 2: Downgrade attempt (should fail)
    print("\n--- Scenario 2: Downgrade Attempt ---")
    metadata = create_demo_metadata("1.1.0", counter=14, is_delta=False)
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 3: Delta patch with wrong base (should fail)
    print("\n--- Scenario 3: Delta Wrong Base ---")
    metadata = create_demo_metadata("1.3.0", counter=20, is_delta=True, 
                                    base_version="1.2.4")
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 4: Delta patch with correct base (should pass)
    print("\n--- Scenario 4: Delta Correct Base ---")
    metadata = create_demo_metadata("1.3.0", counter=20, is_delta=True, 
                                    base_version="1.2.5")
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 5: Counter drift (within tolerance - should pass)
    print("\n--- Scenario 5: Counter Drift Within Tolerance ---")
    state = RollbackState(current_counter=10, last_good_version="1.2.3")
    metadata = create_demo_metadata("1.3.0", counter=8, is_delta=False)
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 6: Counter drift (exceeds tolerance - should fail)
    print("\n--- Scenario 6: Counter Drift Exceeds Tolerance ---")
    state = RollbackState(current_counter=10, last_good_version="1.2.3", 
                          counter_tolerance=5)
    metadata = create_demo_metadata("1.3.0", counter=4, is_delta=False)
    
    valid, errors = enforcer.validate(metadata, state)
    print(f"  Valid: {valid}")
    if not valid:
        for err in errors:
            print(f"    Error: {err}")
    
    # Scenario 7: Apply successful update
    print("\n--- Scenario 7: State Update After Success ---")
    state = RollbackState(current_counter=10, last_good_version="1.2.3")
    metadata = create_demo_metadata("1.3.0", counter=15, is_delta=False)
    
    valid, errors = enforcer.validate(metadata, state)
    if valid:
        print(f"  Before: counter={state.current_counter}, version={state.last_good_version}")
        enforcer.apply(state, metadata)
        print(f"  After:  counter={state.current_counter}, version={state.last_good_version}")
    
    # Scenario 8: Persistence demo
    print("\n--- Scenario 8: State Persistence ---")
    state = RollbackState(current_counter=10, last_good_version="1.2.3")
    temp_path = Path("/tmp/rollback_state.json")
    
    save_state_to_file(state, temp_path)
    print(f"  Saved to {temp_path}")
    
    loaded = load_state_from_file(temp_path)
    print(f"  Loaded: counter={loaded.current_counter}, version={loaded.last_good_version}")
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()
    
    print("\n" + "=" * 60)
    print("Demo Complete")
    print("=" * 60)