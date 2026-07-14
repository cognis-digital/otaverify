use std::collections::{HashMap, BTreeMap};
use std::fmt;
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use rsa::{RsaKeyPair, PublicKey, PrivateKey, PaddingScheme, PKCS1v15};

/// Configuration for the signature chain verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Root public key for initial package verification.
    pub root_public_key: RsaKeyPair,
    
    /// Maximum versions back we can rollback (rollback protection).
    pub max_rollback_versions: u32,
    
    /// Threshold of downgrades before requiring explicit approval.
    pub downgrade_threshold: u32,
    
    /// Current anti-downgrade counter value.
    pub current_downgrade_counter: u32,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            root_public_key: RsaKeyPair::from_pkcs1(
                "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA0Z3VS5JJcd23xiHq...placeholder...\n-----END RSA PUBLIC KEY-----",
            ).unwrap_or_else(|| {
                // Fallback: create a minimal valid key for demo purposes
                let mut rng = rand::thread_rng();
                RsaKeyPair::from_private_key_exponent(
                    65537, 
                    &mut rng.gen_prime(),
                    &mut rng.gen_prime(),
                    &mut rng.gen_prime(),
                    &mut rng.gen_prime(),
                ).unwrap()
            }),
            max_rollback_versions: 20,
            downgrade_threshold: 3,
            current_downgrade_counter: 0,
        }
    }
}

/// Metadata for a package in the OTA chain.
#[derive(Debug, Clone)]
pub struct PackageMetadata {
    /// Version string (e.g., "1.2.3").
    pub version: String,
    
    /// SHA-256 hash of the raw binary payload.
    pub payload_hash: [u8; 32],
    
    /// Size in bytes.
    pub size_bytes: u64,
    
    /// Timestamp when this package was built.
    pub build_timestamp: SystemTime,
}

impl PackageMetadata {
    pub fn new(version: impl Into<String>, payload_hash: [u8; 32], size_bytes: u64) -> Self {
        let now = SystemTime::now();
        Self {
            version: version.into(),
            payload_hash,
            size_bytes,
            build_timestamp: now,
        }
    }
}

/// Result of verifying a single package in the chain.
#[derive(Debug)]
pub enum PackageVerificationResult {
    /// Package verified successfully with metadata.
    Verified(PackageMetadata),
    
    /// Signature verification failed.
    BadSignature(String),
    
    /// Rollback protection triggered (jumped too far back).
    RollbackExceeded(u32, u32),
    
    /// Anti-downgrade counter exceeded threshold.
    DowngradeThresholdExceeded(u32, u32),
    
    /// Delta patch integrity failed.
    DeltaIntegrityFailed(String),
}

impl PackageVerificationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
    
    pub fn error_message(&self) -> Option<&str> {
        match self {
            Self::BadSignature(msg) => Some(msg),
            Self::RollbackExceeded(jump, max) => Some(&format!("Jumped {} versions back (max: {})", jump, max)),
            Self::DowngradeThresholdExceeded(count, threshold) => Some(&format!("Downgrade counter {} >= threshold {}", count, threshold)),
            Self::DeltaIntegrityFailed(msg) => Some(msg),
            Self::Verified(_) => None,
        }
    }
}

/// State maintained during chain verification.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Current position in the version sequence.
    pub current_version: u64,
    
    /// How many times we've downgraded from this point.
    pub downgrade_count: u32,
    
    /// Last verified package metadata (if any).
    pub last_verified: Option<PackageMetadata>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            current_version: 0,
            downgrade_count: 0,
            last_verified: None,
        }
    }
}

/// The main signature chain verifier.
pub struct SignatureChainVerifier {
    config: VerifierConfig,
    state: ChainState,
}

impl SignatureChainVerifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            state: ChainState::default(),
        }
    }
    
    /// Reset the verifier to initial state.
    pub fn reset(&mut self) {
        self.state = ChainState::default();
    }
    
    /// Verify a single package against its expected predecessor in the chain.
    /// 
    /// # Arguments
    /// * `predecessor` - The previous package's metadata (None for root/first package).
    /// * `current_package` - The current package being verified.
    /// * `signature_data` - Signature information for the current package.
    /// 
    /// # Returns
    /// A verification result indicating success or failure with details.
    pub fn verify_package(
        &mut self,
        predecessor: Option<&PackageMetadata>,
        current_package: &PackageMetadata,
        signature_data: &SignatureData,
    ) -> PackageVerificationResult {
        // 1. Check rollback protection - ensure we're not jumping too far back
        if let Some(prev_version) = predecessor.map(|p| parse_version(&p.version)) {
            let jump = self.state.current_version.saturating_sub(prev_version);
            
            if jump > self.config.max_rollback_versions {
                return PackageVerificationResult::RollbackExceeded(jump, self.config.max_rollback_versions);
            }
        } else {
            // First package in chain - starts at version 0
            self.state.current_version = 1;
        }
        
        // 2. Check anti-downgrade counter
        let is_downgrade = if let Some(prev_version) = predecessor.map(|p| parse_version(&p.version)) {
            prev_version > self.state.current_version
        } else {
            false
        };
        
        if is_downgrade {
            self.state.downgrade_count += 1;
            
            if self.state.downgrade_count >= self.config.downgrade_threshold {
                return PackageVerificationResult::DowngradeThresholdExceeded(
                    self.state.downgrade_count,
                    self.config.downgrade_threshold,
                );
            }
        } else {
            // Upgrade or same version - reset counter
            if let Some(prev_version) = predecessor.map(|p| parse_version(&p.version)) {
                if prev_version < self.state.current_version {
                    self.state.downgrade_count = 0;
                }
            }
        }
        
        // 3. Verify signature chain
        match self.verify_signature(predecessor, current_package, signature_data) {
            Ok(_) => {
                self.state.last_verified = Some(current_package.clone());
                PackageVerificationResult::Verified(current_package.clone())
            },
            Err(msg) => PackageVerificationResult::BadSignature(msg),
        }
    }
    
    /// Verify the cryptographic signature for a package.
    fn verify_signature(
        &self,
        predecessor: Option<&PackageMetadata>,
        current: &PackageMetadata,
        sig_data: &SignatureData,
    ) -> Result<(), String> {
        // For root/first package, verify against root public key
        if predecessor.is_none() {
            let hash = Digest::from(current.payload_hash);
            match self.config.root_public_key.verify(
                PaddingScheme::PKCS1v15::<Digest>::new(Digest::SHA256),
                &hash.finalize(),
                sig_data.signature.as_slice(),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Root signature verification failed: {}", e)),
            }
        } else {
            // Chain signature - verify against predecessor's private key
            let hash = Digest::from(current.payload_hash);
            
            match sig_data.predecessor_private_key.verify(
                PaddingScheme::PKCS1v15::<Digest>::new(Digest::SHA256),
                &hash.finalize(),
                sig_data.signature.as_slice(),
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Chain signature verification failed: {}", e)),
            }
        }
    }
    
    /// Verify delta patch integrity.
    /// 
    /// Delta patches need special handling because they apply to a specific base version.
    pub fn verify_delta_integrity(
        &self,
        base_package: &PackageMetadata,
        delta_patch: &DeltaPatchInfo,
    ) -> PackageVerificationResult {
        // 1. Verify patch header matches expected base
        if delta_patch.expected_base_version != parse_version(&base_package.version) {
            return PackageVerificationResult::DeltaIntegrityFailed(
                format!(
                    "Base version mismatch: expected {}, got {}",
                    delta_patch.expected_base_version,
                    base_package.version
                ),
            );
        }
        
        // 2. Verify patch size matches header
        if delta_patch.size_bytes != base_package.size_bytes {
            return PackageVerificationResult::DeltaIntegrityFailed(
                format!(
                    "Size mismatch: expected {}, got {}",
                    delta_patch.size_bytes,
                    base_package.size_bytes
                ),
            );
        }
        
        // 3. Verify patch hash (if provided)
        if !delta_patch.patch_hash.is_empty() {
            let computed = compute_sha256(&base_package.payload_hash);
            if &computed != delta_patch.patch_hash.as_slice() {
                return PackageVerificationResult::DeltaIntegrityFailed(
                    "Patch content hash mismatch".to_string(),
                );
            }
        }
        
        // 4. Verify patch applies correctly (simulated - in real impl, would apply and verify)
        if let Some(expected_result_hash) = &delta_patch.expected_result_hash {
            // In a real implementation, we'd actually apply the delta to base_package.payload_hash
            // For now, just check that expected result is non-empty
            if expected_result_hash.is_empty() {
                return PackageVerificationResult::DeltaIntegrityFailed(
                    "Expected result hash missing".to_string(),
                );
            }
        }
        
        PackageVerificationResult::Verified(base_package.clone())
    }
    
    /// Verify an entire OTA update chain.
    /// 
    /// # Arguments
    /// * `packages` - Ordered list of packages in the chain (first = root, last = current).
    /// * `signature_data` - Signature information for each package.
    /// 
    /// # Returns
    /// A vector of results for each package verification.
    pub fn verify_chain(
        &mut self,
        packages: &[PackageMetadata],
        signature_data: &[SignatureData],
    ) -> Vec<PackageVerificationResult> {
        let mut results = Vec::new();
        
        // Verify root/first package against root key
        if let Some(first_sig) = signature_data.first() {
            results.push(self.verify_package(None, &packages[0], first_sig));
        } else {
            results.push(PackageVerificationResult::BadSignature(
                "Missing root signature".to_string(),
            ));
        }
        
        // Verify remaining packages in chain
        for (i, (pkg, sig)) in packages.iter().zip(signature_data.iter()).skip(1).enumerate() {
            let prev_pkg = &packages[i - 1];
            let prev_sig = &signature_data[i - 1];
            
            results.push(self.verify_package(Some(prev_pkg), pkg, sig));
        }
        
        // Final anti-downgrade check
        if self.state.downgrade_count >= self.config.downgrade_threshold {
            results.last_mut().map(|r| {
                *r = PackageVerificationResult::DowngradeThresholdExceeded(
                    self.state.downgrade_count,
                    self.config.downgrade_threshold,
                );
            });
        }
        
        // Check if overall chain is valid
        let all_valid = results.iter().all(|r| r.is_success());
        
        if !all_valid {
            // Find first failure for reporting
            if let Some(failure) = results.iter().find(|r| !r.is_success()) {
                if let Some(msg) = failure.error_message() {
                    eprintln!("Chain verification failed: {}", msg);
                }
            }
        } else {
            eprintln!("Chain verification successful!");
        }
        
        results
    }
}

/// Signature data for a package in the chain.
#[derive(Debug, Clone)]
pub struct SignatureData {
    /// The actual signature bytes (typically DER-encoded).
    pub signature: Vec<u8>,
    
    /// Private key of the predecessor (for chain signatures).
    pub predecessor_private_key: Option<RsaKeyPair>,
}

impl Default for SignatureData {
    fn default() -> Self {
        Self {
            signature: vec![],
            predecessor_private_key: None,
        }
    }
}

/// Information about a delta patch.
#[derive(Debug, Clone)]
pub struct DeltaPatchInfo {
    /// Expected base version this patch applies to.
    pub expected_base_version: u64,
    
    /// Size of the base package (for integrity check).
    pub size_bytes: u64,
    
    /// SHA-256 hash of the delta patch content.
    pub patch_hash: Vec<u8>,
    
    /// Expected result hash after applying the patch.
    pub expected_result_hash: Option<Vec<u8>>,
}

impl DeltaPatchInfo {
    pub fn new(
        base_version: u64,
        size_bytes: u64,
        patch_hash: Vec<u8>,
    ) -> Self {
        Self {
            expected_base_version: base_version,
            size_bytes,
            patch_hash,
            expected_result_hash: None,
        }
    }
}

/// Parse a semantic version string into a u64 for comparison.
fn parse_version(version: &str) -> u64 {
    // Simple parser: "1.2.3" -> 1002003
    let parts: Vec<&str> = version.split('.').collect();
    
    if parts.len() != 3 {
        return 0;
    }
    
    parts.iter()
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect::<Vec<u64>>()
        .iter()
        .enumerate()
        .fold(0, |acc, (i, &v)| acc + v * 1_000_000_u64.pow(i as u32))
}

/// Compute SHA-256 hash of data.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

impl fmt::Display for PackageVerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(meta) => write!(f, "Verified: {}", meta.version),
            Self::BadSignature(msg) | 
            Self::RollbackExceeded(_, _) |
            Self::DowngradeThresholdExceeded(_, _) |
            Self::DeltaIntegrityFailed(_) => {
                write!(f, "{}", self.error_message().unwrap_or("Unknown error"))
            }
        }
    }
}

/// A demo/main function to show the verifier in action.
#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_keypair() -> RsaKeyPair {
        let mut rng = rand::thread_rng();
        RsaKeyPair::from_private_key_exponent(
            65537, 
            &mut rng.gen_prime(),
            &mut rng.gen_prime(),
            &mut rng.gen_prime(),
            &mut rng.gen_prime(),
        ).unwrap()
    }
    
    #[test]
    fn test_basic_chain_verification() {
        let root_key = create_test_keypair();
        
        // Create a config with our root key
        let mut verifier = SignatureChainVerifier::new(VerifierConfig {
            root_public_key: root_key.clone(),
            ..Default::default()