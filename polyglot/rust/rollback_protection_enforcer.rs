use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for rollback protection behavior.
#[derive(Debug, Clone)]
pub struct RollbackConfig {
    /// Maximum number of consecutive rollbacks allowed before forcing a hard reset.
    pub max_consecutive_rollbacks: u32,
    
    /// Minimum time (in seconds) between two successful commits.
    pub min_commit_interval_seconds: Duration,
    
    /// Path to the state file that persists across reboots.
    pub state_file_path: PathBuf,
    
    /// How long to keep old state files before cleanup.
    pub stale_state_ttl_seconds: Duration,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            max_consecutive_rollbacks: 3,
            min_commit_interval_seconds: Duration::from_secs(60),
            state_file_path: PathBuf::from("/data/ota/rollback_state"),
            stale_state_ttl_seconds: Duration::from_secs(86400 * 7), // 1 week
        }
    }
}

/// Represents the current rollback protection state.
#[derive(Debug, Clone)]
pub struct RollbackState {
    /// The version that was last successfully booted into.
    pub last_successful_boot: String,
    
    /// Timestamp of when this state was committed.
    pub commit_timestamp: u64,
    
    /// Number of consecutive rollbacks since the last successful boot.
    pub consecutive_rollbacks: u32,
    
    /// Total number of rollback cycles ever observed (for long-term analysis).
    pub total_rollback_cycles: u32,
}

impl RollbackState {
    fn new() -> Self {
        Self {
            last_successful_boot: String::new(),
            commit_timestamp: 0,
            consecutive_rollbacks: 0,
            total_rollback_cycles: 0,
        }
    }
    
    /// Load state from disk. Returns None if file doesn't exist or is corrupted.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let mut buffer = Vec::new();
        
        match fs::read(path) {
            Ok(bytes) => {
                // Use a simple length-prefixed format for robustness
                if bytes.len() < 8 {
                    return Err("State file too small".to_string());
                }
                
                let len = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]
                ]) as usize;
                
                if len + 8 > bytes.len() {
                    return Err("State file truncated".to_string());
                }
                
                let state_bytes = &bytes[8..len];
                Self::from_bytes(state_bytes)
            }
            Err(e) => Ok(None),
        }
    }
    
    /// Serialize the state into bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        // Simple format: 4-byte version + 4-byte timestamp + string data
        let mut buffer = Vec::new();
        
        // Magic header for validation
        buffer.extend_from_slice(b"RSV2");
        
        // Version (currently v2)
        buffer.push(0x02);
        
        // Timestamp as u32
        let ts: u32 = self.commit_timestamp.try_into()
            .map_err(|_| "Timestamp overflow".to_string())?;
        buffer.extend_from_slice(&ts.to_le_bytes());
        
        // Consecutive rollbacks as u16
        let cr: u16 = (self.consecutive_rollbacks as u32).try_into()
            .map_err(|_| "Rollback count overflow".to_string())?;
        buffer.extend_from_slice(&cr.to_le_bytes());
        
        // Total rollback cycles as u16
        let trc: u16 = (self.total_rollback_cycles as u32).try_into()
            .map_err(|_| "Total cycles overflow".to_string())?;
        buffer.extend_from_slice(&trc.to_le_bytes());
        
        // Last successful boot version string (null-terminated)
        let boot_str = format!("{}0", self.last_successful_boot);
        for b in boot_str.as_bytes() {
            buffer.push(*b);
        }
        
        Ok(buffer)
    }
    
    /// Deserialize state from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("State data too short".to_string());
        }
        
        // Check magic header
        let magic = &bytes[0..4];
        if magic != b"RSV2" {
            return Err(format!("Invalid magic header: {:?}", magic));
        }
        
        // Check version
        let version = bytes[4];
        if version != 0x02 {
            return Err(format!("Unsupported version: {}", version));
        }
        
        // Parse timestamp
        let ts = u32::from_le_bytes([
            bytes[5], bytes[6], bytes[7], bytes[8]
        ]);
        
        // Parse consecutive rollbacks
        let cr = u16::from_le_bytes([
            bytes[9], bytes[10]
        ]) as u32;
        
        // Parse total rollback cycles
        let trc = u16::from_le_bytes([
            bytes[11], bytes[12]
        ]) as u32;
        
        // Extract boot version string (null-terminated)
        let mut i: usize = 13;
        let mut boot_str = String::new();
        while i < bytes.len() && bytes[i] != 0 {
            boot_str.push(bytes[i] as char);
            i += 1;
        }
        
        Ok(Self {
            last_successful_boot: boot_str,
            commit_timestamp: ts as u64,
            consecutive_rollbacks: cr,
            total_rollback_cycles: trc,
        })
    }
    
    /// Check if we should allow a new update.
    pub fn can_accept_update(&self) -> bool {
        // Allow if within reasonable time window since last commit
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        self.commit_timestamp > 0 && 
        (now - self.commit_timestamp) < 86400 * 7 // Within 1 week
    }
}

/// The main rollback protection enforcer.
pub struct RollbackEnforcer {
    config: Arc<RwLock<RollbackConfig>>,
    state: Arc<RwLock<Option<RollbackState>>>,
}

impl RollbackEnforcer {
    /// Create a new enforcer with the given configuration.
    pub fn new(config: RollbackConfig) -> Self {
        let config = Arc::new(RwLock::new(config));
        let state = Arc::new(RwLock::None);
        
        // Try to initialize from existing state file
        if let Ok(Some(existing)) = RollbackState::load(&config.state_file_path) {
            *state.write().unwrap() = Some(existing);
        }
        
        Self { config, state }
    }
    
    /// Check if an update from `from_version` to `to_version` is safe.
    pub fn can_update(
        &self, 
        from_version: &str, 
        to_version: &str,
    ) -> Result<bool, String> {
        let state = self.state.read().unwrap();
        
        match &*state {
            None => Ok(true), // No history, allow anything
            Some(s) => {
                if !s.can_accept_update() {
                    return Ok(false);
                }
                
                // Check for rollback loop: A→B→A is suspicious
                let is_rollback_loop = s.last_successful_boot == from_version && 
                                       s.consecutive_rollbacks > 0;
                
                if is_rollback_loop {
                    // Allow but warn - might be intentional recovery
                    Ok(true)
                } else {
                    Ok(true)
                }
            }
        }
    }
    
    /// Record that an update was prepared (but not yet committed).
    pub fn prepare_update(&self, from_version: &str, to_version: &str) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        
        match &mut *state {
            None => {
                // First time - initialize with current boot version
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                *state = Some(RollbackState {
                    last_successful_boot: from_version.to_string(),
                    commit_timestamp: now,
                    consecutive_rollbacks: 0,
                    total_rollback_cycles: 0,
                });
            }
            
            Some(s) => {
                // Check if we've exceeded max rollbacks
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                if s.consecutive_rollbacks >= self.config.read().unwrap().max_consecutive_rollbacks {
                    return Err(format!(
                        "Max consecutive rollbacks ({}) exceeded. Force reset required.",
                        s.consecutive_rollbacks
                    ));
                }
                
                // Increment rollback counter for this cycle
                if from_version == &s.last_successful_boot {
                    s.consecutive_rollbacks += 1;
                } else {
                    s.consecutive_rollbacks = 0;
                }
            }
        }
        
        Ok(())
    }
    
    /// Commit the update and record it as successful.
    pub fn commit_update(&self, to_version: &str) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        let config = self.config.read().unwrap();
        
        match &mut *state {
            None => {
                return Err("No active update session".to_string());
            }
            
            Some(s) => {
                // Check minimum interval between commits
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                
                if s.commit_timestamp > 0 && 
                   (now - s.commit_timestamp) < config.min_commit_interval_seconds.as_secs() {
                    return Err(format!(
                        "Commit interval too short. Wait {}s more.",
                        config.min_commit_interval_seconds.as_secs() - (now - s.commit_timestamp)
                    ));
                }
                
                // Update state to reflect successful commit
                s.last_successful_boot = to_version.to_string();
                s.commit_timestamp = now;
                s.consecutive_rollbacks = 0;
            }
        }
        
        self.persist_state()?;
        Ok(())
    }
    
    /// Record a rollback event.
    pub fn record_rollback(&self, from_version: &str) -> Result<(), String> {
        let mut state = self.state.write().unwrap();
        let config = self.config.read().unwrap();
        
        match &mut *state {
            None => {
                return Err("No active update session".to_string());
            }
            
            Some(s) => {
                // Check if this is a rollback loop
                if s.last_successful_boot == from_version && 
                   s.consecutive_rollbacks > 0 {
                    s.total_rollback_cycles += 1;
                    
                    if s.total_rollback_cycles >= config.max_consecutive_rollbacks * 2 {
                        return Err(format!(
                            "Excessive rollback cycles ({}) detected. Force reset required.",
                            s.total_rollback_cycles
                        ));
                    }
                } else {
                    // New boot after previous session
                    s.last_successful_boot = from_version.to_string();
                    s.commit_timestamp = 0;
                    s.consecutive_rollbacks = 0;
                }
            }
        }
        
        self.persist_state()?;
        Ok(())
    }
    
    /// Persist the current state to disk.
    fn persist_state(&self) -> Result<(), String> {
        let config = self.config.read().unwrap();
        let mut bytes = Vec::new();
        
        match &*self.state.read().unwrap() {
            None => return Ok(()),
            Some(s) => {
                bytes = s.to_bytes()?;
            }
        }
        
        // Write with length prefix for robustness
        let len: u64 = bytes.len() as u64;
        let mut buffer = Vec::with_capacity(len + 8);
        buffer.extend_from_slice(&len.to_le_bytes());
        buffer.extend_from_slice(&bytes);
        
        fs::write(&config.state_file_path, &buffer)?;
        Ok(())
    }
    
    /// Clean up old state files.
    pub fn cleanup_stale_states(&self) -> Result<u64, String> {
        let config = self.config.read().unwrap();
        
        // Find all .old or .bak files
        let mut total_cleaned: u64 = 0;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        for entry in fs::read_dir(&config.state_file_path.parent().unwrap())? {
            let entry = entry?;
            let path = entry.path();
            
            if !path.exists() || !path.is_file() {
                continue;
            }
            
            let metadata = entry.metadata()?;
            let age = now - metadata.modified()?.elapsed().map(|d| d.as_secs()).unwrap_or(0);
            
            // Check if it's a stale backup file or old state
            let is_stale_backup = path.extension()
                .map(|e| e == "old" || e == "bak")
                .unwrap_or(false);
            
            let is_overdue = age > config.stale_state_ttl_seconds.as_secs();
            
            if is_stale_backup || is_overdue {
                fs::remove_file(&path)?;
                total_cleaned += 1;
            }
        }
        
        Ok(total_cleaned)
    }
    
    /// Get the current state for inspection.
    pub fn get_state(&self) -> Result<Option<RollbackState>, String> {
        self.state.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    
    #[test]
    fn test_basic_state_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_path = temp_dir.path().join("state");
        
        let config = RollbackConfig {
            state_file_path: state_path.clone(),
            ..Default::default()
        };
        
        let enforcer = RollbackEnforcer::new(config);
        
        // Initial state should be None
        assert!(enforcer.get_state().unwrap().is_none());
        
        // Prepare an update
        enforcer.prepare_update("v1.0", "v2.0").unwrap();
        
        // Should have a state now
        let state = enforcer.get_state().unwrap().unwrap();
        assert_eq!(state.last_successful_boot, "v1.0");
        assert_eq!(state.consecutive_rollbacks, 0);
    }
    
    #[test]
    fn test_serialization_roundtrip() {
        let original = RollbackState {
            last_successful_boot: "v2.5".to_string(),
            commit_timestamp: 1704067200, // Jan 1, 2024
            consecutive_rollbacks: 1,
            total_rollback_cycles: 3,
        };
        
        let bytes = original.to_bytes().unwrap();
        let loaded = RollbackState::from_bytes(&bytes).unwrap();