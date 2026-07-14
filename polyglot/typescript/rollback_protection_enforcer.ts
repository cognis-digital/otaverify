import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface UpdatePackage {
  id: string;
  version: string;
  timestamp: number;
  signatureChain: SignatureChain[];
  deltaPatch?: DeltaPatchInfo;
}

interface SignatureChain {
  algorithm: 'RSA2048' | 'ECDSA-P256';
  publicKeyHash: Buffer;
  previousSignatureHash?: Buffer;
  timestamp: number;
  nonce: string;
}

interface DeltaPatchInfo {
  baseVersion: string;
  patchType: 'full' | 'delta';
  integrityHash: string; // SHA-256 hex
  sizeBytes: number;
}

interface RollbackConfig {
  maxBackwardSteps: number;
  minForwardProgress: number;
  gracePeriodHours: number;
  signatureTTLMinutes: number;
}

interface AntiDowngradeCounter {
  currentVersion: string;
  lastStableVersion: string;
  consecutiveFailures: number;
  lastFailureTime: number;
  totalUpdatesAttempted: number;
}

interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  updatedState?: UpdatePackage;
  newCounter?: AntiDowngradeCounter;
}

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

const DEFAULT_CONFIG: RollbackConfig = {
  maxBackwardSteps: 2,
  minForwardProgress: 1,
  gracePeriodHours: 48,
  signatureTTLMinutes: 720, // 30 days
};

const STATE_FILE_NAME = '.ota_state.json';

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function parseVersion(versionStr: string): number {
  const parts = versionStr.split('.').map(Number);
  if (parts.length === 1) return parts[0];
  if (parts.length >= 2) {
    // Major.Minor format - use major * 10 + minor for comparison
    return parts[0] * 10 + parts[1];
  }
  return parts.reduce((acc, val) => acc * 100 + val, 0);
}

function versionCompare(a: string, b: string): number {
  const aNum = parseVersion(a);
  const bNum = parseVersion(b);
  if (aNum > bNum) return 1;
  if (aNum < bNum) return -1;
  return 0;
}

function isExpired(timestamp: number, ttlMinutes: number): boolean {
  const now = Date.now();
  const threshold = timestamp + (ttlMinutes * 60 * 1000);
  return now > threshold;
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

function loadState(): UpdatePackage | null {
  try {
    const statePath = path.join(process.cwd(), STATE_FILE_NAME);
    if (!fs.existsSync(statePath)) return null;
    
    const content = fs.readFileSync(statePath, 'utf-8');
    return JSON.parse(content) as UpdatePackage;
  } catch (error) {
    console.warn(`Failed to load state: ${(error as Error).message}`);
    return null;
  }
}

function saveState(state: UpdatePackage): void {
  const statePath = path.join(process.cwd(), STATE_FILE_NAME);
  
  // Ensure directory exists
  const dir = path.dirname(statePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const content = JSON.stringify(state, null, 2);
  fs.writeFileSync(statePath, content, 'utf-8');
}

function loadCounter(): AntiDowngradeCounter | null {
  try {
    const counterPath = path.join(process.cwd(), '.ota_counter.json');
    if (!fs.existsSync(counterPath)) return null;
    
    const content = fs.readFileSync(counterPath, 'utf-8');
    return JSON.parse(content) as AntiDowngradeCounter;
  } catch (error) {
    console.warn(`Failed to load counter: ${(error as Error).message}`);
    return null;
  }
}

function saveCounter(counter: AntiDowngradeCounter): void {
  const counterPath = path.join(process.cwd(), '.ota_counter.json');
  
  const dir = path.dirname(counterPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  const content = JSON.stringify(counter, null, 2);
  fs.writeFileSync(counterPath, content, 'utf-8');
}

// ============================================================================
// SIGNATURE CHAIN VERIFICATION
// ============================================================================

function verifySignatureChain(chain: SignatureChain[], currentHash?: Buffer): boolean {
  if (chain.length === 0) return false;
  
  // Verify the first signature in chain against root/public key hash
  const expectedPrevious = currentHash || chain[0].previousSignatureHash;
  
  for (let i = 0; i < chain.length; i++) {
    const sig = chain[i];
    
    // Check if this signature references the previous one correctly
    const actualPrevious = i > 0 ? chain[i - 1].signatureHash : expectedPrevious;
    
    if (!actualPrevious || !sig.previousSignatureHash) continue;
    
    if (actualPrevious.equals(sig.previousSignatureHash)) {
      // Chain is valid up to this point
    } else {
      return false;
    }
  }
  
  return true;
}

function computeSignatureHash(signature: SignatureChain): Buffer {
  const data = JSON.stringify({
    algorithm: signature.algorithm,
    nonce: signature.nonce,
    timestamp: signature.timestamp,
  });
  // In production, use actual crypto library (e.g., node:crypto)
  return Buffer.from(data);
}

// ============================================================================
// ROLLBACK PROTECTION LOGIC
// ============================================================================

function checkRollbackProtection(
  currentVersion: string,
  newVersion: string,
  config: RollbackConfig
): { allowed: boolean; reason?: string } {
  
  const diff = parseVersion(newVersion) - parseVersion(currentVersion);
  
  // Check if we're going backward beyond max steps
  if (diff < 0 && Math.abs(diff) > config.maxBackwardSteps) {
    return { 
      allowed: false, 
      reason: `Exceeds maximum rollback of ${config.maxBackwardSteps} versions` 
    };
  }
  
  // Check minimum forward progress requirement
  if (diff < config.minForwardProgress && diff > 0) {
    return { 
      allowed: false, 
      reason: `Minimum forward progress of ${config.minForwardProgress} version required` 
    };
  }
  
  return { allowed: true };
}

// ============================================================================
// ANTI-DOWNGRADE COUNTER LOGIC
// ============================================================================

function updateCounter(
  currentCounter: AntiDowngradeCounter | null,
  newVersion: string,
  result: ValidationResult
): AntiDowngradeCounter {
  
  if (!currentCounter) {
    return {
      currentVersion: newVersion,
      lastStableVersion: newVersion,
      consecutiveFailures: 0,
      lastFailureTime: 0,
      totalUpdatesAttempted: 1,
    };
  }
  
  const versionDiff = parseVersion(newVersion) - parseVersion(currentCounter.currentVersion);
  
  if (result.isValid && versionDiff >= 0) {
    // Successful forward or equal update
    return {
      ...currentCounter,
      currentVersion: newVersion,
      lastStableVersion: newVersion,
      consecutiveFailures: 0,
      totalUpdatesAttempted: currentCounter.totalUpdatesAttempted + 1,
    };
  } else if (result.isValid && versionDiff < 0) {
    // Successful downgrade within limits
    return {
      ...currentCounter,
      currentVersion: newVersion,
      lastStableVersion: Math.max(
        parseVersion(currentCounter.lastStableVersion),
        parseVersion(newVersion)
      ),
      consecutiveFailures: 0,
      totalUpdatesAttempted: currentCounter.totalUpdatesAttempted + 1,
    };
  } else {
    // Failed update or invalid downgrade
    return {
      ...currentCounter,
      currentVersion: newVersion,
      lastStableVersion: Math.max(
        parseVersion(currentCounter.lastStableVersion),
        parseVersion(newVersion)
      ),
      consecutiveFailures: (currentCounter.consecutiveFailures || 0) + 1,
      totalUpdatesAttempted: currentCounter.totalUpdatesAttempted + 1,
    };
  }
}

function checkGracePeriod(counter: AntiDowngradeCounter): boolean {
  if (!counter.lastFailureTime) return true;
  
  const now = Date.now();
  const graceMs = DEFAULT_CONFIG.gracePeriodHours * 60 * 60 * 1000;
  
  return (now - counter.lastFailureTime) >= graceMs;
}

// ============================================================================
// DELTA PATCH INTEGRITY CHECKING
// ============================================================================

function verifyDeltaPatch(
  patchInfo: DeltaPatchInfo | undefined,
  expectedHash?: string
): { valid: boolean; message?: string } {
  
  if (!patchInfo) return { valid: true }; // No delta patch required
  
  const now = Date.now();
  const expiryMs = DEFAULT_CONFIG.signatureTTLMinutes * 60 * 1000;
  
  // Check expiration
  if (now - patchInfo.timestamp > expiryMs) {
    return { 
      valid: false, 
      message: `Delta patch expired (${patchInfo.sizeBytes} bytes)` 
    };
  }
  
  // Verify integrity hash if provided
  if (expectedHash && expectedHash !== patchInfo.integrityHash) {
    return { 
      valid: false, 
      message: `Integrity mismatch for delta patch` 
    };
  }
  
  return { valid: true };
}

// ============================================================================
// MAIN ENFORCER CLASS
// ============================================================================

export class RollbackProtectionEnforcer {
  private config: RollbackConfig;
  private currentCounter: AntiDowngradeCounter | null = null;
  private currentPackage: UpdatePackage | null = null;
  
  constructor(config?: Partial<RollbackConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }
  
  async loadCurrentState(): Promise<void> {
    const state = loadState();
    if (state) {
      this.currentPackage = state;
    }
    
    const counter = loadCounter();
    if (counter) {
      this.currentCounter = counter;
    }
  }
  
  async validateAndEnforce(
    newPackage: UpdatePackage,
    expectedDeltaHash?: string
  ): Promise<ValidationResult> {
    
    // Step 1: Load current state
    await this.loadCurrentState();
    
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Step 2: Verify signature chain
    if (!verifySignatureChain(newPackage.signatureChain, this.currentPackage?.signatureChain[0]?.previousSignatureHash)) {
      errors.push('Invalid or broken signature chain');
    }
    
    // Step 3: Check rollback protection
    const rollbackCheck = checkRollbackProtection(
      this.currentCounter?.currentVersion || '0.0',
      newPackage.version,
      this.config
    );
    
    if (!rollbackCheck.allowed) {
      errors.push(rollbackCheck.reason!);
    } else {
      warnings.push(`Rollback within limits: diff=${parseVersion(newPackage.version) - parseVersion(this.currentCounter?.currentVersion || '0.0')}`);
    }
    
    // Step 4: Verify delta patch if present
    const deltaResult = verifyDeltaPatch(
      newPackage.deltaPatch,
      expectedDeltaHash
    );
    
    if (!deltaResult.valid) {
      errors.push(deltaResult.message!);
    } else {
      warnings.push(`Delta patch verified: ${newPackage.deltaPatch?.patchType || 'full'}`);
    }
    
    // Step 5: Check grace period for consecutive failures
    if (this.currentCounter && this.currentCounter.consecutiveFailures > 0) {
      const inGrace = checkGracePeriod(this.currentCounter);
      
      if (!inGrace) {
        errors.push(`Still within grace period after ${this.currentCounter.consecutiveFailures} failures`);
      } else {
        warnings.push('Grace period expired, allowing retry');
      }
    }
    
    // Step 6: Update counter and state
    const newCounter = updateCounter(
      this.currentCounter,
      newPackage.version,
      { isValid: errors.length === 0, errors, warnings }
    );
    
    if (errors.length > 0) {
      return { 
        isValid: false, 
        errors, 
        warnings,
        newCounter,
      };
    }
    
    // Success - update persisted state
    const updatedPackage = {
      ...this.currentPackage,
      signatureChain: [...newPackage.signatureChain],
      deltaPatch: newPackage.deltaPatch,
    };
    
    saveState(updatedPackage);
    saveCounter(newCounter);
    
    return { 
      isValid: true, 
      errors: [], 
      warnings,
      updatedState: updatedPackage,
      newCounter,
    };
  }
  
  async rollbackToPrevious(): Promise<ValidationResult> {
    
    if (!this.currentPackage) {
      return {
        isValid: false,
        errors: ['No previous state to roll back from'],
        warnings: [],
      };
    }
    
    const currentVersion = this.currentCounter?.currentVersion || '0.0';
    const targetVersion = this.currentPackage.version;
    
    // Check if rollback is within limits
    const diff = parseVersion(currentVersion) - parseVersion(targetVersion);
    
    if (diff > this.config.maxBackwardSteps) {
      return {
        isValid: false,
        errors: [`Rollback exceeds limit of ${this.config.maxBackwardSteps} versions`],
        warnings: [],
      };
    }
    
    // Perform rollback
    const updatedPackage = {
      ...this.currentPackage,
      signatureChain: [...this.currentPackage.signatureChain],
    };
    
    saveState(updatedPackage);
    
    return {
      isValid: true,
      errors: [],
      warnings: [`Rolled back from ${currentVersion} to ${targetVersion}`],
      updatedState: updatedPackage,
    };
  }
  
  async reset(): Promise<void> {
    saveState(null as any); // null is valid for "no state"
    saveCounter({
      currentVersion: '0.0',
      lastStableVersion: '0.0',
      consecutiveFailures: 0,
      lastFailureTime: 0,
      totalUpdatesAttempted: 0,
    });
    
    this.currentPackage = null;
    this.currentCounter = null;
  }
}

// ============================================================================
// EXPORTED TYPE FOR TYPING
// ============================================================================

export type { UpdatePackage, SignatureChain, DeltaPatchInfo };

// ============================================================================
// RUNNABLE DEMO / ENTRY POINT
// ============================================================================

async function main(): Promise<void> {
  console.log('=== OTA Rollback Protection Enforcer Demo ===\n');
  
  const enforcer = new RollbackProtectionEnforcer({ maxBackwardSteps: 3 });
  
  // Create a mock current state
  const currentState: UpdatePackage = {
    id: 'current',
    version: '2.1.0',
    timestamp: Date.now() - (7 * 24 * 60 * 60 * 1000), // 7 days ago
    signatureChain: [
      {
        algorithm: 'RSA2048',
        publicKeyHash: Buffer.from('current-root-key'),
        previousSignatureHash: Buffer.from('initial-anchor'),
        timestamp: Date.now() - (30 * 24 * 60 * 60 * 1000), // 30 days ago
        nonce: 'anchor-001',
      },
    ],
  };
  
  saveState(currentState);
  console.log('✓ Loaded current state: v' + currentState.version);
  
  // Test Case 1: Valid forward update
  const nextVersion = '2.2.0';
  const nextPackage: UpdatePackage = {
    id: 'next',
    version: nextVersion,
    timestamp: Date.now(),
    signatureChain: [
      {
        algorithm: 'RSA2048',
        publicKeyHash: Buffer.from('next-key'),
        previousSignatureHash: currentState.signatureChain[