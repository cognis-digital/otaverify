import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

type Algorithm = 'sha256' | 'sha384' | 'sha512';

interface SignatureBlock {
  id: string;
  version: number;
  timestamp: Date;
  dataHash: Buffer;
  signature: Buffer;
  previousSignature?: Buffer;
}

interface ChainConfig {
  algorithm: Algorithm;
  rootPublicKey: crypto.KeyObject | string;
  expectedRootHash?: Buffer;
  allowedClockSkewMs: number;
}

interface VerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  metadata: Record<string, unknown>;
}

interface RollbackState {
  currentVersion: number;
  history: number[];
  minAllowedDelta: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function createHash(algorithm: Algorithm): crypto.Hash {
  const hashers: Record<Algorithm, typeof crypto.Hash> = {
    sha256: crypto.createHash('sha256'),
    sha384: crypto.createHash('sha384'),
    sha512: crypto.createHash('sha512'),
  };

  if (!(algorithm in hashers)) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return hashers[algorithm] as unknown as crypto.Hash;
}

function computeDataHash(data: Buffer | string): Buffer {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return createHash('sha256').update(buffer).digest();
}

function serializeBlock(block: SignatureBlock): Buffer {
  const parts: (number | string | Date | Buffer)[] = [
    block.id,
    block.version,
    block.timestamp.getTime(),
    block.dataHash.length,
    block.previousSignature?.length || 0,
  ];

  for (const part of parts) {
    if (typeof part === 'number') {
      parts[parts.indexOf(part as any)] = part;
    } else if (part instanceof Date) {
      parts[parts.indexOf(part as any)] = part.getTime();
    } else if (Buffer.isBuffer(part)) {
      parts[parts.indexOf(part as any)] = part.length;
    }
  }

  const serialized: string[] = [];
  for (const [i, part] of parts.entries()) {
    if (typeof part === 'number') {
      serialized.push(`N${i}:${part}`);
    } else if (part instanceof Date) {
      serialized.push(`D${i}:${part.getTime()}`);
    } else if (Buffer.isBuffer(part)) {
      serialized.push(`B${i}:${part.length}`);
    } else {
      serialized.push(`S${i}:${part}`);
    }
  }

  return createHash('sha256').update(serialized.join('|')).digest();
}

function deserializeBlock(data: string): SignatureBlock {
  const parts = data.split('|');
  const block: Partial<SignatureBlock> = {};

  for (const part of parts) {
    if (part.startsWith('N')) {
      const [_, index, value] = part.match(/N(\d+):(.+)/)!;
      block[Object.keys(block)[parseInt(index)] as keyof SignatureBlock] = parseInt(value);
    } else if (part.startsWith('D')) {
      const [_, index, value] = part.match(/D(\d+):(.+)/)!;
      block[Object.keys(block)[parseInt(index)] as keyof SignatureBlock] = new Date(parseInt(value));
    } else if (part.startsWith('B')) {
      const [_, index, value] = part.match(/B(\d+):(.+)/)!;
      block[Object.keys(block)[parseInt(index)] as keyof SignatureBlock] = Buffer.from(parseInt(value), 'hex');
    } else if (part.startsWith('S')) {
      const [_, index, value] = part.match(/S(\d+):(.+)/)!;
      block[Object.keys(block)[parseInt(index)] as keyof SignatureBlock] = value;
    }
  }

  return block as SignatureBlock;
}

// ============================================================================
// ROLLBACK PROTECTION GUARD
// ============================================================================

class RollbackGuard {
  private state: RollbackState;
  private readonly minAllowedDelta: number;

  constructor(minAllowedDelta: number = 1) {
    this.minAllowedDelta = minAllowedDelta;
    this.state = {
      currentVersion: 0,
      history: [0],
      minAllowedDelta,
    };
  }

  public checkTransition(oldVersion: number, newVersion: number): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (newVersion < oldVersion) {
      const delta = oldVersion - newVersion;
      if (delta > this.minAllowedDelta) {
        errors.push(`Major rollback detected: ${oldVersion} → ${newVersion} (delta: ${delta})`);
      } else {
        warnings.push(`Minor rollback detected: ${oldVersion} → ${newVersion}`);
      }
    }

    if (newVersion > oldVersion) {
      const delta = newVersion - oldVersion;
      if (delta < this.minAllowedDelta) {
        errors.push(`Unexpected small version jump: ${oldVersion} → ${newVersion}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      metadata: { oldVersion, newVersion },
    };
  }

  public recordTransition(newVersion: number): void {
    this.state.currentVersion = newVersion;
    this.state.history.push(newVersion);
  }

  public getState(): RollbackState {
    return this.state;
  }
}

// ============================================================================
// COUNTER MANAGER (ANTI-DOWNGRADE)
// ============================================================================

class CounterManager {
  private counters: Map<string, number>;
  private readonly tolerance: number;

  constructor(tolerance: number = 100) {
    this.counters = new Map();
    this.tolerance = tolerance;
  }

  public getCounter(name: string): number {
    return this.counters.get(name) || 0;
  }

  public setCounter(name: string, value: number): void {
    if (value < this.getCounter(name)) {
      const delta = this.getCounter(name) - value;
      throw new Error(`Counter ${name} decreased by ${delta}, exceeding tolerance of ${this.tolerance}`);
    }
    this.counters.set(name, value);
  }

  public incrementCounter(name: string): void {
    this.setCounter(name, this.getCounter(name) + 1);
  }

  public reset(name: string): void {
    this.setCounter(name, 0);
  }

  public getReport(): Record<string, number> {
    return Object.fromEntries(this.counters.entries());
  }
}

// ============================================================================
// DELTA PATCH INTEGRITY CHECKER
// ============================================================================

interface DeltaPatch {
  sourceHash: Buffer;
  targetHash: Buffer;
  patchData: Buffer;
  expectedTargetState: Buffer;
}

class DeltaIntegrityChecker {
  private readonly baseImageHash: Buffer;

  constructor(baseImageHash: Buffer) {
    this.baseImageHash = baseImageHash;
  }

  public validatePatch(patch: DeltaPatch): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verify source matches expected base
    if (!patch.sourceHash.equals(this.baseImageHash)) {
      errors.push(`Source hash mismatch:\n  Expected: ${this.baseImageHash.toString('hex')}\n  Got:     ${patch.sourceHash.toString('hex')}`);
    }

    // Apply patch and verify result
    const appliedState = this.applyPatch(patch, this.baseImageHash);

    if (!appliedState.equals(patch.expectedTargetState)) {
      errors.push(`Applied state mismatch:\n  Expected: ${patch.expectedTargetState.toString('hex')}\n  Got:     ${appliedState.toString('hex')}`);
    }

    // Check for unexpected modifications
    const diff = this.computeDiff(appliedState, patch.expectedTargetState);
    if (diff.length > 0) {
      warnings.push(`Unexpected modifications detected in ${diff.length} bytes`);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      metadata: { appliedStateSize: appliedState.length },
    };
  }

  private applyPatch(patch: DeltaPatch, baseState: Buffer): Buffer {
    // Simplified patch application - in reality this would parse binary format
    const result = Buffer.alloc(baseState.length + patch.patchData.length);
    result.set(baseState, 0);
    result.set(patch.patchData, baseState.length);
    return result;
  }

  private computeDiff(state1: Buffer, state2: Buffer): Buffer {
    // XOR-based diff for binary comparison
    const maxLength = Math.max(state1.length, state2.length);
    const diff = Buffer.alloc(maxLength);

    for (let i = 0; i < maxLength; i++) {
      if (i >= state1.length || i >= state2.length) {
        diff[i] = 0xFF;
      } else if (state1[i] !== state2[i]) {
        diff[i] = state1[i] ^ state2[i];
      }
    }

    return diff;
  }
}

// ============================================================================
// SIGNATURE CHAIN VERIFIER (MAIN CLASS)
// ============================================================================

class SignatureChainVerifier extends EventEmitter {
  private config: ChainConfig;
  private rollbackGuard: RollbackGuard;
  private counterManager: CounterManager;
  private deltaChecker: DeltaIntegrityChecker;
  private loadedBlocks: Map<string, SignatureBlock>;
  private verificationLog: VerificationResult[];

  constructor(
    config: ChainConfig,
    baseImageHash: Buffer = createHash('sha256').update(Buffer.from('base-image')).digest()
  ) {
    super();
    this.config = config;
    this.rollbackGuard = new RollbackGuard();
    this.counterManager = new CounterManager();
    this.deltaChecker = new DeltaIntegrityChecker(baseImageHash);
    this.loadedBlocks = new Map();
    this.verificationLog = [];
  }

  public async loadBlock(block: SignatureBlock): Promise<VerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Verify signature against previous block (if any)
    if (block.previousSignature) {
      const prevHash = serializeBlock({
        id: '',
        version: 0,
        timestamp: new Date(0),
        dataHash: Buffer.from([]),
        signature: block.previousSignature!,
      });

      const verifyResult = this.verifySingleBlock(prevHash, block.previousSignature);
      if (!verifyResult.valid) {
        errors.push(`Previous block signature failed:\n  ${verifyResult.errors.join('\n  ')}`);
      } else {
        warnings.push('Previous block verified successfully');
      }
    }

    // Verify current block
    const currentHash = serializeBlock(block);
    const currentVerify = this.verifySingleBlock(currentHash, block.signature);

    if (!currentVerify.valid) {
      errors.push(`Current block signature failed:\n  ${currentVerify.errors.join('\n  ')}`);
    } else {
      warnings.push('Current block verified successfully');
    }

    // Update rollback state
    const transitionResult = this.rollbackGuard.checkTransition(0, block.version);
    if (!transitionResult.valid) {
      errors.push(`Rollback check failed:\n  ${transitionResult.errors.join('\n  ')}`);
    } else {
      this.rollbackGuard.recordTransition(block.version);
    }

    // Update counters
    const counterName = `block_${block.id}`;
    try {
      this.counterManager.setCounter(counterName, block.version);
    } catch (err: unknown) {
      errors.push(`Counter update failed:\n  ${(err as Error).message}`);
    }

    // Store loaded block
    this.loadedBlocks.set(block.id, block);

    const result = {
      valid: errors.length === 0,
      errors,
      warnings,
      metadata: {
        blockId: block.id,
        version: block.version,
        timestamp: block.timestamp.toISOString(),
        ...transitionResult.metadata,
      },
    };

    this.verificationLog.push(result);
    return result;
  }

  public async loadChain(blocks: SignatureBlock[]): Promise<VerificationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const block of blocks) {
      const result = await this.loadBlock(block);
      if (!result.valid) {
        errors.push(`Block ${block.id}:\n  ${result.errors.join('\n  ')}`);
      } else {
        warnings.push(`Block ${block.id}: OK`);
      }

      // Check root hash against expected (for first block)
      if (!this.config.expectedRootHash && !block.previousSignature) {
        const computedRoot = createHash('sha256')
          .update(serializeBlock(block))
          .digest();
        this.config.expectedRootHash = computedRoot;
      }

      // Verify root hash matches expected (for last block)
      if (this.config.expectedRootHash && !block.previousSignature) {
        const computedRoot = createHash('sha256')
          .update(serializeBlock(block))
          .digest();
        if (!computedRoot.equals(this.config.expectedRootHash!)) {
          errors.push(`Root hash mismatch:\n  Expected: ${this.config.expectedRootHash!.toString('hex')}\n  Computed: ${computedRoot.toString('hex')}`);
        }
      }
    }

    const result = {
      valid: errors.length === 0,
      errors,
      warnings,
      metadata: {
        totalBlocks: blocks.length,
        finalVersion: this.rollbackGuard.getState().currentVersion,
        counterReport: this.counterManager.getReport(),
      },
    };

    return result;
  }

  public verifySingleBlock(dataHash: Buffer, signature: Buffer): VerificationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Create verifier using RSA-PKCS1v15 padding (most common for OTA)
    const algorithm = this.config.algorithm;
    let publicKey: crypto.KeyObject | undefined;

    if (typeof this.config.rootPublicKey === 'string') {
      publicKey = crypto.createPublicKey(this.config.rootPublicKey);
    } else {
      publicKey = this.config.rootPublicKey as unknown as crypto.KeyObject;
    }

    const verifier = crypto.createVerify(algorithm);
    verifier.update(dataHash);

    if (!verifier.verify(publicKey, signature)) {
      errors.push(`RSA verification failed for algorithm: ${algorithm}`);
    } else {
      warnings.push('RSA verification passed');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      metadata: { algorithm },
    };
  }

  public getVerificationLog(): VerificationResult[] {
    return this.verificationLog;
  }

  public reset(): void {
    this.rollbackGuard = new RollbackGuard();
    this.counterManager = new CounterManager();
    this.loadedBlocks.clear();
    this.verificationLog = [];
  }

  public exportReport(): string {
    const report: Record<string, unknown> = {
      config: this.config,
      rollbackState: this.rollbackGuard.getState(),
      counters: this.counterManager.getReport(),
      log: this.verificationLog.map((log) => ({
        valid: log.valid,
        errorCount: log.errors.length,
        warningCount: log.warnings.length,
        metadata: log.metadata,
      })),
    };

    return JSON.stringify(report, null, 2);
  }
}

// ============================================================================
// FACTORY & CONVENIENCE FUNCTIONS
// ============================================================================

function createVerifier(
  publicKeyPem: string,
  algorithm: Algorithm = 'sha256',
  expectedRootHash?: Buffer,
  allowedClockSkewMs: number = 5000
): SignatureChainVerifier {
  return new SignatureChainVerifier({
    algorithm,
    rootPublicKey: publicKeyPem,
    expectedRootHash,
    allowedClockSkewMs,
  });
}

function createBlock(
  id: string,
  version: number,
  dataHash: Buffer,
  signature: Buffer,
  previousSignature?: Buffer,
  timestamp: Date = new Date()
): SignatureBlock {
  return {
    id,
    version,
    timestamp,
    dataHash,
    signature,
    ...(previousSignature ?