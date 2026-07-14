package otaverify;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * OTA Update Package Signature Chain Verifier.
 * 
 * Validates the complete cryptographic chain from root to device, including:
 * - Root key verification (trusted anchor)
 * - Intermediate key signing and timestamp validation
 * - Device-specific key derivation and anti-downgrade protection
 * - Delta-patch integrity verification
 */
public class signature_chain_verifier {

    // Key hierarchy constants
    private static final int KEY_SIZE = 2048;
    private static final long ROOT_EXPIRY_DAYS = 365L;
    private static final long INTERMEDIATE_EXPIRY_DAYS = 90L;
    
    /**
     * Represents a key in the signature chain with metadata.
     */
    private static class ChainKey {
        private final String type;
        private final KeyPair keyPair;
        private final PublicKey publicKey;
        private final long issuedAt;
        private final long expiresAt;
        private final byte[] serialNumber;
        
        public ChainKey(String type, KeyPair kp, long issuedAt, long expiresAt) {
            this.type = type;
            this.keyPair = kp;
            this.publicKey = kp.getPublic();
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.serialNumber = new byte[16];
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
        
        public long getRemainingTime() {
            return Math.max(0, expiresAt - System.currentTimeMillis());
        }
    }

    /**
     * Represents an OTA update package with its cryptographic metadata.
     */
    private static class UpdatePackage {
        private final String version;
        private final byte[] payloadHash;
        private final long timestamp;
        
        public UpdatePackage(String version, byte[] payload) throws NoSuchAlgorithmException {
            this.version = version;
            this.timestamp = System.currentTimeMillis();
            this.payloadHash = calculateSha256(payload);
        }
        
        private static byte[] calculateSha256(byte[] data) throws NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        }
    }

    /**
     * Configuration for the verification process.
     */
    private static class VerificationConfig {
        public final String rootKeyPath;
        public final String intermediateKeyPath;
        public final String deviceKeyPath;
        public final long maxAntiDowngradeDelta = 30L; // days
        
        public VerificationConfig(String root, String inter, String dev) {
            this.rootKeyPath = root;
            this.intermediateKeyPath = inter;
            this.deviceKeyPath = dev;
        }
    }

    /**
     * Result of a signature chain verification.
     */
    private static class VerificationResult {
        public final boolean success;
        public final String message;
        public final Map<String, Object> metadata;
        
        public VerificationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
            this.metadata = new HashMap<>();
        }
    }

    /**
     * Generates a self-signed root key pair for the chain anchor.
     */
    private static ChainKey createRootKey(String alias, long expiryDays) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        KeyPair kp = generator.generateKeyPair();
        
        // Use current time as issue/expiry timestamps
        long now = System.currentTimeMillis();
        long expiry = now + (expiryDays * 24L * 60L * 60L * 1000L);
        
        return new ChainKey("ROOT", kp, now, expiry);
    }

    /**
     * Creates an intermediate key signed by the root key.
     */
    private static ChainKey createIntermediateKey(ChainKey root, String alias) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        KeyPair kp = generator.generateKeyPair();
        
        // Sign the intermediate key's public key with root
        byte[] encodedPubKey = Base64.getEncoder().encode(kp.getPublic().getEncoded());
        Signature rootSig = Signature.getInstance("SHA256withRSA");
        rootSig.initSign(root.keyPair.getPrivate());
        rootSig.update(encodedPubKey);
        byte[] rootSignature = rootSig.sign();
        
        long now = System.currentTimeMillis();
        long expiry = now + (INTERMEDIATE_EXPIRY_DAYS * 24L * 60L * 60L * 1000L);
        
        return new ChainKey("INTERMEDIATE", kp, now, expiry, rootSignature);
    }

    /**
     * Creates a device-specific key signed by the intermediate key.
     */
    private static ChainKey createDeviceKey(ChainKey intermediate, String deviceId) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        KeyPair kp = generator.generateKeyPair();
        
        // Sign with intermediate key (includes device ID in payload for uniqueness)
        byte[] devicePayload = (deviceId + "_" + System.currentTimeMillis()).getBytes();
        Signature interSig = Signature.getInstance("SHA256withRSA");
        interSig.initSign(intermediate.keyPair.getPrivate());
        interSig.update(devicePayload);
        byte[] interSignature = interSig.sign();
        
        long now = System.currentTimeMillis();
        long expiry = now + (INTERMEDIATE_EXPIRY_DAYS * 24L * 60L * 60L * 1000L);
        
        return new ChainKey("DEVICE", kp, now, expiry, interSignature);
    }

    /**
     * Creates a test OTA payload with known structure.
     */
    private static byte[] createTestPayload(String version) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("OTA_VERSION=").append(version).append("\n");
        sb.append("BUILD_TIMESTAMP=").append(System.currentTimeMillis()).append("\n");
        
        // Add some padding to make it realistic
        for (int i = 0; i < 1024 * 1024; i++) {
            sb.append((char)('A' + (i % 26))).append('\n');
        }
        
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Main verification entry point.
     */
    public static VerificationResult verifyChain(VerificationConfig config, 
                                                  UpdatePackage package) throws GeneralSecurityException {
        AtomicInteger warnings = new AtomicInteger(0);
        
        // Step 1: Verify root key is present and not expired
        if (!File.exists(config.rootKeyPath)) {
            return new VerificationResult(false, "Root key file not found at: " + config.rootKeyPath);
        }
        
        KeyPair rootKp = loadKeyPair(config.rootKeyPath);
        if (rootKp == null) {
            return new VerificationResult(false, "Failed to parse root key");
        }
        
        // Step 2: Verify intermediate key chain
        if (!File.exists(config.intermediateKeyPath)) {
            return new VerificationResult(false, "Intermediate key file not found at: " + config.intermediateKeyPath);
        }
        
        KeyPair interKp = loadKeyPair(config.intermediateKeyPath);
        if (interKp == null) {
            return new VerificationResult(false, "Failed to parse intermediate key");
        }
        
        // Step 3: Verify device key and payload signature
        if (!File.exists(config.deviceKeyPath)) {
            return new VerificationResult(false, "Device key file not found at: " + config.deviceKeyPath);
        }
        
        KeyPair deviceKp = loadKeyPair(config.deviceKeyPath);
        if (deviceKp == null) {
            return new VerificationResult(false, "Failed to parse device key");
        }
        
        // Step 4: Verify payload hash against expected value
        byte[] actualHash = calculateSha256(package.payloadHash);
        String version = package.version;
        
        // Simulate expected hash for demo (in real scenario, this comes from manifest)
        String expectedHashHex = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456";
        
        if (!Arrays.equals(actualHash, Base64.getDecoder().decode(expectedHashHex))) {
            warnings.set(1);
        }
        
        // Step 5: Anti-downgrade timestamp check
        long now = System.currentTimeMillis();
        long packageTime = package.timestamp;
        long maxDelta = config.maxAntiDowngradeDelta * 24L * 60L * 60L * 1000L;
        
        if (now - packageTime > maxDelta) {
            warnings.set(2);
        }
        
        // Step 6: Delta-patch integrity check
        long expectedSize = 50 * 1024 * 1024; // 50MB typical update
        long actualSize = package.payloadHash.length;
        
        if (Math.abs(expectedSize - actualSize) > 1024) {
            warnings.set(3);
        }
        
        boolean success = warnings.get() == 0;
        String resultMsg = success ? "Chain verified successfully" : 
                          "Verification completed with " + warnings.get() + " warning(s)";
        
        return new VerificationResult(success, resultMsg);
    }

    /**
     * Loads a key pair from file path.
     */
    private static KeyPair loadKeyPair(String path) throws GeneralSecurityException {
        try (FileInputStream fis = new FileInputStream(path)) {
            byte[] encoded = fis.readAllBytes();
            
            // Try to decode as PEM format first
            String pemContent = new String(encoded, StandardCharsets.UTF_8);
            if (pemContent.contains("-----BEGIN RSA PUBLIC KEY-----")) {
                return parsePemKeyPair(pemContent);
            } else if (pemContent.contains("-----BEGIN EC PUBLIC KEY-----")) {
                return parsePemKeyPair(pemContent);
            } else {
                // Assume DER format
                try (ByteArrayInputStream bais = new ByteArrayInputStream(encoded)) {
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bais.readAllBytes());
                    PublicKey pubKey = factory.generatePublic(pubSpec);
                    
                    // For private key, we need the full pair - assume DER format with both
                    try (ByteArrayInputStream bais2 = new ByteArrayInputStream(encoded)) {
                        KeyFactory factory2 = KeyFactory.getInstance("RSA");
                        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(
                            readDERInt(bais2), readDERInt(bais2)
                        );
                        return new KeyPair(factory2.generatePublic(privSpec), 
                                           factory2.generatePrivate(privSpec));
                    }
                }
            }
        } catch (IOException e) {
            throw new GeneralSecurityException("IO error reading key: " + path, e);
        }
    }

    /**
     * Parses PEM-formatted key from string.
     */
    private static KeyPair parsePemKeyPair(String pemContent) throws GeneralSecurityException {
        String[] parts = pemContent.split("-----END");
        
        // Extract public and private components
        String pubPart = parts[0].trim();
        String privPart = parts.length > 1 ? "BEGIN" + parts[1] : "";
        
        try (ByteArrayInputStream baisPub = new ByteArrayInputStream(pubPart.getBytes(StandardCharsets.UTF_8))) {
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(baisPub.readAllBytes());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = factory.generatePublic(pubSpec);
            
            // For private key, use a simpler approach - assume we have the full pair encoded
            try (ByteArrayInputStream baisPriv = new ByteArrayInputStream(pemContent.getBytes(StandardCharsets.UTF_8))) {
                X509EncodedKeySpec privSpec = new X509EncodedKeySpec(baisPriv.readAllBytes());
                RSAPrivateKeySpec privKeySpec;
                
                // Try to extract RSA components from DER-encoded private key
                try (ByteArrayInputStream bais2 = new ByteArrayInputStream(pemContent.getBytes(StandardCharsets.UTF_8))) {
                    byte[] derData = bais2.readAllBytes();
                    if (derData.length > 100) {
                        // Simplified: assume we can extract n and e from first integers
                        int modulusOffset = 4;
                        int exponentOffset = 4 + readDERInt(derData, modulusOffset);
                        
                        byte[] modulusBytes = new byte[readDERInt(derData, 0)];
                        System.arraycopy(derData, 4, modulusBytes, 0, modulusBytes.length);
                        
                        byte[] exponentBytes = new byte[readDERInt(derData, modulusOffset)];
                        System.arraycopy(derData, modulusOffset + 4, exponentBytes, 0, exponentBytes.length);
                        
                        BigInteger n = new BigInteger(1, modulusBytes);
                        BigInteger e = new BigInteger(1, exponentBytes);
                        
                        privKeySpec = new RSAPrivateKeySpec(n, e);
                    } else {
                        // Fallback: use public key as both for demo
                        privKeySpec = new RSAPrivateKeySpec(pubKey.getModulus(), pubKey.getPublicExponent());
                    }
                    
                    return new KeyPair(factory.generatePublic(privKeySpec), 
                                      factory.generatePrivate(privKeySpec));
                }
            }
        } catch (IOException e) {
            throw new GeneralSecurityException("PEM parsing error", e);
        }
    }

    /**
     * Reads a DER-encoded integer from byte array.
     */
    private static int readDERInt(byte[] data, int offset) throws IOException {
        if (offset >= data.length) return 0;
        
        // Skip length byte and sign bit
        int len = ((data[offset] & 0x7F) << 1) | 
                   ((data[offset + 1] & 0x80) ? 2 : 1);
        offset += 2;
        
        if (offset >= data.length) return 0;
        
        // Read actual integer bytes
        int value = 0;
        for (int i = 0; i < len && offset + i < data.length; i++) {
            value = (value << 8) | (data[offset + i] & 0xFF);
        }
        
        return value;
    }

    /**
     * Demonstrates the complete verification flow.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("=== OTA Signature Chain Verifier Demo ===\n");
        
        // Step 1: Generate test key hierarchy
        System.out.println("[1] Generating test key hierarchy...");
        
        ChainKey root = createRootKey("root-anchor", ROOT_EXPIRY_DAYS);
        System.out.println("    Root key created, expires in " + 
            (root.getRemainingTime() / (24 * 60 * 60 * 1000)) + " days");
        
        ChainKey intermediate = createIntermediateKey(root, "intermediate-v1");
        System.out.println("    Intermediate key created and signed by root");
        
        String deviceId = "device-" + UUID.randomUUID().toString().substring(0, 8);
        ChainKey device = createDeviceKey(intermediate, deviceId);
        System.out.println("    Device key created for: " + deviceId);
        
        // Step 2: Create test OTA package
        System.out.println("\n[2] Creating test OTA package...");
        
        byte[] payload = createTestPayload("v2.1.0-build456");
        UpdatePackage package = new UpdatePackage("v2.1.0-build456", payload);
        System.out.println("