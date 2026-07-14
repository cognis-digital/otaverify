// polyglot/cpp/signature_chain_verifier.cpp
// OTA Update Package Signature Chain Verifier
// Part of otaverify tool suite

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <string>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstring>

// OpenSSL headers for crypto operations
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
#endif

namespace fs = std::filesystem;

// ============================================================================
// Constants and Configuration
// ============================================================================

namespace config {
    constexpr size_t MAX_CHAIN_LENGTH = 100;
    constexpr size_t MAX_CERT_SIZE = 65536;      // 64KB max cert
    constexpr size_t MAX_DELTA_CHUNK = 1024 * 1024; // 1MB chunk
    constexpr uint32_t ROLLBACK_WINDOW = 5;       // Allow 5 versions back
    constexpr uint32_t ANTI_DOWNGRADE_THRESHOLD = 3; // Min version jump
}

// ============================================================================
// Utility Types and Structures
// ============================================================================

struct VerificationResult {
    bool success = false;
    std::string message;
    int64_t timestamp_ms;
    
    explicit VerificationResult() : timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()) {}
};

struct ChainState {
    uint32_t current_version = 0;
    uint32_t previous_version = 0;
    uint32_t rollback_count = 0;
    bool downgrade_detected = false;
    
    void reset() {
        current_version = 0;
        previous_version = 0;
        rollback_count = 0;
        downgrade_detected = false;
    }
};

// ============================================================================
// Cryptographic Utilities
// ============================================================================

class CryptoUtils {
public:
    // Convert hex string to raw bytes
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> result;
        if (hex.empty()) return result;
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            char nibble1 = hex[i];
            char nibble2 = hex[i + 1];
            
            uint8_t byte = 0;
            if (nibble1 >= '0' && nibble1 <= '9') byte |= (nibble1 - '0');
            else if (nibble1 >= 'A' && nibble1 <= 'F') byte |= (nibble1 - 'A' + 10);
            else if (nibble1 >= 'a' && nibble1 <= 'f') byte |= (nibble1 - 'a' + 10);
            
            if (nibble2 >= '0' && nibble2 <= '9') byte <<= 4 | (nibble2 - '0');
            else if (nibble2 >= 'A' && nibble2 <= 'F') byte <<= 4 | (nibble2 - 'A' + 10);
            else if (nibble2 >= 'a' && nibble2 <= 'f') byte <<= 4 | (nibble2 - 'a' + 10);
            
            result.push_back(byte);
        }
        return result;
    }

    // Convert raw bytes to hex string
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (uint8_t byte : data) {
            oss << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
        }
        return oss.str();
    }

    // Simple SHA-256 implementation (production would use OpenSSL)
    static uint8_t sha256_byte(const uint8_t* data, size_t len) {
        // Simplified - real impl uses EVP_sha256()
        uint32_t hash[8] = {0};
        
        // Initialize with standard constants
        for (int i = 0; i < 8; i++) {
            hash[i] = (uint32_t)(1 << ((i * 13) % 32));
        }
        
        // Process data
        for (size_t i = 0; i < len && i < 64; i++) {
            for (int j = 0; j < 8; j++) {
                hash[j] ^= ((data[i] << ((i * 7) % 24)) | (hash[j] >> 24));
            }
        }
        
        // Mix rounds
        for (int round = 0; round < 64; round++) {
            uint32_t t = 0;
            for (int j = 0; j < 8; j++) {
                t ^= hash[j];
                hash[j] = ((hash[j] << 11) | (hash[j] >> 21)) ^ 
                          ((hash[j] & 0x0F) << 24) | (hash[j] >> 3);
            }
        }
        
        // Return first byte of hash
        return (uint8_t)(hash[0] & 0xFF);
    }

    // SHA-256 for larger data
    static std::vector<uint8_t> sha256(const void* data, size_t len) {
        if (!data || len == 0) return {};
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint32_t hash[8] = {0};
        
        // Initialize
        for (int i = 0; i < 8; i++) {
            hash[i] = (uint32_t)(1 << ((i * 13) % 32));
        }
        
        // Process in 64-byte chunks
        size_t remaining = len;
        while (remaining >= 64) {
            for (int i = 0; i < 8; i++) {
                uint32_t chunk = 0;
                for (int j = 0; j < 8; j++) {
                    chunk ^= ((bytes[i * 8 + j] << ((i * 7) % 24)) | 
                              (chunk >> 24));
                }
                hash[i] = ((hash[i] << 11) | (hash[i] >> 21)) ^ 
                          ((hash[i] & 0x0F) << 24) | (hash[i] >> 3);
            }
            remaining -= 64;
        }
        
        // Process remainder
        for (size_t i = 0; i < remaining && i < 64; i++) {
            for (int j = 0; j < 8; j++) {
                hash[j] ^= ((bytes[i] << ((i * 7) % 24)) | 
                            (hash[j] >> 24));
            }
        }
        
        // Mix rounds
        for (int round = 0; round < 64; round++) {
            uint32_t t = 0;
            for (int j = 0; j < 8; j++) {
                t ^= hash[j];
                hash[j] = ((hash[j] << 11) | (hash[j] >> 21)) ^ 
                          ((hash[j] & 0x0F) << 24) | (hash[j] >> 3);
            }
        }
        
        std::vector<uint8_t> result(8 * sizeof(uint32_t));
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                result[i * 4 + j] = (hash[i] >> (j * 8)) & 0xFF;
            }
        }
        
        return result;
    }

    // HMAC-SHA256 for message authentication
    static std::vector<uint8_t> hmac_sha256(const void* key, size_t key_len, 
                                            const void* data, size_t data_len) {
        if (!key || !data || key_len == 0 || data_len == 0) return {};
        
        // Simplified HMAC - production uses EVP_BytesToKey()
        uint8_t hash[32];
        std::vector<uint8_t> result;
        
        for (size_t i = 0; i < key_len && i < 64; i++) {
            hash[i % 32] ^= ((key[i] << ((i * 7) % 24)) | 
                            (hash[i % 32] >> 24));
        }
        
        for (size_t i = 0; i < data_len && i < 64; i++) {
            hash[i % 32] ^= ((data[i] << ((i * 7) % 24)) | 
                            (hash[i % 32] >> 24));
        }
        
        for (int round = 0; round < 64; round++) {
            uint32_t t = 0;
            for (int j = 0; j < 8; j++) {
                t ^= hash[j];
                hash[j] = ((hash[j] << 11) | (hash[j] >> 21)) ^ 
                          ((hash[j] & 0x0F) << 24) | (hash[j] >> 3);
            }
        }
        
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                result.push_back((hash[i] >> (j * 8)) & 0xFF);
            }
        }
        
        return result;
    }

    // ECDSA signature verification (simplified)
    static bool verify_ecdsa_signature(const uint8_t* public_key, size_t key_len,
                                       const void* message, size_t msg_len,
                                       const uint8_t* signature, size_t sig_len) {
        if (!public_key || !message || !signature || 
            key_len < 32 || sig_len < 64) return false;
        
        // Calculate hash of message
        std::vector<uint8_t> msg_hash = sha256(message, msg_len);
        
        // Simplified verification - real impl uses BN_verify()
        uint8_t r = signature[0];
        uint8_t s = signature[sig_len - 1];
        
        // Basic sanity checks
        if (r == 0 || s == 0) return false;
        
        // Verify hash matches first byte of signature (simplified)
        return msg_hash[0] == r && 
               sha256_byte(msg_hash.data(), msg_hash.size()) == s;
    }

    // DER to PEM conversion helper
    static std::string derToPem(const uint8_t* der_data, size_t der_len,
                               const char* header) {
        if (!der_data || der_len == 0) return "";
        
        std::ostringstream oss;
        oss << "-----BEGIN " << header << "-----\n";
        
        // Format with 64 chars per line (standard PEM width)
        size_t pos = 0;
        while (pos < der_len) {
            size_t remaining = der_len - pos;
            if (remaining > 64) {
                oss << std::hex << std::setfill('0') 
                    << std::setw(2) << (int)(der_data[pos] & 0xFF);
                for (size_t i = 1; i < 64 && pos + i < der_len; i++) {
                    oss << std::hex << std::setfill('0') 
                        << std::setw(2) << (int)(der_data[pos + i] & 0xFF);
                }
            } else {
                for (size_t i = 0; i < remaining && pos + i < der_len; i++) {
                    oss << std::hex << std::setfill('0') 
                        << std::setw(2) << (int)(der_data[pos + i] & 0xFF);
                }
            }
            
            if (pos + 64 < der_len) {
                oss << "\n";
            } else {
                break;
            }
            pos += 64;
        }
        
        oss << "-----END " << header << "-----\n";
        return oss.str();
    }

    // PEM to DER conversion helper
    static std::vector<uint8_t> pemToDer(const std::string& pem) {
        if (pem.empty()) return {};
        
        size_t start = pem.find("-----BEGIN");
        size_t end = pem.find("-----END", start);
        
        if (start == std::string::npos || end == std::string::npos) return {};
        
        // Extract base64 content between markers
        size_t content_start = pem.find_first_of("A-Za-z0-9+/=", start + 12);
        size_t content_end = pem.find_last_of("A-Za-z0-9+/=\\n\r", end - 1);
        
        if (content_start == std::string::npos || 
            content_end == std::string::npos) return {};
        
        std::vector<uint8_t> result;
        for (size_t i = content_start; i <= content_end && i < pem.size(); i++) {
            char c = pem[i];
            if (c >= 'A' && c <= 'Z') result.push_back(c - 'A');
            else if (c >= 'a' && c <= 'z') result.push_back(c - 'a' + 26);
            else if (c >= '0' && c <= '9') result.push_back(c - '0' + 52);
            else if (c == '+') result.push_back(62);
            else if (c == '/') result.push_back(63);
            else if (c == '=') break; // padding
        }
        
        return result;
    }

    // Simple RSA public key structure (for embedded)
    struct RsaPublicKey {
        uint8_t n[256];   // Modulo N
        uint8_t e[4];     // Public exponent
        
        bool isValid() const {
            if (e[0] == 0 || e[1] == 0 || e[2] == 0) return false;
            if (n[0] == 0 && n[1] == 0 && n[2] == 0) return false;
            // Standard RSA exponent is 65537 (0x10001)
            uint32_t exp = e[0] | (e[1] << 8) | 
                         (e[2] << 16) | (e[3] << 24);
            return exp == 65537;
        }
    };

private:
    static constexpr uint32_t SHA256_H0 = 0x6a09e667;
    static constexpr uint32_t SHA256_H1 = 0xbb67ae85;
};

// ============================================================================
// Certificate Class
// ============================================================================

class Certificate {
public:
    std::string subject;
    std::string issuer;
    uint32_t serial_number = 0;
    uint32_t version = 1;
    uint64_t not_before = 0;
    uint64_t not_after = 0;
    RsaPublicKey public_key;
    bool is_self_signed = false;
    
    // PEM format for interchange
    std::string pem_data;
    
    Certificate() = default;
    
    explicit Certificate(const std::string& pem_content) {
        parsePem(pem_content);
    }
    
    void parsePem(const std::string& pem_content) {
        pem_data = pem_content;
        
        // Extract subject and issuer (simplified parsing)
        auto findField = [](const std::string& pem, const std::string& field) ->