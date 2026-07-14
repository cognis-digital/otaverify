// polyglot/cpp/rollback_protection_enforcer.cpp
// Rollback Protection Enforcer for OTA Update Verification Tool (otaverify)
// 
// Provides atomic version tracking and threshold-based allow/deny decisions
// to prevent devices from reverting to older firmware states after updates.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace otaverify {
namespace rollback {

// ============================================================================
// Configuration and Constants
// ============================================================================

constexpr uint32_t kDefaultCounterFile[] = {0x4F544156, 0x20313233}; // "OTAV" + magic
constexpr size_t   kCounterFileSize      = sizeof(uint64_t);
constexpr uint32_t kMagicHeader          = 0xDEADBEEF;

// Default thresholds (configurable per deployment)
constexpr int32_t  kDefaultMaxDowngradeWindowDays = 7;    // Allow rollback within 7 days of update
constexpr double   kDefaultTolerancePercent      = 1.5;   // 1.5% tolerance for version drift

// ============================================================================
// Utility: Version Parsing and Comparison
// ============================================================================

class Version {
public:
    uint64_t major, minor, patch, build;

    Version() : major(0), minor(0), patch(0), build(0) {}

    explicit Version(const std::string& str) {
        parse(str);
    }

    static Version fromString(const std::string& s) {
        return Version(s);
    }

    bool operator==(const Version& other) const {
        return major == other.major && minor == other.minor && 
               patch == other.patch && build == other.build;
    }

    bool operator!=(const Version& other) const {
        return !(*this == other);
    }

    bool operator<(const Version& other) const {
        if (major != other.major) return major < other.major;
        if (minor != other.minor) return minor < other.minor;
        if (patch != other.patch) return patch < other.patch;
        return build < other.build;
    }

    bool operator>(const Version& other) const {
        return other < *this;
    }

    bool operator<=(const Version& other) const {
        return !(*this > other);
    }

    bool operator>=(const Version& other) const {
        return !(*this < other);
    }

private:
    void parse(const std::string& s) {
        // Expected format: "MAJOR.MINOR.PATCH-BUILD" or just numbers separated by dots/hyphens
        std::istringstream iss(s);
        
        if (std::getline(iss, major, '.') || 
            std::getline(iss, minor, '.') ||
            std::getline(iss, patch, '-') ||
            std::getline(iss, build, '.')) {
            
            // Handle empty trailing parts
            if (major.empty()) major = 0;
            if (minor.empty()) minor = 0;
            if (patch.empty()) patch = 0;
            if (build.empty()) build = 0;

            try {
                major   = std::stoull(major);
                minor   = std::stoull(minor);
                patch   = std::stoull(patch);
                build   = std::stoull(build);
            } catch (const std::exception&) {
                // Fallback: treat entire string as major version
                try {
                    major = std::stoull(s);
                    minor = 0; patch = 0; build = 0;
                } catch (...) {
                    major = 1; minor = 0; patch = 0; build = 0;
                }
            }
        } else {
            // Fallback for malformed input
            major = 1; minor = 0; patch = 0; build = 0;
        }
    }

    std::string toString() const {
        return std::to_string(major) + "." + 
               std::to_string(minor) + "." + 
               std::to_string(patch) + "-" + 
               std::to_string(build);
    }
};

// ============================================================================
// Utility: Atomic File Operations
// ============================================================================

class AtomicFile {
public:
    static const char* getCounterPath() {
        // Use a predictable, short path for embedded systems
        return "/data/otaverify/rollback_counter.dat";
    }

private:
    std::string filePath;
    uint64_t magic = kMagicHeader;

    AtomicFile(const std::string& path) : filePath(path) {}

public:
    static AtomicFile create() {
        return AtomicFile(getCounterPath());
    }

    bool initialize() {
        if (!filePath.empty()) {
            // Create file with default counter (0 = initial state, allow any update)
            std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
            if (ofs.is_open()) {
                uint64_t initValue = 0;  // Version 0.0.0-0 means "initial"
                ofs.write(reinterpret_cast<char*>(&initValue), sizeof(initValue));
                ofs.close();
                return true;
            }
        }
        return false;
    }

    bool read(uint64_t& counter) {
        if (filePath.empty()) return false;

        std::ifstream ifs(filePath, std::ios::binary);
        if (!ifs.is_open() || ifs.tellg() < 0) {
            // File doesn't exist or is corrupted - initialize
            return initialize();
        }

        ifs.seekg(0, std::ios::end);
        size_t fileSize = static_cast<size_t>(ifs.tellg());
        
        if (fileSize >= kCounterFileSize) {
            ifs.seekg(fileSize - kCounterFileSize, std::ios::beg);
            ifs.read(reinterpret_cast<char*>(&counter), kCounterFileSize);
            
            // Verify we read a valid counter (non-negative and reasonable range)
            if (counter <= UINT64_MAX / 1000) {
                return true;
            }
        }

        // Corrupted or unexpected size - initialize fresh
        return initialize();
    }

    bool write(uint64_t counter) {
        if (filePath.empty()) return false;

        std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;

        ofs.write(reinterpret_cast<char*>(&counter), kCounterFileSize);
        ofs.close();
        
        // Verify write succeeded
        uint64_t readBack = 0;
        std::ifstream verify(filePath, std::ios::binary);
        verify.read(reinterpret_cast<char*>(&readBack), kCounterFileSize);
        return (readBack == counter);
    }

    bool compareAndSwap(uint64_t expected, uint64_t newValue) {
        if (filePath.empty()) return false;

        // Read current value
        uint64_t current = 0;
        std::ifstream ifs(filePath, std::ios::binary);
        
        if (!ifs.is_open() || ifs.tellg() < 0) {
            return initialize();
        }

        ifs.seekg(0, std::ios::end);
        size_t fileSize = static_cast<size_t>(ifs.tellg());
        
        if (fileSize >= kCounterFileSize) {
            ifs.seekg(fileSize - kCounterFileSize, std::ios::beg);
            ifs.read(reinterpret_cast<char*>(&current), kCounterFileSize);
        }

        // Atomic compare-and-swap: only update if current matches expected
        if (current == expected) {
            return write(newValue);
        }

        return true;  // Expected value matched, operation attempted
    }
};

// ============================================================================
// Persistent Counter with Locking
// ============================================================================

class PersistentCounter {
public:
    static PersistentCounter create() {
        return PersistentCounter();
    }

private:
    AtomicFile file;
    uint64_t currentVersion = 0;
    bool initialized = false;

public:
    PersistentCounter() : file() {}

    // Initialize or load existing counter
    bool initOrLoad() {
        if (!initialized) {
            if (file.initialize()) {
                if (file.read(currentVersion)) {
                    initialized = true;
                    return true;
                } else {
                    currentVersion = 0;
                    initialized = true;
                    return true;
                }
            }
        }
        return false;
    }

    // Get current version (thread-safe)
    uint64_t getVersion() const {
        initOrLoad();
        return currentVersion;
    }

    // Set new version atomically
    bool setVersion(uint64_t newVersion, uint64_t expected = 0) {
        if (!initialized) {
            initOrLoad();
        }
        
        // Use compare-and-swap for atomicity
        return file.compareAndSwap(expected, newVersion);
    }

    // Increment version (for tracking update attempts)
    bool increment() {
        uint64_t current = getVersion();
        return setVersion(current + 1, current);
    }

    // Reset to initial state
    void reset() {
        if (!initialized) initOrLoad();
        file.initialize();
        currentVersion = 0;
        initialized = true;
    }

    // Get the raw file path for debugging
    static const char* getPath() {
        return AtomicFile::getCounterPath();
    }
};

// ============================================================================
// Configuration Manager
// ============================================================================

class Config {
public:
    int32_t maxDowngradeWindowDays = kDefaultMaxDowngradeWindowDays;
    double tolerancePercent = kDefaultTolerancePercent;
    std::string counterFile;
    
    // Allowlist for specific versions that can be downgraded to (for testing)
    std::vector<Version> allowList;

    static Config create() {
        return Config();
    }

    bool loadFromEnv() {
        const char* envPath = getenv("OTAV_CONFIG_PATH");
        if (envPath && strlen(envPath) > 0) {
            // Load from file path specified in environment
            std::ifstream ifs(envPath);
            if (ifs.is_open()) {
                std::string line;
                while (std::getline(ifs, line)) {
                    if (line.empty() || line[0] == '#') continue;
                    
                    auto pos = line.find('=');
                    if (pos != std::string::npos) {
                        std::string key = line.substr(0, pos);
                        std::string value = line.substr(pos + 1);

                        // Trim whitespace
                        while (!value.empty() && (value.front() == ' ' || value.back() == ' ')) {
                            value.erase(value.size() - 1);
                        }

                        if (key == "MAX_DOWNGRADE_WINDOW_DAYS") {
                            try {
                                maxDowngradeWindowDays = std::stoi(value);
                            } catch (...) {}
                        } else if (key == "TOLERANCE_PERCENT") {
                            try {
                                tolerancePercent = std::stod(value);
                            } catch (...) {}
                        } else if (key == "COUNTER_FILE") {
                            counterFile = value;
                        } else if (key == "ALLOW_VERSION" || key == "ALLOW_LIST") {
                            // Parse comma-separated versions for allowlist
                            std::stringstream ss(value);
                            std::string verStr;
                            while (std::getline(ss, verStr, ',')) {
                                if (!verStr.empty()) {
                                    allowList.emplace_back(verStr);
                                }
                            }
                        }
                    }
                }
                ifs.close();
            }
        }

        // Apply defaults if nothing loaded
        if (maxDowngradeWindowDays == 0) {
            maxDowngradeWindowDays = kDefaultMaxDowngradeWindowDays;
        }
        if (tolerancePercent == 0.0) {
            tolerancePercent = kDefaultTolerancePercent;
        }

        return true;
    }

    void resetToDefaults() {
        maxDowngradeWindowDays = kDefaultMaxDowngradeWindowDays;
        tolerancePercent = kDefaultTolerancePercent;
        counterFile.clear();
        allowList.clear();
    }

    bool isValid() const {
        return maxDowngradeWindowDays > 0 && 
               tolerancePercent > 0.0 && 
               !counterFile.empty();
    }
};

// ============================================================================
// Time Utilities for Window Calculations
// ============================================================================

class TimeUtils {
public:
    static uint64_t getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count());
    }

    static int32_t getDaysSince(uint64_t timestamp) {
        if (timestamp == 0) return -1;
        
        auto now = getCurrentTimestamp();
        if (now < timestamp) return -1;  // Timestamp is in the future
        
        return static_cast<int32_t>((now - timestamp) / 86400);  // seconds per day
    }

    static uint64_t getTimestampFromDays(int32_t days, uint64_t base = 0) {
        if (days < 0 || base == 0) return 0;
        
        auto now = getCurrentTimestamp();
        int32_t elapsed = static_cast<int32_t>((now - base) / 86400);
        
        if (elapsed >= days) {
            return base + (static_cast<uint64_t>(days) * 86400);
        }
        return now;
    }

    static bool isWithinWindow(uint64_t timestamp, int32_t windowDays) {
        if (timestamp == 0 || windowDays <= 0) return true;
        
        int32_t daysSince = getDaysSince(timestamp);
        return daysSince >= 0 && daysSince < windowDays;
    }
};

// ============================================================================
// Rollback Protection Enforcer - Main Class
// ============================================================================

class RollbackProtectionEnforcer {
public:
    static RollbackProtectionEnforcer create() {
        return RollbackProtectionEnforcer();
    }

private:
    PersistentCounter counter;
    Config config;
    uint64_t lastUpdateTimestamp = 0;
    
    // Track the version we installed (for detecting rollback attempts)
    Version installedVersion;
    bool hasInstalled = false;

public:
    RollbackProtectionEnforcer() : counter(), config() {}

    // Initialize the enforcer with configuration
    void init() {
        if (!config.isValid()) {
            config.loadFromEnv();
        }
        
        counter.initOrLoad();
        lastUpdateTimestamp = TimeUtils::getCurrentTimestamp();
    }

    // Set a specific version as "installed" (called after successful OTA)
    void markInstalled(const Version& ver, uint64_t timestamp = 0) {
        if (!config.isValid()) config.loadFromEnv();
        
        installedVersion = ver;
        hasInstalled = true;
        lastUpdateTimestamp = timestamp ? timestamp : TimeUtils::getCurrentTimestamp();
    }

    // Check if a new version can be safely installed
    struct CheckResult {
        bool allowed;
        Version currentVersion;
        Version proposedVersion;
        int32_t daysSinceInstall;
        std::string reason;
        
        explicit CheckResult(bool ok, const Version& curr, 
                           const Version& prop, int32_t days, 
                           const std::string& r = "")
            : allowed(ok), currentVersion(curr), proposedVersion(prop),
              daysSinceInstall(days), reason(r) {}
    };

    // Main check: can we install this version?
    CheckResult canInstall(const Version& proposedVersion, uint64_t timestamp = 0) {
        if (!config.isValid()) config.loadFromEnv();
        
        uint64_t currentVer = counter.getVersion();
        int32_t daysSince = TimeUtils::getDaysSince(lastUpdateTimestamp);
        
        // If never installed anything yet, allow any version
        if (!hasInstalled) {
            return CheckResult(true, Version(), proposedVersion, 0, 
                             "Initial installation - no baseline");
        }

        // Parse current and proposed versions for comparison
        Version currVer(currentVer);
        
        // Build a reasonable current version string from counter value
        std::ostringstream oss;
        oss << (currentVer / 1000) << "." << ((currentVer % 1000) / 100) 
            << ".0-0";
        currVer = Version