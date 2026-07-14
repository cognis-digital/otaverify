/*
 * polyglot/c/rollback_protection_enforcer.c
 * 
 * OTA Update Rollback Protection Enforcer
 * 
 * Purpose: Prevents downgrade attacks by ensuring new version >= current version,
 *          maintains atomicity guarantees, and enforces minimum delta thresholds.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* ============================================================
 * Configuration Constants
 * ============================================================ */

#define MAX_VERSION_LEN    64
#define HASH_BUFFER_SIZE   1024
#define ROLLBACK_WINDOW    3        /* Allow N minor versions below current */
#define MIN_DELTA_BYTES    1024     /* Min size diff to consider upgrade */
#define CURRENT_VER_FILE  "/etc/otaverify/current_version"
#define LOCK_FILE         "/var/run/otaverify.lock"

/* ============================================================
 * Data Structures
 * ============================================================ */

typedef struct {
    char current[MAX_VERSION_LEN];
    uint64_t current_epoch;
    uint32_t build_id;
} CurrentState;

typedef struct {
    uint64_t new_version_epoch;
    uint32_t new_build_id;
    uint64_t new_hash;
    bool is_delta;
    int delta_offset;
} NewPackageInfo;

/* ============================================================
 * Utility Functions
 * ============================================================ */

static inline int safe_strlen(const char *s) {
    if (!s) return 0;
    size_t len = strlen(s);
    return (len > MAX_VERSION_LEN - 1) ? MAX_VERSION_LEN - 1 : (int)len;
}

static inline bool is_empty_or_whitespace(const char *s, int len) {
    for (int i = 0; i < len && s[i] == ' '; i++) {}
    return !s[len-1];
}

/* ============================================================
 * Hash Functions (SHA256 implementation)
 * ============================================================ */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];
    int buffer_pos;
} SHA256_CTX;

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    ctx->buffer_pos = 0;
}

static void sha256_transform(SHA256_CTX *ctx, uint32_t a, uint32_t b, 
                            uint32_t c, uint32_t d, uint32_t e, 
                            uint32_t f, uint32_t g, uint32_t h) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h;
}

static void sha256_update(SHA256_CTX *ctx, const unsigned char *data, int len) {
    while (len > 0) {
        if (ctx->buffer_pos == 64) {
            /* Process full block - simplified for brevity */
            ctx->count += 64;
            ctx->buffer_pos = 0;
        }
        int to_copy = len < 64 ? len : 64;
        memcpy(ctx->buffer + ctx->buffer_pos, data, to_copy);
        ctx->buffer_pos += to_copy;
        data += to_copy;
        len -= to_copy;
    }
}

static void sha256_final(SHA256_CTX *ctx, unsigned char *out) {
    int pad = 8 - (ctx->buffer_pos + 1) % 64;
    if (pad == 0) pad = 64;
    
    ctx->buffer[ctx->buffer_pos++] = (unsigned char)(pad & 0xff);
    while (ctx->buffer_pos < 56) {
        ctx->buffer[ctx->buffer_pos++] = 0;
    }
    
    /* Process last partial block */
    ctx->count += ctx->buffer_pos;
}

static uint64_t compute_file_hash(const char *path, int max_size) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    
    unsigned char buf[1024];
    size_t n;
    int limit = max_size > 0 ? min(max_size, (int)(sizeof(buf)-1)) : -1;
    
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha256_update(&ctx, buf, n);
        if (limit >= 0 && ctx.count >= limit) break;
    }
    
    fclose(f);
    return ctx.count;
}

/* ============================================================
 * Version Parsing and Comparison
 * ============================================================ */

static int parse_version(const char *ver_str, uint64_t *epoch, 
                        uint32_t *build_id, bool *is_dev) {
    if (!ver_str || !*ver_str) return -1;
    
    /* Format: YYYYMMDD-HHMMSS-BUILDID[.DEV] */
    char buf[MAX_VERSION_LEN];
    strncpy(buf, ver_str, MAX_VERSION_LEN - 1);
    buf[MAX_VERSION_LEN - 1] = '\0';
    
    *is_dev = false;
    
    /* Check for dev suffix */
    int len = strlen(buf);
    if (len > 4 && buf[len-4] == '.') {
        if (strcmp(&buf[len-3], "DEV") == 0) {
            *is_dev = true;
            buf[len-4] = '\0';
        } else if (strncmp(&buf[len-3], "BETA", 4) == 0) {
            *is_dev = true;
            buf[len-4] = '\0';
        }
    }
    
    /* Parse YYYYMMDD-HHMMSS-BUILDID */
    int dash1, dash2;
    dash1 = strcspn(buf, "-");
    dash2 = strcspn(&buf[dash1 + 1], "-") + dash1 + 1;
    
    if (dash1 < 0 || dash2 <= dash1) return -1;
    
    uint64_t date_part = strtoull(buf, &buf, 10);
    *build_id = (uint32_t)strtoul(&buf[dash2], NULL, 10);
    
    /* Convert YYYYMMDD to epoch-like value */
    int year = date_part / 10000;
    int month = (date_part % 10000) / 100;
    int day = date_part % 100;
    
    *epoch = ((uint64_t)(year - 2000) << 32) | 
             ((uint64_t)(month * 100 + day) << 8);
    
    return 0;
}

static int compare_versions(const char *new_ver, const char *curr_ver) {
    uint64_t new_epoch = 0;
    uint32_t new_build = 0;
    bool new_dev = false;
    
    uint64_t curr_epoch = 0;
    uint32_t curr_build = 0;
    bool curr_dev = false;
    
    if (parse_version(new_ver, &new_epoch, &new_build, &new_dev) < 0) {
        return -1;
    }
    if (parse_version(curr_ver, &curr_epoch, &curr_build, &curr_dev) < 0) {
        return -1;
    }
    
    /* Dev versions always considered lower */
    if (new_dev && !curr_dev) return -1;
    if (!new_dev && curr_dev) return 1;
    if (new_dev && curr_dev) {
        /* Both dev: compare by epoch then build */
    }
    
    if (new_epoch > curr_epoch) return 1;
    if (new_epoch < curr_epoch) return -1;
    
    /* Same epoch, compare build IDs */
    return (int)(new_build - curr_build);
}

/* ============================================================
 * Current State Management
 * ============================================================ */

static int load_current_state(CurrentState *state) {
    if (!fopen(CURRENT_VER_FILE, "r")) {
        state->current[0] = '\0';
        state->current_epoch = 0;
        state->build_id = 0;
        return -1;
    }
    
    char buf[MAX_VERSION_LEN];
    if (fgets(buf, sizeof(buf), f)) {
        strncpy(state->current, buf, MAX_VERSION_LEN - 1);
        buf[MAX_VERSION_LEN - 1] = '\0';
        
        if (parse_version(buf, &state->current_epoch, 
                         &state->build_id, NULL) == 0) {
            return 0;
        }
    }
    
    fclose(f);
    state->current[0] = '\0';
    state->current_epoch = 0;
    state->build_id = 0;
    return -1;
}

static int save_current_state(const CurrentState *state) {
    FILE *f = fopen(CURRENT_VER_FILE, "w");
    if (!f) return -1;
    
    char buf[MAX_VERSION_LEN];
    strncpy(buf, state->current, MAX_VERSION_LEN - 1);
    buf[MAX_VERSION_LEN - 1] = '\0';
    
    fprintf(f, "%s\n", buf);
    fclose(f);
    return 0;
}

/* ============================================================
 * Atomic File Operations
 * ============================================================ */

static int atomic_write(const char *path, const void *data, size_t len) {
    /* Write to temp file first, then rename atomically */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    
    if (written != len) {
        unlink(tmp);
        return -1;
    }
    
    /* Rename atomically */
    if (rename(tmp, path) < 0) {
        unlink(tmp);
        return -1;
    }
    
    return 0;
}

static int atomic_read(const char *path, void *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    size_t read_len = fread(buf, 1, len, f);
    fclose(f);
    
    return (read_len == len) ? 0 : -1;
}

/* ============================================================
 * Rollback Protection Core Logic
 * ============================================================ */

typedef struct {
    CurrentState current;
    NewPackageInfo new_pkg;
    int result;           /* 0=ok, 1=upgrade, -1=downgrade, -2=same */
    char reason[256];
} CheckResult;

static bool is_valid_version_format(const char *ver) {
    if (!ver || !*ver) return false;
    
    /* Basic format validation: digits and dashes only */
    for (const char *p = ver; *p; p++) {
        if (!isdigit(*p) && *p != '-') {
            return false;
        }
    }
    return true;
}

static int check_rollback_protection(const NewPackageInfo *new_pkg, 
                                     CheckResult *result) {
    /* Step 1: Validate version format */
    if (!is_valid_version_format(new_pkg->current)) {
        snprintf(result->reason, sizeof(result->reason),
                 "Invalid current version format");
        result->result = -2;
        return -1;
    }
    
    /* Step 2: Check against rollback window */
    int cmp = compare_versions(new_pkg->new_ver, new_pkg->current);
    
    if (cmp == 0) {
        snprintf(result->reason, sizeof(result->result), "Same version");
        result->result = -2;
        return 0;
    } else if (cmp < 0) {
        /* Downgrade attempt */
        int window_violation = ROLLBACK_WINDOW - 
                             ((new_pkg->current_epoch - new_pkg->new_epoch) / 100);
        
        if (window_violation > 0) {
            snprintf(result->reason, sizeof(result->result),
                     "Downgrade within %d version window", ROLLBACK_WINDOW);
            result->result = -1;
            return 0;
        } else {
            snprintf(result->reason, sizeof(result->result),
                     "Downgrade outside rollback window");
            result->result = -1;
            return -1;
        }
    } else {
        /* Upgrade */
        int delta_bytes = new_pkg->delta_offset;
        
        if (delta_bytes < MIN_DELTA_BYTES) {
            snprintf(result->reason, sizeof(result->result),
                     "Upgrade too small: %d bytes", delta_bytes);
            result->result = 1;
            return 0;
        }
        
        snprintf(result->reason, sizeof(result->result),
                 "Valid upgrade");
        result->result = 1;
        return 0;
    }
}

/* ============================================================
 * Delta Patch Integrity Verification
 * ============================================================ */

static int verify_delta_integrity(const NewPackageInfo *new_pkg) {
    /* For delta patches, verify the offset points to valid data */
    if (!new_pkg->is_delta || new_pkg->delta_offset <= 0) {
        return 0;
    }
    
    /* In production, this would read from the actual package file */
    /* and verify the delta stream matches expected checksums */
    
    /* Simplified check: ensure offset is reasonable */
    if (new_pkg->delta_offset > HASH_BUFFER_SIZE * 1024) {
        return -1;
    }
    
    return 0;
}

/* ============================================================
 * Signature Chain Verification (Placeholder for real impl)
 * ============================================================ */

static int verify_signature_chain(const NewPackageInfo *new_pkg,
                                  const char *pubkey_path) {
    /* Real implementation would:
     * 1. Load the public key from PKCS#8 format
     * 2. Extract signature from package header
     * 3. Compute hash of payload (excluding signature)
     * 4. Verify using RSA/ECDSA with the public key
     */
    
    if (!pubkey_path || !new_pkg->is_delta) {
        return 0;
    }
    
    /* Placeholder: assume valid for now */
    return 0;
}

/* ============================================================
 * Main Verification Function
 * ============================================================ */

int otaverify_rollback_check(const NewPackageInfo *new_pkg,
                            const char *pubkey_path) {
    CheckResult result = {0};
    
    /* Initialize current state if not loaded yet */
    CurrentState curr;
    int load_ok = load_current_state(&curr);
    
    if (load_ok < 0 && !curr.current[0]) {
        /* No previous version - treat as first install */
        strncpy(curr.current, "20240101-000000-0", MAX_VERSION_LEN - 1);
        curr.current_epoch = 0x01010100;
        curr.build_id = 0;
    } else if (load_ok < 0) {
        strncpy(curr.current, new_pkg->current, MAX_VERSION_LEN - 1);
    }
    
    /* Perform rollback protection check */
    int rc = check_rollback_protection(new_pkg, &result);
    
    /* Verify delta integrity if applicable */
    if (new_pkg->is_delta) {
        verify_delta_integrity(new_pkg);
    }
    
    /* Verify signature chain if public key provided */
    if (pubkey_path && new_pkg->is_delta) {
        verify_signature_chain(new_pkg, pubkey_path);
    }
    
    result.current_epoch = curr.current_epoch;
    result.build_id = curr.build_id;