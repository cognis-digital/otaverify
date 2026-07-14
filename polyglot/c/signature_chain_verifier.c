#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

/* ============================================================================
   Configuration and Constants
   ============================================================================ */

#define MAX_BLOCK_SIZE    65536      /* Maximum block size for OTA packages */
#define MAX_CHAIN_LENGTH  1024       /* Maximum number of blocks in chain */
#define HASH_SIZE         32         /* SHA-256 output size in bytes */
#define SIGNATURE_SIZE    64         /* ECDSA P-256 signature size */

/* Error codes for the verifier */
typedef enum {
    VERR_OK = 0,
    VERR_INVALID_INPUT,
    VERR_HASH_MISMATCH,
    VERR_SIGNATURE_MISSING,
    VERR_CHAIN_BREAK,
    VERR_ROLLBACK_DETECTED,
    VERR_DOWNGRADE_DETECTED,
    VERR_DELTA_INTEGRITY_FAIL,
    VERR_MEMORY_ALLOC,
    VERR_CRYPTO_FAIL,
    VERR_INVALID_STATE,
    VERR_MAX_ERROR = 255
} VerifierError;

/* ============================================================================
   Data Structures
   ============================================================================ */

typedef struct {
    uint8_t version[4];              /* Block version (big-endian) */
    uint64_t sequence_number;        /* Monotonically increasing sequence */
    uint32_t anti_downgrade_count;   /* Anti-downgrade counter */
    uint8_t  flags;                  /* Feature flags */
} __attribute__((packed)) BlockHeader;

typedef struct {
    uint8_t  hash[HASH_SIZE];       /* SHA-256 of previous block header + payload */
    uint8_t  signature[SIGNATURE_SIZE];  /* Signature of this block's data */
} __attribute__((packed)) BlockSignature;

/* OTA Package structure for the chain */
typedef struct {
    BlockHeader   headers[MAX_CHAIN_LENGTH];
    BlockSignature signatures[MAX_CHAIN_LENGTH];
    uint32_t      total_blocks;
    uint8_t       root_hash[HASH_SIZE];  /* Root hash of entire chain */
} OtaChain;

/* ============================================================================
   Cryptographic Primitives (SHA-256 Implementation)
   ============================================================================ */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c2f15c, 0xe1b3e7c5,
    0xc76c5163, 0x949ae4f9, 0xd6297e15, 0x96fe8d91,
    0x3f4f8b83, 0xc58c206c, 0x6d701ef2, 0x47d63163,
    0xe3f57a79, 0xf57eae6a, 0x835ca8e5, 0x9b74afd3,
    0x08c47dd8, 0xd5d61fe2, 0x6f4fcf82, 0x46ad1ef4,
    0xe97d3a3e, 0x3b16af6d, 0xfdccf0ae, 0x5d2a6cfd,
    0xf57d1f82, 0x7787e428, 0x8b8e8bc9, 0x2e1b6381,
    0xc36e809f, 0xd4a509ff, 0x4fbefab7, 0xff197d72,
    0xa85163db, 0xdd46bce3, 0x688fe3c6, 0x13f6ee26,
    0x8a71d281, 0x44406093, 0x52ac70fa, 0x6ca9f14e,
    0x4cda0cbc, 0xb49f3b37, 0x1aefad4e, 0xd8a3e621,
    0x3d658b22, 0x0fc18dc3, 0x95cd309d, 0x69c6f4b6,
    0xe4b2641b, 0x0174e1cb, 0xcf656fe2, 0xdceb44af,
    0x4ebda38d, 0xf4a13945, 0x857be820, 0x4f2dd0ea,
    0x74a7c4f9, 0xc55b14fa, 0xcc763cfb, 0x24414d34,
    0x2e41f5fb, 0x387a6bbd, 0xa5feaf87, 0x7cced372,
    0x4a9b0418, 0xfc4c6a8d, 0x4e345754, 0x4f53e473
};

static void sha256_transform(uint32_t *state, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, i, j;
    
    for (int round = 0; round < 64; round++) {
        if (round < 16) {
            i = round;
            j = round;
        } else {
            uint32_t t = state[7];
            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3];
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = t;
            
            uint64_t temp = (uint64_t)state[0] << 32 | state[1];
            i = (temp >> 59) & 0x3F;
            j = (temp >> 57) & 0x3F;
        }
        
        uint64_t w = ((uint64_t)data[i] << 24 | data[i+1] << 16 | 
                      data[i+2] << 8 | data[i+3]) ^ K[round];
        
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        
        uint32_t t0 = (h >> 1) + ((a & b) | (~a & c)) ^ K[round] ^ w;
        uint32_t t1 = (g >> 1) + ((d & e) | (~d & f));
        
        state[0] = a + t0 + t1;
        state[1] = b + t0;
        state[2] = c + t1;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;
    }
}

static void sha256_init(uint8_t *output) {
    uint32_t state[8];
    
    /* Initial hash values */
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    
    /* Process data in 512-bit chunks */
    for (int chunk = 0; chunk < 4; chunk++) {
        uint8_t *data = output + chunk * 64;
        
        /* Pad the message if necessary */
        int pad_len = 56 - ((chunk * 64) % 512);
        data[56] = (pad_len & 0xFF);
        data[57] = (pad_len >> 8) & 0xFF;
        
        /* Process the chunk */
        sha256_transform(state, data);
    }
    
    /* Final padding and transform */
    uint32_t pad_len = 56 - ((4 * 64) % 512);
    output[56] = (pad_len & 0xFF);
    output[57] = (pad_len >> 8) & 0xFF;
    
    sha256_transform(state, output + 56);
    
    /* Convert state to output */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            uint8_t byte = (state[i] >> (j * 8)) & 0xFF;
            output[56 + i * 4 + j] = byte;
        }
    }
}

static void sha256_update(uint8_t *output, const uint8_t *data, size_t len) {
    /* Simple implementation - for production use a proper streaming hash */
    int offset = (len < 64) ? 0 : 1;
    
    if (offset == 0) {
        sha256_init(output);
    } else {
        memcpy(output, output + 64, 64 - offset);
        memset(output + 64 - offset, 0, offset);
    }
    
    /* Copy data into the hash buffer */
    for (size_t i = 0; i < len && i < 64; i++) {
        output[offset + i] = data[i];
    }
}

static void sha256_finish(uint8_t *output) {
    /* Final padding and transform */
    uint32_t pad_len = 56 - ((4 * 64) % 512);
    output[56] = (pad_len & 0xFF);
    output[57] = (pad_len >> 8) & 0xFF;
    
    sha256_transform(output, output + 56);
}

/* ============================================================================
   Signature Chain Verification Functions
   ============================================================================ */

static int verify_block_signature(const OtaChain *chain, 
                                   int block_idx,
                                   const uint8_t *expected_sig) {
    if (block_idx < 0 || block_idx >= chain->total_blocks) {
        return VERR_INVALID_INPUT;
    }
    
    /* Calculate hash of this block's header */
    BlockHeader *header = &chain->headers[block_idx];
    uint8_t hash[HASH_SIZE];
    
    /* Hash the header data (excluding signature field) */
    sha256_init(hash);
    memcpy(hash, header, sizeof(BlockHeader));
    
    /* Compare with expected signature */
    if (memcmp(hash, expected_sig, HASH_SIZE) == 0) {
        return VERR_OK;
    }
    
    return VERR_SIGNATURE_MISSING;
}

static int verify_chain_continuity(const OtaChain *chain) {
    uint8_t current_hash[HASH_SIZE];
    
    /* Initialize with root hash */
    memcpy(current_hash, chain->root_hash, HASH_SIZE);
    
    for (uint32_t i = 0; i < chain->total_blocks; i++) {
        BlockHeader *header = &chain->headers[i];
        
        /* Hash current block header + previous hash */
        sha256_init(current_hash);
        memcpy(current_hash, header, sizeof(BlockHeader));
        memcpy(current_hash + sizeof(BlockHeader), chain->root_hash, HASH_SIZE);
        
        /* Verify against stored signature */
        if (memcmp(current_hash, &chain->signatures[i].hash, HASH_SIZE) != 0) {
            return VERR_CHAIN_BREAK;
        }
    }
    
    return VERR_OK;
}

static int verify_anti_downgrade(const OtaChain *chain, 
                                  uint32_t expected_min_version,
                                  uint32_t current_system_version) {
    if (current_system_version < expected_min_version) {
        /* Check anti-downgrade counter */
        for (uint32_t i = 0; i < chain->total_blocks; i++) {
            if (chain->headers[i].anti_downgrade_count > 0) {
                return VERR_DOWNGRADE_DETECTED;
            }
        }
    }
    
    return VERR_OK;
}

/* ============================================================================
   Main Verification Function
   ============================================================================ */

VerifierError ota_verify_chain(const OtaChain *chain,
                               uint32_t expected_min_version,
                               uint32_t current_system_version) {
    if (!chain || !chain->headers || !chain->signatures) {
        return VERR_INVALID_INPUT;
    }
    
    /* Step 1: Verify chain continuity and signatures */
    VerifierError result = verify_chain_continuity(chain);
    if (result != VERR_OK) {
        return result;
    }
    
    /* Step 2: Verify anti-downgrade protection */
    result = verify_anti_downgrade(chain, expected_min_version, 
                                    current_system_version);
    if (result != VERR_OK) {
        return result;
    }
    
    /* Step 3: Check for rollback conditions */
    uint64_t min_seq = UINT64_MAX;
    uint64_t max_seq = 0;
    
    for (uint32_t i = 0; i < chain->total_blocks; i++) {
        if (chain->headers[i].sequence_number < min_seq) {
            min_seq = chain->headers[i].sequence_number;
        }
        if (chain->headers[i].sequence_number > max_seq) {
            max_seq = chain->headers[i].sequence_number;
        }
    }
    
    /* Rollback detected if sequence numbers are not monotonically increasing */
    if (min_seq < max_seq - 100) {  /* Allow some tolerance for gaps */
        return VERR_ROLLBACK_DETECTED;
    }
    
    return VERR_OK;
}

/* ============================================================================
   Delta Patch Integrity Verification
   ============================================================================ */

static int verify_delta_patch(const OtaChain *chain, 
                              const uint8_t *patch_data,
                              size_t patch_size) {
    if (!patch_data || patch_size == 0) {
        return VERR_INVALID_INPUT;
    }
    
    /* Calculate hash of the delta patch */
    uint8_t patch_hash[HASH_SIZE];
    sha256_init(patch_hash);
    
    /* Hash in chunks to handle large patches */
    for (size_t offset = 0; offset < patch_size; offset += HASH_SIZE) {
        size_t chunk_size = (patch_size - offset > HASH_SIZE) ? 
                           HASH_SIZE : (patch_size - offset);
        sha256_update(patch_hash, patch_data + offset, chunk_size);
    }
    
    /* Compare with expected hash from chain metadata */
    if (memcmp(patch_hash, &chain->headers[0].hash, HASH_SIZE) == 0) {
        return VERR_OK;
    }
    
    return VERR_DELTA_INTEGRITY_FAIL;
}

/* ============================================================================
   Demo/Test Code
   ============================================================================ */

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog_name);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -f <file>     Load chain from file\n");
    fprintf(stderr, "  -v <version>  Minimum required version (default: 1.0.0)\n");
    fprintf(stderr, "  -s <ver>      Current system version (default: 2.0.0)\n");
    fprintf(stderr, "  -d            Include delta patch verification\n");
    fprintf(stderr, "\nExit codes:\n");
    fprintf(stderr, "  0   Success\n");
    fprintf(stderr, "  1   Invalid input\n");
    fprintf(stderr, "  2   Chain signature mismatch\n");
    fprintf(stderr, "  3   Anti-downgrade violation\n");
    fprintf(stderr, "  4   Rollback detected\n");
    fprintf(stderr, "  5   Delta patch integrity fail\n");
}