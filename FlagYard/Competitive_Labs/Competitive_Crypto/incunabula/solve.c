/*
 * Ultra-fast MITM solver for Incunabula CTF
 * Uses KPA (Known Plaintext Attack) for first block
 * Compile: gcc -O3 -march=native -o solve solve.c -lgmp -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <gmp.h>

#define N_BITS 28
#define TABLE_SIZE (1ULL << N_BITS)

// ASCII constraint: bits 7,15,23,31,39,47,55,63 are 0
static const int FIRST_HALF[28] = {
    0,1,2,3,4,5,6, 8,9,10,11,12,13,14, 
    16,17,18,19,20,21,22, 24,25,26,27,28,29,30
};
static const int SECOND_HALF[28] = {
    32,33,34,35,36,37,38, 40,41,42,43,44,45,46,
    48,49,50,51,52,53,54, 56,57,58,59,60,61,62
};

typedef struct {
    mpz_t val;
    uint32_t gray;
} TableEntry;

// Global arrays
mpz_t p;
mpz_t roots[64];
mpz_t first_roots[28], second_roots[28];
mpz_t first_inv[28], second_inv[28];

// Hash table for MITM
#define HASH_SIZE (1ULL << 29)  // ~500M entries
typedef struct HashEntry {
    uint64_t key_w3;  // bits 192-255
    uint64_t key_w2;  // bits 128-191
    uint64_t key_w1;  // bits 64-127
    uint64_t key_w0;  // bits 0-63
    uint32_t gray;
    struct HashEntry *next;
} HashEntry;

HashEntry **hash_table = NULL;
HashEntry *entry_pool = NULL;
size_t pool_index = 0;

void init_hash_table(void) {
    hash_table = (HashEntry**)calloc(HASH_SIZE, sizeof(HashEntry*));
    entry_pool = (HashEntry*)malloc(TABLE_SIZE * sizeof(HashEntry));
    pool_index = 0;
}

void free_hash_table(void) {
    free(hash_table);
    free(entry_pool);
    hash_table = NULL;
    entry_pool = NULL;
}

static inline uint64_t hash_mpz(mpz_t val) {
    // Use lower bits for hash
    return mpz_get_ui(val) & (HASH_SIZE - 1);
}

void hash_insert(mpz_t val, uint32_t gray) {
    uint64_t h = hash_mpz(val);
    HashEntry *e = &entry_pool[pool_index++];
    
    // Store full 256-bit key as 4 x 64-bit words
    mpz_t tmp;
    mpz_init_set(tmp, val);
    e->key_w0 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    e->key_w1 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    e->key_w2 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    e->key_w3 = mpz_get_ui(tmp);
    mpz_clear(tmp);
    
    e->gray = gray;
    e->next = hash_table[h];
    hash_table[h] = e;
}

int hash_lookup(mpz_t val, uint32_t *gray_out) {
    uint64_t h = hash_mpz(val);
    
    // Extract all 4 words for comparison
    mpz_t tmp;
    mpz_init_set(tmp, val);
    uint64_t w0 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    uint64_t w1 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    uint64_t w2 = mpz_get_ui(tmp);
    mpz_tdiv_q_2exp(tmp, tmp, 64);
    uint64_t w3 = mpz_get_ui(tmp);
    mpz_clear(tmp);
    
    for (HashEntry *e = hash_table[h]; e; e = e->next) {
        if (e->key_w0 == w0 && e->key_w1 == w1 && e->key_w2 == w2 && e->key_w3 == w3) {
            *gray_out = e->gray;
            return 1;
        }
    }
    return 0;
}

uint32_t gray_to_binary(uint32_t g) {
    uint32_t b = g;
    while (g > 0) {
        g >>= 1;
        b ^= g;
    }
    return b;
}

uint64_t reconstruct_64bit(uint32_t first_pattern, uint32_t second_pattern) {
    // Gray code values ARE the bit patterns directly - no conversion needed!
    uint64_t result = 0;
    for (int i = 0; i < 28; i++) {
        if (first_pattern & (1 << i))
            result |= (1ULL << FIRST_HALF[i]);
        if (second_pattern & (1 << i))
            result |= (1ULL << SECOND_HALF[i]);
    }
    return result;
}

// KPA attack: brute-force when we know most of the plaintext
uint64_t kpa_attack(mpz_t ct, const char *known_prefix, int known_len) {
    printf("  KPA attack: known prefix '%s' (%d bytes)\n", known_prefix, known_len);
    
    // Convert known prefix to bits
    uint64_t known_bits = 0;
    for (int i = 0; i < known_len; i++) {
        known_bits |= ((uint64_t)(unsigned char)known_prefix[i]) << ((7 - i) * 8);
    }
    
    // Brute-force unknown bytes (positions known_len to 7)
    int unknown_bytes = 8 - known_len;
    uint64_t max_val = 1ULL << (unknown_bytes * 7);  // 7 bits per ASCII char
    
    printf("  Brute-forcing %d unknown bytes (%llu possibilities)...\n", 
           unknown_bytes, (unsigned long long)max_val);
    
    mpz_t expected, temp;
    mpz_init(expected);
    mpz_init(temp);
    
    clock_t start = clock();
    
    for (uint64_t guess = 0; guess < max_val; guess++) {
        // Build full plaintext from known + guess
        uint64_t pt = known_bits;
        
        // Expand guess bits into ASCII bytes (7 bits each, bit 7 = 0)
        for (int b = 0; b < unknown_bytes; b++) {
            uint8_t byte_val = (guess >> (b * 7)) & 0x7F;
            pt |= ((uint64_t)byte_val) << ((7 - known_len - b) * 8);
        }
        
        // Compute expected ciphertext
        mpz_set_ui(expected, 1);
        for (int i = 0; i < 64; i++) {
            if (pt & (1ULL << i)) {
                mpz_mul(expected, expected, roots[i]);
                mpz_mod(expected, expected, p);
            }
        }
        
        if (mpz_cmp(expected, ct) == 0) {
            double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
            printf("  Found in %.1fs! plaintext = 0x%016llx\n", elapsed, (unsigned long long)pt);
            
            // Print as string
            char str[9];
            for (int i = 0; i < 8; i++) {
                str[i] = (pt >> ((7 - i) * 8)) & 0xFF;
            }
            str[8] = '\0';
            printf("  As string: '%s'\n", str);
            
            mpz_clear(expected);
            mpz_clear(temp);
            return pt;
        }
        
        if (guess % (1 << 20) == 0 && guess > 0) {
            double pct = 100.0 * guess / max_val;
            printf("    Progress: %.1f%%\n", pct);
        }
    }
    
    mpz_clear(expected);
    mpz_clear(temp);
    printf("  KPA attack failed!\n");
    return 0;
}

// Full MITM attack for unknown blocks
uint64_t mitm_attack(mpz_t ct) {
    printf("  Building MITM table (2^%d entries)...\n", N_BITS);
    
    init_hash_table();
    
    mpz_t val;
    mpz_init_set_ui(val, 1);
    
    uint32_t gray = 0;
    hash_insert(val, gray);
    
    clock_t start = clock();
    
    for (uint32_t i = 1; i < TABLE_SIZE; i++) {
        uint32_t new_gray = i ^ (i >> 1);
        uint32_t diff = gray ^ new_gray;
        int idx = __builtin_ctz(diff);
        
        if (new_gray & diff) {
            mpz_mul(val, val, first_roots[idx]);
        } else {
            mpz_mul(val, val, first_inv[idx]);
        }
        mpz_mod(val, val, p);
        
        hash_insert(val, new_gray);
        gray = new_gray;
        
        if (i % (1 << 24) == 0) {
            printf("    Table: %d%%\n", (int)(100ULL * i / TABLE_SIZE));
        }
    }
    
    double table_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("    Table built in %.1fs\n", table_time);
    
    // Search phase
    printf("  Searching (2^%d iterations)...\n", N_BITS);
    start = clock();
    
    mpz_t val_inv, target;
    mpz_init_set_ui(val_inv, 1);
    mpz_init(target);
    
    gray = 0;
    mpz_mul(target, ct, val_inv);
    mpz_mod(target, target, p);
    
    uint32_t first_gray;
    if (hash_lookup(target, &first_gray)) {
        uint64_t result = reconstruct_64bit(first_gray, gray);
        mpz_clear(val);
        mpz_clear(val_inv);
        mpz_clear(target);
        free_hash_table();
        return result;
    }
    
    for (uint32_t i = 1; i < TABLE_SIZE; i++) {
        uint32_t new_gray = i ^ (i >> 1);
        uint32_t diff = gray ^ new_gray;
        int idx = __builtin_ctz(diff);
        
        if (new_gray & diff) {
            mpz_mul(val_inv, val_inv, second_inv[idx]);
        } else {
            mpz_mul(val_inv, val_inv, second_roots[idx]);
        }
        mpz_mod(val_inv, val_inv, p);
        
        mpz_mul(target, ct, val_inv);
        mpz_mod(target, target, p);
        
        if (hash_lookup(target, &first_gray)) {
            double search_time = (double)(clock() - start) / CLOCKS_PER_SEC;
            printf("    Found at i=%u in %.1fs\n", i, search_time);
            
            uint64_t result = reconstruct_64bit(first_gray, new_gray);
            mpz_clear(val);
            mpz_clear(val_inv);
            mpz_clear(target);
            free_hash_table();
            return result;
        }
        
        gray = new_gray;
        
        if (i % (1 << 24) == 0) {
            double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
            double rate = i / elapsed;
            double eta = (TABLE_SIZE - i) / rate;
            printf("    Search: %d%%, ETA: %.0fs\n", (int)(100ULL * i / TABLE_SIZE), eta);
        }
    }
    
    mpz_clear(val);
    mpz_clear(val_inv);
    mpz_clear(target);
    free_hash_table();
    
    printf("  MITM failed!\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <data_file>\n", argv[0]);
        printf("Create data_file by running: python get_data.py > data.txt\n");
        return 1;
    }
    
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    // Helper to strip newline
    auto strip_newline = [](char *s) {
        size_t len = strlen(s);
        while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r')) {
            s[--len] = '\0';
        }
    };
    
    // Read p
    char line[4096];
    if (!fgets(line, sizeof(line), f)) { printf("Failed to read p\n"); return 1; }
    strip_newline(line);
    mpz_init(p);
    if (mpz_set_str(p, line, 10) != 0) { printf("Failed to parse p: '%s'\n", line); return 1; }
    gmp_printf("p = %Zd\n", p);
    
    // Read roots
    for (int i = 0; i < 64; i++) {
        if (!fgets(line, sizeof(line), f)) { printf("Failed to read root %d\n", i); return 1; }
        strip_newline(line);
        mpz_init(roots[i]);
        if (mpz_set_str(roots[i], line, 10) != 0) { printf("Failed to parse root %d: '%s'\n", i, line); return 1; }
    }
    
    // Prepare first/second half roots and inverses
    for (int i = 0; i < 28; i++) {
        mpz_init_set(first_roots[i], roots[FIRST_HALF[i]]);
        mpz_init_set(second_roots[i], roots[SECOND_HALF[i]]);
        mpz_init(first_inv[i]);
        mpz_init(second_inv[i]);
        mpz_invert(first_inv[i], first_roots[i], p);
        mpz_invert(second_inv[i], second_roots[i], p);
    }
    
    // Read number of ciphertexts
    int n_ct;
    if (!fgets(line, sizeof(line), f)) { printf("Failed to read n_ct\n"); return 1; }
    strip_newline(line);
    n_ct = atoi(line);
    printf("Ciphertexts: %d\n\n", n_ct);
    
    mpz_t ciphertexts[n_ct];
    for (int i = 0; i < n_ct; i++) {
        if (!fgets(line, sizeof(line), f)) { printf("Failed to read ct %d\n", i); return 1; }
        strip_newline(line);
        mpz_init(ciphertexts[i]);
        if (mpz_set_str(ciphertexts[i], line, 10) != 0) { printf("Failed to parse ct %d: '%s'\n", i, line); return 1; }
    }
    fclose(f);
    
    // Solve each ciphertext
    // IMPORTANT: ciphertext order is REVERSED!
    // ct[n-1] = first 8 chars (contains "FlagY{")
    // ct[0] = last 8 chars (contains "}")
    
    uint64_t parts[n_ct];
    
    // First block (ct[n_ct-1]) uses KPA with "FlagY{"
    printf("Block 1 (first 8 chars, contains 'FlagY{'):\n");
    parts[n_ct - 1] = kpa_attack(ciphertexts[n_ct - 1], "FlagY{", 6);
    
    // Last block (ct[0]) might end with "}"
    // For now use MITM, but could do KPA if we knew more
    
    for (int i = n_ct - 2; i >= 0; i--) {
        printf("\nBlock %d:\n", n_ct - i);
        parts[i] = mitm_attack(ciphertexts[i]);
        
        // Print as string
        char str[9];
        for (int j = 0; j < 8; j++) {
            str[j] = (parts[i] >> ((7 - j) * 8)) & 0xFF;
        }
        str[8] = '\0';
        printf("  Decrypted: '%s'\n", str);
    }
    
    // Reconstruct flag
    printf("\n==================================================\n");
    printf("FLAG: ");
    for (int i = n_ct - 1; i >= 0; i--) {
        for (int j = 0; j < 8; j++) {
            char c = (parts[i] >> ((7 - j) * 8)) & 0xFF;
            if (c) putchar(c);
        }
    }
    printf("\n==================================================\n");
    
    // Cleanup
    mpz_clear(p);
    for (int i = 0; i < 64; i++) mpz_clear(roots[i]);
    for (int i = 0; i < 28; i++) {
        mpz_clear(first_roots[i]);
        mpz_clear(second_roots[i]);
        mpz_clear(first_inv[i]);
        mpz_clear(second_inv[i]);
    }
    for (int i = 0; i < n_ct; i++) mpz_clear(ciphertexts[i]);
    
    return 0;
}
