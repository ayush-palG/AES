#ifndef AES_H_
#define AES_H_

#include <stdint.h>

#define AES_BLOCK_SIZE  16

typedef enum {
    AES_128_KEY_SIZE = 16,
    AES_192_KEY_SIZE = 24,
    AES_256_KEY_SIZE = 32,
} AES_Key_Size;

typedef enum {
    AES_128_ROUNDS = 10,
    AES_192_ROUNDS = 12,
    AES_256_ROUNDS = 14,
} AES_Rounds;

typedef enum {
    AES_OK = 0,
    AES_ERR_INVALID_KEY,
    AES_ERR_INVALID_ARG,
    AES_ERR_NULL_PTR,
} AES_Err;

// Max expanded key length (60 words × 4 bytes)
#define AES_MAX_EXP_KEY_SIZE  (60 * 4)

typedef struct {
    uint8_t  round_key[AES_MAX_EXP_KEY_SIZE]; // Expanded key schedule
    uint32_t rounds_num;                      // Number of rounds
    uint32_t key_length;                      // Key length in 32-bit words
} AES_Context;

AES_Err aes_init(AES_Context *context, const uint8_t *key, int key_size);
static void key_expansion(AES_Context *context, const uint8_t *key);
static void add_round_key(uint8_t *state, const uint8_t *round_key);

static void sub_bytes(uint8_t *state);
static void shift_rows(uint8_t *state);
static void mix_columns(uint8_t *state);

static void inv_sub_bytes(uint8_t *state);
static void inv_shift_rows(uint8_t *state);
static void inv_mix_columns(uint8_t *state);

// `in` and `out` should be array of length AES_BLOCK_SIZE 
static void cipher(const AES_Context *context, const uint8_t *in, uint8_t *out);
static void inv_cipher(const AES_Context *context, const uint8_t *in, uint8_t *out);

// -----------------------------------------------------------------------------
// ECB Mode - Electronic CodeBook Mode
// -----------------------------------------------------------------------------

// No need for these single-block encryption/decryption API
AES_Err aes_ecb_encrypt_block(const AES_Context *context, const uint8_t *in, uint8_t *out);
AES_Err aes_ecb_decrypt_block(const AES_Context *context, const uint8_t *in, uint8_t *out);

// len must be a multiple of AES_BLOCK_SIZE
AES_Err aes_ecb_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len);
AES_Err aes_ecb_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len);

// -----------------------------------------------------------------------------
// CBC Mode - Cipher Block Chaining Mode
// @iv      - 16-byte initialisation vector (not modified)
// len must be a multiple of AES_BLOCK_SIZE
// -----------------------------------------------------------------------------

AES_Err aes_cbc_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv);
AES_Err aes_cbc_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv);

// -----------------------------------------------------------------------------
// CFB-128 Mode - Cipher FeedBack Mode
// @iv          - updated to the last ciphertext block on return
// -----------------------------------------------------------------------------

AES_Err aes_cfb_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv);
AES_Err aes_cfb_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv);

// -----------------------------------------------------------------------------
// OFB Mode - Output FeedBack Mode
// @iv      - updated to the last ciphertext block on return
// -----------------------------------------------------------------------------

AES_Err aes_ofb_xcrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv);

#endif // AES_H_


#ifdef AES_IMPLEMENTATION

// -----------------------------------------------------------------------------
// AES Look-Up Tables for substitutions
// -----------------------------------------------------------------------------

static const uint8_t sbox[256] = {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                                  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                                  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                                  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                                  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                                  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                                  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                                  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                                  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                                  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                                  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                                  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                                  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                                  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                                  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                                  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const uint8_t rsbox[256] = {0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
                                   0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
                                   0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
                                   0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
                                   0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
                                   0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
                                   0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
                                   0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
                                   0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
                                   0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
                                   0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
                                   0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
                                   0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
                                   0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
                                   0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
                                   0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

AES_Err aes_init(AES_Context *context, const uint8_t *key, int key_size)
{
    if (!context || !key) return AES_ERR_NULL_PTR;

    switch (key_size) {
    case AES_128_KEY_SIZE: context->rounds_num = AES_128_ROUNDS; context->key_length = 4; break;
    case AES_192_KEY_SIZE: context->rounds_num = AES_192_ROUNDS; context->key_length = 6; break;
    case AES_256_KEY_SIZE: context->rounds_num = AES_256_ROUNDS; context->key_length = 8; break;
    default: return AES_ERR_INVALID_KEY;
    }

    key_expansion(context, key);
    return AES_OK;
}

static void key_expansion(AES_Context *context, const uint8_t *key)
{
    int key_length = context->key_length;
    int rounds_num = context->rounds_num;
    int total_words = (rounds_num + 1) * 4;

    // Copy the original key into the first key_length words
    for (size_t i = 0; i < key_length * 4; ++i) {
        context->round_key[i] = key[i];
    }

    for (int i = key_length; i < total_words; i++) {
        uint8_t temp[4];
        for (size_t j = 0; j < 4; ++j) {
            temp[j] = context->round_key[(i-1)*4 + j];
        }

        if (i % context->key_length == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];  temp[1] = temp[2];  temp[2] = temp[3];  temp[3] = t;
            
            // SubWord
            temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];

            // XOR Rcon
            temp[0] ^= rcon[i / key_length - 1];
        } else if (key_length > 6 && i % key_length == 4) {
            // Extra SubWord for AES-256
            temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
        }

        context->round_key[i*4+0] = context->round_key[(i - key_length)*4+0] ^ temp[0];
        context->round_key[i*4+1] = context->round_key[(i - key_length)*4+1] ^ temp[1];
        context->round_key[i*4+2] = context->round_key[(i - key_length)*4+2] ^ temp[2];
        context->round_key[i*4+3] = context->round_key[(i - key_length)*4+3] ^ temp[3];
    }
}

// -----------------------------------------------------------------------------
// GF (2^8) helpers
// -----------------------------------------------------------------------------
static inline uint8_t xtime(uint8_t x)
{
    return (uint8_t)(((x << 1) ^ ((x >> 7) ? 0x1b : 0x00)) & 0xff);
}
 
// Multiply two bytes in GF(2^8)
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

// -----------------------------------------------------------------------------
// State helpers  (state is a 4×4 byte matrix, column-major)
// state[col][row]  -  but keep it flat for simplicity
// -----------------------------------------------------------------------------

#define S(r,c)  state[(r) + (c)*4]

static void add_round_key(uint8_t *state, const uint8_t *round_key)
{
    for (int i = 0; i < 16; i++) state[i] ^= round_key[i];
}

static void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void shift_rows(uint8_t *state)
{
    uint8_t tmp;

    // Row 1: left rotate by 1
    tmp = S(1,0);  S(1,0) = S(1,1);  S(1,1) = S(1,2);  S(1,2) = S(1,3);  S(1,3) = tmp;

    // Row 2: left rotate by 2
    tmp = S(2,0);  S(2,0) = S(2,2);  S(2,2) = tmp;
    tmp = S(2,1);  S(2,1) = S(2,3);  S(2,3) = tmp;

    // Row 3: left rotate by 3 (= right rotate by 1)
    tmp = S(3,3);  S(3,3) = S(3,2);  S(3,2) = S(3,1);  S(3,1) = S(3,0);  S(3,0) = tmp;
}

static void mix_columns(uint8_t *state)
{
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = S(0,c), s1 = S(1,c), s2 = S(2,c), s3 = S(3,c);
        S(0,c) = gf_mul(0x02,s0) ^ gf_mul(0x03,s1) ^ s2              ^ s3;
        S(1,c) = s0              ^ gf_mul(0x02,s1) ^ gf_mul(0x03,s2) ^ s3;
        S(2,c) = s0              ^ s1              ^ gf_mul(0x02,s2) ^ gf_mul(0x03,s3);
        S(3,c) = gf_mul(0x03,s0) ^ s1              ^ s2              ^ gf_mul(0x02,s3);
    }
}

static void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++) state[i] = rsbox[state[i]];
}

static void inv_shift_rows(uint8_t *state)
{
    uint8_t temp;

    // Row 1: right rotate by 1
    temp = S(1,3); S(1,3) = S(1,2); S(1,2) = S(1,1); S(1,1) = S(1,0); S(1,0) = temp;

    // Row 2: right rotate by 2
    temp = S(2,0); S(2,0) = S(2,2); S(2,2) = temp;
    temp = S(2,1); S(2,1) = S(2,3); S(2,3) = temp;

    // Row 3: right rotate by 3 (= left rotate by 1)
    temp = S(3,0); S(3,0) = S(3,1); S(3,1) = S(3,2); S(3,2) = S(3,3); S(3,3) = temp;
}

static void inv_mix_columns(uint8_t *state)
{
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = S(0,c), s1 = S(1,c), s2 = S(2,c), s3 = S(3,c);
        S(0,c) = gf_mul(0x0e,s0) ^ gf_mul(0x0b,s1) ^ gf_mul(0x0d,s2) ^ gf_mul(0x09,s3);
        S(1,c) = gf_mul(0x09,s0) ^ gf_mul(0x0e,s1) ^ gf_mul(0x0b,s2) ^ gf_mul(0x0d,s3);
        S(2,c) = gf_mul(0x0d,s0) ^ gf_mul(0x09,s1) ^ gf_mul(0x0e,s2) ^ gf_mul(0x0b,s3);
        S(3,c) = gf_mul(0x0b,s0) ^ gf_mul(0x0d,s1) ^ gf_mul(0x09,s2) ^ gf_mul(0x0e,s3);
    }
}

// TODO: undef the S(r,c) macro

static void cipher(const AES_Context *context, const uint8_t *in, uint8_t *out)
{
    uint8_t state[16];
    for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); ++i) {
        state[i] = in[i];
    }

    const uint8_t *round_key = context->round_key;
    add_round_key(state, round_key);
    round_key += AES_BLOCK_SIZE;

    for (size_t round = 1; round < context->rounds_num; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
        round_key += AES_BLOCK_SIZE;
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key);

    for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); ++i) {
        out[i] = state[i];
    }
}

static void inv_cipher(const AES_Context *context, const uint8_t *in, uint8_t *out)
{
    uint8_t state[16];
    for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); ++i) {
        state[i] = in[i];
    }

    const uint8_t *round_key = context->round_key + context->rounds_num * 16;
    add_round_key(state, round_key);
    round_key -= AES_BLOCK_SIZE;

    for (size_t round = 1; round < context->rounds_num; ++round) {
        inv_sub_bytes(state);
        inv_shift_rows(state);        
        add_round_key(state, round_key);
        round_key -= AES_BLOCK_SIZE;
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_key);

    for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); ++i) {
        out[i] = state[i];
    }
}

AES_Err aes_ecb_encrypt_block(const AES_Context *context, const uint8_t *in, uint8_t *out)
{
    if (!context || !in || !out) return AES_ERR_NULL_PTR;
    cipher(context, in, out);
    return AES_OK;
}

AES_Err aes_ecb_decrypt_block(const AES_Context *context, const uint8_t *in, uint8_t *out)
{
    if (!context || !in || !out) return AES_ERR_NULL_PTR;
    inv_cipher(context, in, out);
    return AES_OK;
}

AES_Err aes_ecb_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len)
{
    if (!context || !in || !out) return AES_ERR_NULL_PTR;
    if (len % AES_BLOCK_SIZE != 0) return AES_ERR_INVALID_ARG;

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        cipher(context, in + i, out + i);
    }
    return AES_OK;
}

AES_Err aes_ecb_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len)
{
    if (!context || !in || !out) return AES_ERR_NULL_PTR;
    if (len % AES_BLOCK_SIZE != 0) return AES_ERR_INVALID_ARG;

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        inv_cipher(context, in + i, out + i);
    }
    return AES_OK;
}

AES_Err aes_cbc_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
    if (!context || !in || !out || !iv) return AES_ERR_NULL_PTR;
    if (len % AES_BLOCK_SIZE != 0) return AES_ERR_INVALID_ARG;

    uint8_t prev_iv[AES_BLOCK_SIZE];
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        prev_iv[i] = iv[i];
    }

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
	uint8_t temp[AES_BLOCK_SIZE];
	for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
	    temp[j] = in[i + j];
	}
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            temp[j] ^= prev_iv[j];
        }
        cipher(context, temp, out + i);
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            prev_iv[j] = out[i + j];
        }
    }

    return AES_OK;
}

AES_Err aes_cbc_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, const uint8_t *iv)
{
    if (!context || !in || !out || !iv) return AES_ERR_NULL_PTR;
    if (len % AES_BLOCK_SIZE != 0) return AES_ERR_INVALID_ARG;

    uint8_t prev_iv[AES_BLOCK_SIZE];
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        prev_iv[i] = iv[i];
    }

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        inv_cipher(context, in + i, out + i);
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            out[i + j] ^= prev_iv[j];
        }
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            prev_iv[j] = in[i + j];
        }
    }

    return AES_OK;
}

AES_Err aes_cfb_encrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv)
{
    if (!context || !in || !out || !iv) return AES_ERR_NULL_PTR;

    while (len >= AES_BLOCK_SIZE) {
        uint8_t temp[AES_BLOCK_SIZE];
        cipher(context, iv, temp);
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
            out[i] = in[i] ^ temp[i];
        }
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
            iv[i] = out[i];
        }
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        len -= AES_BLOCK_SIZE;
    }

    if (len > 0) {
        uint8_t temp[AES_BLOCK_SIZE];
        cipher(context, iv, temp);
        for (size_t i = 0; i < len; ++i) {
            out[i] = in[i] ^ temp[i];
        }
        for (size_t i = 0; i < AES_BLOCK_SIZE - len; ++i) {
            iv[i] = iv[i + len];
        }
        for (size_t i = 0; i < len; ++i) {
            iv[i + AES_BLOCK_SIZE - len] = out[i];
        }
    }

    return AES_OK;
}

AES_Err aes_cfb_decrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv)
{
    if (!context || !in || !out) return AES_ERR_NULL_PTR;

    while (len >= AES_BLOCK_SIZE) {
        uint8_t temp[AES_BLOCK_SIZE];
        cipher(context, iv, temp);
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
            iv[i] = in[i];
        }
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
            out[i] = in[i] ^ temp[i];
        }
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        len -= AES_BLOCK_SIZE;
    }

    if (len > 0) {
        uint8_t temp[AES_BLOCK_SIZE];
        cipher(context, iv, temp);
        for (size_t i = 0; i < AES_BLOCK_SIZE - len; ++i) {
            iv[i] = iv[i + len];
        }
        for (size_t i = 0; i < len; ++i) {
            iv[i + AES_BLOCK_SIZE - len] = in[i];
        }
        for (size_t i = 0; i < len; ++i) {
            out[i] = in[i] ^ temp[i];
        }
    }

    return AES_OK;
}

AES_Err aes_ofb_xcrypt(const AES_Context *context, const uint8_t *in, uint8_t *out, size_t len, uint8_t *iv)
{
    if (!context || !in || !out || !iv) return AES_ERR_NULL_PTR;

    while (len > 0) {
        cipher(context, iv, iv);
        size_t chunk = len < AES_BLOCK_SIZE ? len : AES_BLOCK_SIZE;
        for (size_t j = 0; j < chunk; j++) {
            out[j] = in[j] ^ iv[j];
        }
        in  += chunk;
        out += chunk;
        len -= chunk;
    }

    return AES_OK;
}

#endif // AES_IMPLEMENTATION
