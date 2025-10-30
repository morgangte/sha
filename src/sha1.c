// MIT License
// 
// Copyright (c) 2025 Morgan Gillette
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/**
 * @internal
 * @file sha1.c
 * @brief SHA-1 implementation file.
 * 
 * This implementation directly follows the standard described in 
 * the FIPS PUB 180-4:
 * 
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#include "sha.h"
#include "sha1.h"

#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

// 1.    INTRODUCTION

#define BLOCK_SIZE_IN_BITS 512
#define WORD_SIZE_IN_BITS 32
#define MESSAGE_DIGEST_SIZE_IN_BITS 256
#define ADD_MODULO 4294967296           // 2^32

// 4.    FUNCTIONS AND CONSTANTS
// 4.1   Functions
// 4.1.1 SHA-1 Functions

static uint32_t _f(uint32_t x, uint32_t y, uint32_t z, uint8_t t)
{
    assert(t <= 79);

    if (t <= 19) {
        return Ch(x, y, z);
    } else if (t <= 39) {
        return Parity(x, y, z);
    } else if (t <= 59) {
        return Maj(x, y, z);
    } else {
        return Parity(x, y, z);
    }
}

// 4.2   Constants
// 4.2.2 SHA-1 Constants

#define K_0 0x5a827999
#define K_20 0x6ed9eba1
#define K_40 0x8f1bbcdc
#define K_60 0xca62c1d6

// 5.    PREPROCESSING
// 5.3   Setting the Initial Hash Value
// 5.3.1 SHA-1

#define H_0_0 0x67452301
#define H_1_0 0xefcdab89
#define H_2_0 0x98badcfe
#define H_3_0 0x10325476
#define H_4_0 0xc3d2e1f0

// 6.    SECURE HASH ALGORITHMS
// 6.1   SHA-1

static void _compute_hash(const char *message, size_t message_length, uint32_t digest[5])
{
    uint32_t H_i[5] = {
        H_0_0, H_1_0, H_2_0, H_3_0, H_4_0
    };

    uint32_t K[80] = { 
        K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, 
        K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, K_0, 
        K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, 
        K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, K_20, 
        K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, 
        K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, K_40, 
        K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60, 
        K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60, K_60
    };

    size_t fit = 0;
    size_t consumed = 0;

    uint32_t a, b, c, d, e;
    uint32_t T;

    do {
        uint8_t block_bytes[64] = {0};
        consumed = _sha1_sha224_sha256_build_block(block_bytes, message, message_length, fit);

        uint32_t block_words[16] = {0};
        _block_bytes_to_uint32_words(block_bytes, block_words);

        uint32_t W[80] = {0};
        memcpy(W, block_words, 16 * sizeof(uint32_t));
        for (uint8_t t = 16; t < 80; t++) {
            W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        a = H_i[0];
        b = H_i[1];
        c = H_i[2];
        d = H_i[3];
        e = H_i[4];

        for (uint8_t t = 0; t < 80; t++) {
            T = ADD5(ROTL(a, 5), _f(b, c, d, t), e, K[t], W[t]);
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = T;
        }

        H_i[0] = ADD(a, H_i[0]);
        H_i[1] = ADD(b, H_i[1]);
        H_i[2] = ADD(c, H_i[2]);
        H_i[3] = ADD(d, H_i[3]);
        H_i[4] = ADD(e, H_i[4]);

        fit += consumed;
    } while (consumed > 0);

    digest[0] = H_i[0];
    digest[1] = H_i[1];
    digest[2] = H_i[2];
    digest[3] = H_i[3];
    digest[4] = H_i[4];
}

// Public Functions

void sha1_hash_string(const char *message, size_t message_length, uint32_t digest_destination[5])
{
    _compute_hash(message, message_length, digest_destination);
}

void sha1_digest_to_string(uint32_t digest[5], char string_digest_destination[SHA1_STRING_DIGEST_LENGTH])
{
    sprintf(string_digest_destination, "%08x %08x %08x %08x %08x", 
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4]
    );
}
