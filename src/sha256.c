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

// This implementation directly follows the standard described in 
// the FIPS PUB 180-4:
//
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

#include "sha256.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

// 1.    INTRODUCTION

#define BLOCK_SIZE_IN_BITS 512
#define WORD_SIZE_IN_BITS 32
#define MESSAGE_DIGEST_SIZE_IN_BITS 256

// 3.    NOTATION AND CONVENTIONS
// 3.2   Operations on Words

#define ADD_MODULO 4294967296
#define ADD(x, y) (uint32_t)(((uint32_t)(x) + (uint32_t)(y)) % ADD_MODULO)
#define ADD4(a, b, c, d) (uint32_t)(ADD(ADD(ADD((a), (b)), (c)), (d)))
#define ADD5(a, b, c, d, e) (uint32_t)(ADD((a), ADD4((b), (c), (d), (e))))

#define ROTL(x, n) (uint32_t)(((uint32_t)(x) << (uint32_t)(n)) | ((uint32_t)(x) >> (WORD_SIZE_IN_BITS - (uint32_t)(n))))
#define ROTR(x, n) (uint32_t)(((uint32_t)(x) >> (uint32_t)(n)) | ((uint32_t)(x) << (WORD_SIZE_IN_BITS - (uint32_t)(n))))
#define SHR(x, n) (uint32_t)((uint32_t)(x) >> (uint32_t)(n))

// 4.    FUNCTIONS AND CONSTANTS
// 4.1   Functions
// 4.1.2 SHA-224 and SHA-256 Functions

#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA_0_256(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA_1_256(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma_0_256(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma_1_256(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// 4.2   Constants
// 4.2.2 SHA-224 and SHA-256 Constants

#define K_0_256 0x428a2f98
#define K_1_256 0x71374491
#define K_2_256 0xb5c0fbcf
#define K_3_256 0xe9b5dba5
#define K_4_256 0x3956c25b
#define K_5_256 0x59f111f1
#define K_6_256 0x923f82a4
#define K_7_256 0xab1c5ed5
#define K_8_256 0xd807aa98 
#define K_9_256 0x12835b01 
#define K_10_256 0x243185be 
#define K_11_256 0x550c7dc3 
#define K_12_256 0x72be5d74 
#define K_13_256 0x80deb1fe 
#define K_14_256 0x9bdc06a7 
#define K_15_256 0xc19bf174
#define K_16_256 0xe49b69c1 
#define K_17_256 0xefbe4786 
#define K_18_256 0x0fc19dc6 
#define K_19_256 0x240ca1cc 
#define K_20_256 0x2de92c6f 
#define K_21_256 0x4a7484aa 
#define K_22_256 0x5cb0a9dc 
#define K_23_256 0x76f988da
#define K_24_256 0x983e5152 
#define K_25_256 0xa831c66d 
#define K_26_256 0xb00327c8 
#define K_27_256 0xbf597fc7 
#define K_28_256 0xc6e00bf3 
#define K_29_256 0xd5a79147 
#define K_30_256 0x06ca6351 
#define K_31_256 0x14292967
#define K_32_256 0x27b70a85 
#define K_33_256 0x2e1b2138 
#define K_34_256 0x4d2c6dfc 
#define K_35_256 0x53380d13 
#define K_36_256 0x650a7354 
#define K_37_256 0x766a0abb 
#define K_38_256 0x81c2c92e 
#define K_39_256 0x92722c85
#define K_40_256 0xa2bfe8a1 
#define K_41_256 0xa81a664b 
#define K_42_256 0xc24b8b70 
#define K_43_256 0xc76c51a3 
#define K_44_256 0xd192e819 
#define K_45_256 0xd6990624 
#define K_46_256 0xf40e3585 
#define K_47_256 0x106aa070
#define K_48_256 0x19a4c116 
#define K_49_256 0x1e376c08 
#define K_50_256 0x2748774c 
#define K_51_256 0x34b0bcb5 
#define K_52_256 0x391c0cb3 
#define K_53_256 0x4ed8aa4a 
#define K_54_256 0x5b9cca4f 
#define K_55_256 0x682e6ff3
#define K_56_256 0x748f82ee 
#define K_57_256 0x78a5636f 
#define K_58_256 0x84c87814 
#define K_59_256 0x8cc70208 
#define K_60_256 0x90befffa 
#define K_61_256 0xa4506ceb 
#define K_62_256 0xbef9a3f7 
#define K_63_256 0xc67178f2

// 5.    PREPROCESSING
// 5.1   Padding the Message
// 5.1.1 SHA-1, SHA-224 and SHA-256

size_t _build_non_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
{
    size_t length = MIN(message_length - start_index, 64);
    memcpy(bytes, message + start_index, length);

    if (length < 64) {
        bytes[length] = 0x80;
    }

    return length;
}

size_t _build_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
{
    if (start_index < message_length || message_length % 64 == 0) {
        size_t length = MIN(message_length - start_index, 64);
        memcpy(bytes, message + start_index, length);
        bytes[length] = 0x80;
    }

    uint64_t message_length_in_bits = 8 * message_length;
    for (uint8_t i = 0; i < 8; i++) {
        bytes[56 + i] = (uint8_t)(message_length_in_bits >> 8*(7-i));
    }

    return 0;
}

size_t _build_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index)
{
    if (start_index >= message_length || message_length - start_index <= 55) {
        return _build_last_block(bytes, message, message_length, start_index);
    }
    return _build_non_last_block(bytes, message, message_length, start_index);
}

// 5.3   Setting the Initial Hash Value
// 5.3.3 SHA-256

#define H_0_0 0x6a09e667
#define H_1_0 0xbb67ae85
#define H_2_0 0x3c6ef372
#define H_3_0 0xa54ff53a
#define H_4_0 0x510e527f
#define H_5_0 0x9b05688c
#define H_6_0 0x1f83d9ab
#define H_7_0 0x5be0cd19

// 6.    SECURE HASH ALGORITHMS
// 6.2   SHA-256

void _block_bytes_to_words(uint8_t block_bytes[64], uint32_t block_words[16])
{
    for (int i = 0; i < 16; i++) {
        block_words[i] = ((uint32_t)block_bytes[i * 4    ] << 24) |
                         ((uint32_t)block_bytes[i * 4 + 1] << 16) |
                         ((uint32_t)block_bytes[i * 4 + 2] <<  8) |
                         ((uint32_t)block_bytes[i * 4 + 3] <<  0);
    }
}

void _compute_hash(const char *message, size_t message_length, uint32_t digest[8])
{
    uint32_t H_i[8] = {
        H_0_0, H_1_0, H_2_0, H_3_0, H_4_0, H_5_0, H_6_0, H_7_0
    };

    uint32_t K_256[64] = { 
        K_0_256, K_1_256, K_2_256, K_3_256, K_4_256, K_5_256, K_6_256, K_7_256, 
        K_8_256, K_9_256, K_10_256, K_11_256, K_12_256, K_13_256, K_14_256, K_15_256, 
        K_16_256, K_17_256, K_18_256, K_19_256, K_20_256, K_21_256, K_22_256, K_23_256, 
        K_24_256, K_25_256, K_26_256, K_27_256, K_28_256, K_29_256, K_30_256, K_31_256, 
        K_32_256, K_33_256, K_34_256, K_35_256, K_36_256, K_37_256, K_38_256, K_39_256, 
        K_40_256, K_41_256, K_42_256, K_43_256, K_44_256, K_45_256, K_46_256, K_47_256, 
        K_48_256, K_49_256, K_50_256, K_51_256, K_52_256, K_53_256, K_54_256, K_55_256, 
        K_56_256, K_57_256, K_58_256, K_59_256, K_60_256, K_61_256, K_62_256, K_63_256
    };

    size_t fit = 0;
    size_t consumed = 0;

    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T_1, T_2;

    do {
        uint8_t block_bytes[64] = {0};
        consumed = _build_block(block_bytes, message, message_length, fit);

        uint32_t block_words[16] = {0};
        _block_bytes_to_words(block_bytes, block_words);

        uint32_t W[64] = {0};
        memcpy(W, block_words, 16 * sizeof(uint32_t));
        for (uint8_t t = 16; t < 64; t++) {
            W[t] = ADD4(sigma_1_256(W[t-2]), W[t-7], sigma_0_256(W[t-15]), W[t-16]);
        }

        a = H_i[0];
        b = H_i[1];
        c = H_i[2];
        d = H_i[3];
        e = H_i[4];
        f = H_i[5];
        g = H_i[6];
        h = H_i[7];

        for (uint8_t t = 0; t < 64; t++) {
            T_1 = ADD5(h, SIGMA_1_256(e), Ch(e, f, g), K_256[t], W[t]);
            T_2 = ADD(SIGMA_0_256(a), Maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = ADD(d, T_1);
            d = c;
            c = b;
            b = a;
            a = ADD(T_1, T_2);
        }

        H_i[0] = ADD(a, H_i[0]);
        H_i[1] = ADD(b, H_i[1]);
        H_i[2] = ADD(c, H_i[2]);
        H_i[3] = ADD(d, H_i[3]);
        H_i[4] = ADD(e, H_i[4]);
        H_i[5] = ADD(f, H_i[5]);
        H_i[6] = ADD(g, H_i[6]);
        H_i[7] = ADD(h, H_i[7]);

        fit += consumed;
    } while (consumed > 0);

    digest[0] = H_i[0];
    digest[1] = H_i[1];
    digest[2] = H_i[2];
    digest[3] = H_i[3];
    digest[4] = H_i[4];
    digest[5] = H_i[5];
    digest[6] = H_i[6];
    digest[7] = H_i[7];
}

// Public Functions

void sha256_hash_string(const char *message, size_t message_length, uint32_t digest_destination[8])
{
    _compute_hash(message, message_length, digest_destination);
}

void sha256_digest_to_string(uint32_t digest[8], char string_digest_destination[SHA256_STRING_DIGEST_LENGTH])
{
    sprintf(string_digest_destination, "%08x %08x %08x %08x %08x %08x %08x %08x", 
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6],
        digest[7]
    );
}
