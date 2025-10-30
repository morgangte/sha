#ifndef SHA_H
#define SHA_H

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
 * @file sha.h
 * @brief Generic SHA functions header file.
 * 
 * This implementation directly follows the standard described in 
 * the FIPS PUB 180-4:
 * 
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#include <stdlib.h>
#include <stdint.h>

// 3.    NOTATION AND CONVENTIONS
// 3.2   Operations on Words

/**
 * @brief Performs addition modulo 2^w.
 * @note The macro 'ADD_MODULO' must be defined in the implementation 
 * source file.
 * 
 * @param x The first parameter
 * @param y The second parameter
 */
#define ADD(x, y) (uint32_t)(((uint32_t)(x) + (uint32_t)(y)) % ADD_MODULO)

/**
 * @brief Performs the addition of 4 integers modulo 2^w.
 * 
 * @param a
 * @param b
 * @param c
 * @param d
 */
#define ADD4(a, b, c, d) (uint32_t)(ADD(ADD(ADD((a), (b)), (c)), (d)))

/**
 * @brief Performs the addition of 5 integers modulo 2^w.
 * 
 * @param a
 * @param b
 * @param c
 * @param d
 * @param e
 */
#define ADD5(a, b, c, d, e) (uint32_t)(ADD((a), ADD4((b), (c), (d), (e))))

/**
 * @brief The rotate left (circular left shift) operation as defined in 
 * section 3.2 of the Secure Hash Standard.
 * @note The macro 'WORD_SIZE_IN_BITS' must be defined in the implementation
 * source file.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (WORD_SIZE_IN_BITS - (n))))

/**
 * @brief The rotate right (circular right shift) operation as defined in 
 * section 3.2 of the Secure Hash Standard.
 * @note The macro 'WORD_SIZE_IN_BITS' must be defined in the implementation
 * source file.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (WORD_SIZE_IN_BITS - (n))))

/**
 * @brief The right shift operation as defined in section 3.2 of the Secure
 * Hash Standard.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define SHR(x, n) ((x) >> (n))

// 4.    FUNCTIONS AND CONSTANTS
// 4.1   Functions
// 4.1.2 SHA-224 and SHA-256 Functions

#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Parity(x, y, z) ((x) ^ (y) ^ (z))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA_0_256(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA_1_256(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma_0_256(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma_1_256(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/**
 * @brief Transforms a block of 64 bytes into a bock of 16 words.
 * 
 * @param block_bytes The 64 bytes to transform
 * @param block_words The 16 words destination
 */
void _block_bytes_to_uint32_words(uint8_t block_bytes[64], uint32_t block_words[16]);

// 5.    PREPROCESSING
// 5.1   Padding the Message
// 5.1.1 SHA-1, SHA-224 and SHA-256

/**
 * @brief Builds a block for the SHA-1, SHA-224 and SHA-256 algorithms. See
 * section 5.1.1 of the Secure Hash Standard.
 * 
 * @param bytes The resulting block destination
 * @param message The message to hash
 * @param message_length The full message length
 * @param start_index The starting index for the message
 */
size_t _sha1_sha224_sha256_build_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index);

#endif
