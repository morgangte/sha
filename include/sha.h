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
 * @internal
 * @brief The rotate left (circular left shift) operation as defined in 
 * section 3.2 of the Secure Hash Standard.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (WORD_SIZE_IN_BITS - (n))))

/**
 * @internal
 * @brief The rotate right (circular right shift) operation as defined in 
 * section 3.2 of the Secure Hash Standard.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (WORD_SIZE_IN_BITS - (n))))

/**
 * @internal
 * @brief The right shift operation as defined in section 3.2 of the Secure
 * Hash Standard.
 * 
 * @param x A w-bit word
 * @param n An integer with 0 <= n < w
 */
#define SHR(x, n) ((x) >> (n))

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
