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
 * @file sha256.h
 * @brief SHA-256 implementation header file.
 * 
 * This implementation directly follows the standard described in 
 * the FIPS PUB 180-4:
 * 
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Computes the SHA-256 hash of a string.
 * 
 * @param message The string message to hash
 * @param message_length The length of the message to hash
 * @param digest_destination The resulting hash
 */
void sha256_hash_string(const char *message, size_t message_length, uint32_t digest_destination[8]);

/**
 * @brief The length of the digest string output by sha256_digest_to_string()
 */
#define SHA256_STRING_DIGEST_LENGTH 72

/**
 * @brief Transforms a SHA-256 digest into a readable string.
 * 
 * @param digest The SHA-256 digest
 * @param string_digest_destination The resulting string digest
 */
void sha256_digest_to_string(uint32_t digest[8], char string_digest_destination[SHA256_STRING_DIGEST_LENGTH]);

#endif
