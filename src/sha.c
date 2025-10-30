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
 * @file sha.c
 * @brief Generic SHA functions.
 * 
 * This implementation directly follows the standard described in 
 * the FIPS PUB 180-4:
 * 
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#include "sha.h"

#include <string.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

// 5.    PREPROCESSING
// 5.1   Padding the Message
// 5.1.1 SHA-1, SHA-224 and SHA-256

static size_t _sha1_sha224_sha256_build_non_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
{
    size_t length = MIN(message_length - start_index, 64);
    memcpy(bytes, message + start_index, length);

    if (length < 64) {
        bytes[length] = 0x80;
    }

    return length;
}

static size_t _sha1_sha224_sha256_build_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
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

size_t _sha1_sha224_sha256_build_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index)
{
    if (start_index >= message_length || message_length - start_index <= 55) {
        return _sha1_sha224_sha256_build_last_block(bytes, message, message_length, start_index);
    }
    return _sha1_sha224_sha256_build_non_last_block(bytes, message, message_length, start_index);
}
