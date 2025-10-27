#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 5.    PREPROCESSING
// 5.1   Padding the Message
// 5.1.1 SHA-1, SHA-224 and SHA-256

size_t _build_non_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
{
    if (start_index >= message_length) {
        printf("ERROR start_index\n");
        exit(1);
    }

    size_t length = MIN(message_length - start_index, 64);
    memcpy(bytes, message + start_index*sizeof(char), length);

    if (length < 64) {
        bytes[length] = 0x80;
    }

    return length;
}

size_t _build_last_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index) 
{
    if (start_index < message_length) {
        size_t length = MIN(message_length - start_index, 64);
        memcpy(bytes, message + start_index*sizeof(char), length);
        bytes[length] = 0x80;
    }

    size_t message_length_in_bits = 8 * message_length;
    for (uint8_t i = 0; i < 8; i++) {
        bytes[56 + i] = (uint8_t)(message_length_in_bits >> 8*(7-i));
    }

    return 0;
}

size_t _build_block(uint8_t bytes[64], const char *message, size_t message_length, size_t start_index)
{
    if (start_index >= message_length || message_length - start_index <= 55) {
        printf("Build last block\n");
        return _build_last_block(bytes, message, message_length, start_index);
    }

    printf("Build non last block\n");
    return _build_non_last_block(bytes, message, message_length, start_index);
}

// 6.    SECURE HASH ALGORITHMS
// 6.2   SHA-256

void _block_bytes_to_words(uint8_t block_bytes[64], uint32_t block_words[16])
{
    for (int i = 0; i < 16; i++) {
        block_words[i] = ((uint32_t)block_bytes[i * 4 + 0] << 24) |
                         ((uint32_t)block_bytes[i * 4 + 1] << 16) |
                         ((uint32_t)block_bytes[i * 4 + 2] << 8)  |
                         ((uint32_t)block_bytes[i * 4 + 3]);
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
    size_t last_fit = 0;

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    uint32_t T_1;
    uint32_t T_2;

    do {
        uint8_t block_bytes[64] = {0};
        last_fit = _build_block(block_bytes, message, message_length, fit);

        uint32_t block_words[16] = {0};
        _block_bytes_to_words(block_bytes, block_words);

        uint32_t W[64] = {0};
        // TODO: replace with memcpy
        for (uint8_t t = 0; t < 16; t++) {
            W[t] = block_words[t];
        }
        for (uint8_t t = 16; t < 64; t++) {
            W[t] = ADD4( sigma_1_256(W[t-2]), W[t-7], sigma_0_256(W[t-15]), W[t-16] );
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


        fit += last_fit;
    } while (last_fit > 0);

    digest[0] = H_i[0];
    digest[1] = H_i[1];
    digest[2] = H_i[2];
    digest[3] = H_i[3];
    digest[4] = H_i[4];
    digest[5] = H_i[5];
    digest[6] = H_i[6];
    digest[7] = H_i[7];
}
