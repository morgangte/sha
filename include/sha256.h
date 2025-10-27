#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// Utils

#define MOD(x, n) ((((x) % (n)) + (n)) % (n))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

// 1.    INTRODUCTION

#define BLOCK_SIZE_IN_BITS 512
#define WORD_SIZE_IN_BITS 32
#define MESSAGE_DIGEST_SIZE_IN_BITS 256

// 3.    NOTATION AND CONVENTIONS
// 3.2   Operations on Words

#define ADD_MODULO 4294967296
#define ADD(x, y) (((x) + (y)) % ADD_MODULO)
#define ADD4(a, b, c, d) ADD(ADD(ADD((a), (b)), (c)), (d))
#define ADD5(a, b, c, d, e) ADD((a), ADD4((b), (c), (d), (e)))

#define ROTL(x, n) (((x) << (n)) | ((x) << (WORD_SIZE_IN_BITS - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (WORD_SIZE_IN_BITS - (n))))
#define SHR(x, n) ((x) >> (n))

// 4.    FUNCTIONS AND CONSTANTS
// 4.1   Functions
// 4.1.2 SHA-224 and SHA-256 Functions

#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA_0_256(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA_1_256(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma_0_256(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
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

void _compute_hash(const char *message, size_t message_length, uint32_t digest[8]);

#endif
