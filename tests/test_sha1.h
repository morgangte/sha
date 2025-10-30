#ifndef TEST_SHA1_H
#define TEST_SHA1_H

#include <stdint.h>

#include "sha1.h"
#include "minunit.h"

MU_TEST(test_sha1_string_0_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "";
    char expected[] = "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_24_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "abc";
    char expected[] = "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_440_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc";
    char expected[] = "96b713c0 a5f41776 f8bf8572 923f18b0 574f25a2";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_448_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char expected[] = "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_456_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "abcdbcdecdefdefgefghjfghighijhijkijkljklmklmnlmnomnopnopq";
    char expected[] = "f1418faa 27a61763 e8142fa6 4a79b1c6 53394d17";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_512_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "apqghipqudfosjbdqfisqubfoudpuidfhpusqdbfpisqubfpisdqbfiqsbudfibu";
    char expected[] = "d9766f95 6f0af9be c03b7f65 1e747edd b53c8152";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_896_bits) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char expected[] = "a49b2446 a02c645b f419f995 b6709125 3a04a259";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST(test_sha1_string_1_000_000_a) 
{
    uint32_t digest[5];
    char string_digest[SHA1_STRING_DIGEST_LENGTH];

    char message[1000001];
    for (uint32_t i = 0; i < 1000000; i++) {
        message[i] = 'a';
    }
    message[1000000] = '\0';
    char expected[] = "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f";
    
    sha1_hash_string(message, strlen(message), digest);
    sha1_digest_to_string(digest, string_digest);

    mu_assert_string_eq(expected, string_digest);
}

MU_TEST_SUITE(suite_sha1)
{
    MU_RUN_TEST(test_sha1_string_0_bits);
    MU_RUN_TEST(test_sha1_string_24_bits);
    MU_RUN_TEST(test_sha1_string_440_bits);
    MU_RUN_TEST(test_sha1_string_448_bits);
    MU_RUN_TEST(test_sha1_string_456_bits);
    MU_RUN_TEST(test_sha1_string_512_bits);
    MU_RUN_TEST(test_sha1_string_896_bits);
    MU_RUN_TEST(test_sha1_string_1_000_000_a);
}

#endif // TEST_SHA1_H
