#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#include "sha256.h"

int _test_hash_string(const char *message, size_t message_length, const char *expected_hash)
{
    uint32_t digest[8];
    char string_digest[SHA256_STRING_DIGEST_LENGTH];
    sha256_hash_string(message, message_length, digest);
    sha256_digest_to_string(digest, string_digest);

    return strcmp(string_digest, expected_hash);
}

int test_hash_empty_string()
{
    char message[] = "";
    char expected[] = "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_24_bits()
{
    char message[] = "abc";
    char expected[] = "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_440_bits()
{
    char message[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc";
    char expected[] = "2c886b3d 53367f58 d29fe6f4 1442c60c 63005ce9 f6c59783 c01b7832 fb260d5b";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_448_bits()
{
    char message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char expected[] = "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_456_bits()
{
    char message[] = "abcdbcdecdefdefgefghjfghighijhijkijkljklmklmnlmnomnopnopq";
    char expected[] = "aade6485 e8f82a30 5b76573c bf75eead 6ebf86a2 d468e501 384bd8f7 eecdd13c";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_512_bits()
{
    char message[] = "apqghipqudfosjbdqfisqubfoudpuidfhpusqdbfpisqubfpisdqbfiqsbudfibu";
    char expected[] = "6ab3d64a d335f115 6ec759a1 4345734f a5b1dc52 66923b96 02886cb0 ba4fa22d";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_896_bits()
{
    char message[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char expected[] = "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_ten_thousand_a()
{
    char message[10001];
    for (uint32_t i = 0; i < 10000; i++) {
        message[i] = 'a';
    }
    message[10000] = '\0';
    char expected[] = "27dd1f61 b867b6a0 f6e9d8a4 1c43231d e52107e5 3ae424de 8f847b82 1db4b711";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_hundred_thousand_a()
{
    char message[100001];
    for (uint32_t i = 0; i < 100000; i++) {
        message[i] = 'a';
    }
    message[100000] = '\0';
    char expected[] = "6d1cf22d 7cc09b08 5dfc25ee 1a1f3ae0 265804c6 07bc2074 ad253bcc 82fd81ee";
    return _test_hash_string(message, strlen(message), expected);
}

int test_hash_string_million_a()
{
    char message[1000001];
    for (uint32_t i = 0; i < 1000000; i++) {
        message[i] = 'a';
    }
    message[1000000] = '\0';
    char expected[] = "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0";
    return _test_hash_string(message, strlen(message), expected);
}

int run_test(const char *test_name, int (*test)(), int *total, int *passed)
{
    *total += 1;
    int failed = test();
    if (failed) {
        printf("[Test failed: %s]", test_name);
        fflush(stdout);
        return EXIT_FAILURE;
    } else {
        *passed += 1;
        printf(".");
        fflush(stdout);
        return EXIT_SUCCESS;
    }
}

int run_tests()
{
    int passed = 0;
    int total = 0;
    run_test("test_hash_empty_string", test_hash_empty_string, &total, &passed);
    run_test("test_hash_string_24_bits", test_hash_string_24_bits, &total, &passed);
    run_test("test_hash_string_440_bits", test_hash_string_440_bits, &total, &passed);
    run_test("test_hash_string_448_bits", test_hash_string_448_bits, &total, &passed);
    run_test("test_hash_string_456_bits", test_hash_string_456_bits, &total, &passed);
    run_test("test_hash_string_512_bits", test_hash_string_512_bits, &total, &passed);
    run_test("test_hash_string_896_bits", test_hash_string_896_bits, &total, &passed);
    run_test("test_hash_string_ten_thousand_a", test_hash_string_ten_thousand_a, &total, &passed);
    run_test("test_hash_string_hundred_thousand_a", test_hash_string_hundred_thousand_a, &total, &passed);
    run_test("test_hash_string_million_a", test_hash_string_million_a, &total, &passed);

    if (passed == total) {
        printf("\nAll %d/%d tests have been passed successfully.\n", passed, total);
        return EXIT_SUCCESS;    
    } 
    printf("\n%d/%d tests passed, %d failed.\n", passed, total, total-passed);
    return EXIT_FAILURE;
}

int main(void)
{
    return run_tests();
}