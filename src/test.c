#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "sha256.h"

void print_digest(uint32_t digest[8])
{
    for (uint8_t i = 0; i < 8; i++) {
        printf("%08X ", digest[i]);
    }
    printf("\n");
}

int main(void)
{
    char message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t length = strlen(message);
    uint32_t digest[8];

    _compute_hash(message, length, digest);

    print_digest(digest);

    return 0;
}