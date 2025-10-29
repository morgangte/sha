#include "minunit.h"

#include "test_sha256.h"

int main(void)
{
    MU_RUN_SUITE(suite_sha256);

    MU_REPORT();
    return MU_EXIT_CODE;
}
