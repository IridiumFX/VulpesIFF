#include <stdio.h>

#include "Test.h"

int main(int argc, char *argv[])
{
	printf("=================================\n");
	printf("  Starting VulpesIFF Test Suite  \n");
	printf("=================================\n");

	RUN_TEST_SUITE(test_suite_parse_basic);
	RUN_TEST_SUITE(test_suite_generate_basic);
	RUN_TEST_SUITE(test_suite_parse_containers);
	RUN_TEST_SUITE(test_suite_generate_containers);
	RUN_TEST_SUITE(test_suite_parse_segments);
	RUN_TEST_SUITE(test_suite_parse_decoders);
	RUN_TEST_SUITE(test_suite_parse_flags);
	RUN_TEST_SUITE(test_suite_parse_checksum);

	printf("\n=================================\n");
	printf("      Test Suite Complete        \n");
	printf("=================================\n");

	return 0;
}
