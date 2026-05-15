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
	RUN_TEST_SUITE(test_suite_generate_advanced);
	RUN_TEST_SUITE(test_suite_generate_encoders);
	RUN_TEST_SUITE(test_suite_parse_bootstrap);
	RUN_TEST_SUITE(test_suite_parse_header_flags);
	RUN_TEST_SUITE(test_suite_generate_validation);
	RUN_TEST_SUITE(test_suite_parse_containers_advanced);
	RUN_TEST_SUITE(test_suite_parse_chunks);
	RUN_TEST_SUITE(test_suite_parse_directives);
	RUN_TEST_SUITE(test_suite_generate_chunks);
	RUN_TEST_SUITE(test_suite_generate_header);
	RUN_TEST_SUITE(test_suite_generate_filler);
	RUN_TEST_SUITE(test_suite_parse_midstream);
	RUN_TEST_SUITE(test_suite_parse_boundary);
	RUN_TEST_SUITE(test_suite_parse_flags_combo);
	RUN_TEST_SUITE(test_suite_generate_containers_blobbed);
	RUN_TEST_SUITE(test_suite_generate_progressive);
	RUN_TEST_SUITE(test_suite_generate_flags);
	RUN_TEST_SUITE(test_suite_parse_props);
	RUN_TEST_SUITE(test_suite_parse_decoders_advanced);
	RUN_TEST_SUITE(test_suite_parse_sharding);
	RUN_TEST_SUITE(test_suite_parse_ref_mandatory);
	RUN_TEST_SUITE(test_suite_generate_directives);
	RUN_TEST_SUITE(test_suite_generate_checksum_span);
	RUN_TEST_SUITE(test_suite_generate_encoders_advanced);
	RUN_TEST_SUITE(test_suite_parse_container_delivery);
	RUN_TEST_SUITE(test_suite_generate_container_groups);
	RUN_TEST_SUITE(test_suite_parse_checksum_advanced);
	RUN_TEST_SUITE(test_suite_parse_checksum_algorithms);
	RUN_TEST_SUITE(test_suite_parse_midstream_sharding);
	RUN_TEST_SUITE(test_suite_generate_checksum_advanced);
	RUN_TEST_SUITE(test_suite_generate_flags_advanced);
	RUN_TEST_SUITE(test_suite_roundtrip);
	RUN_TEST_SUITE(test_suite_parse_version);
	RUN_TEST_SUITE(test_suite_generate_bytes_written);

	printf("\n=================================\n");
	printf("      Test Suite Complete        \n");
	printf("=================================\n");

	return 0;
}
