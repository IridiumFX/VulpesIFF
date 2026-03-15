cmake_minimum_required(VERSION 3.10)

project(VulpesIFF_Tests)

add_executable(VulpesIFF_Tests
	test_main.c
	test_parse_basic.c
	test_generate_basic.c
	test_parse_containers.c
	test_generate_containers.c
	test_parse_segments.c
	test_parse_decoders.c
	test_parse_flags.c
	test_parse_checksum.c
	test_generate_advanced.c
	test_generate_encoders.c
	test_parse_bootstrap.c
	test_parse_header_flags.c
	test_generate_validation.c
	test_parse_containers_advanced.c
	test_parse_chunks.c
	test_parse_directives.c
	test_generate_chunks.c
	test_generate_header.c
	test_generate_filler.c
	test_parse_midstream.c
	test_parse_boundary.c
	test_parse_flags_combo.c
	test_generate_containers_blobbed.c
	test_generate_progressive.c
	test_generate_flags.c
	test_parse_props.c
	test_parse_decoders_advanced.c
	test_parse_sharding.c
	test_parse_ref_mandatory.c
	test_generate_directives.c
	test_generate_checksum_span.c
	test_generate_encoders_advanced.c
	test_parse_checksum_advanced.c
	test_parse_checksum_algorithms.c
	test_parse_midstream_sharding.c
	test_generate_checksum_advanced.c
	test_generate_flags_advanced.c
	test_roundtrip.c
	test_parse_version.c
	test_generate_bytes_written.c
	test_harness/IFF_TestBuilder.c
	test_harness/IFF_TestDecoders.c
	test_harness/IFF_TestChecksumAlgorithm.c
	test_harness/IFF_TestEncoders.c
)

target_include_directories(VulpesIFF_Tests PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/test_harness
)

target_link_libraries(VulpesIFF_Tests PRIVATE VulpesIFF)
