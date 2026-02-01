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
	test_harness/IFF_TestBuilder.c
	test_harness/IFF_TestDecoders.c
	test_harness/IFF_TestChecksumAlgorithm.c
)

target_include_directories(VulpesIFF_Tests PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/test_harness
)

target_link_libraries(VulpesIFF_Tests PRIVATE VulpesIFF)
