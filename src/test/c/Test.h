// --- Test Runner Macros ---

#define TEST_ASSERT(condition) \
if (!(condition)) { \
printf("    [FAIL] Assertion failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
return 0; \
}

#define RUN_TEST(test_func) \
printf("  Running test: %s\n", #test_func); \
if (test_func()) { \
printf("    [PASS]\n"); \
success_count++; \
} else { \
failure_count++; \
}

#define RUN_TEST_SUITE(suite_func) \
printf("\n--- Running test suite: %s ---\n", #suite_func); \
suite_func();

// --- Test Suite Function Declarations ---
void test_suite_parse_basic(void);
void test_suite_generate_basic(void);
void test_suite_parse_containers(void);
void test_suite_generate_containers(void);
void test_suite_parse_segments(void);
void test_suite_parse_decoders(void);
void test_suite_parse_flags(void);
void test_suite_parse_checksum(void);
void test_suite_generate_advanced(void);
void test_suite_generate_encoders(void);
void test_suite_parse_bootstrap(void);
void test_suite_parse_header_flags(void);
void test_suite_generate_validation(void);
void test_suite_parse_containers_advanced(void);
void test_suite_parse_chunks(void);
void test_suite_parse_directives(void);
void test_suite_generate_chunks(void);
void test_suite_generate_header(void);
void test_suite_generate_filler(void);
void test_suite_parse_midstream(void);
void test_suite_parse_boundary(void);
void test_suite_parse_flags_combo(void);
void test_suite_generate_containers_blobbed(void);
void test_suite_generate_progressive(void);
void test_suite_generate_flags(void);
void test_suite_parse_props(void);
void test_suite_parse_decoders_advanced(void);
void test_suite_parse_sharding(void);
void test_suite_parse_ref_mandatory(void);
void test_suite_generate_directives(void);
void test_suite_generate_checksum_span(void);
void test_suite_generate_encoders_advanced(void);
void test_suite_parse_checksum_advanced(void);
void test_suite_parse_checksum_algorithms(void);
void test_suite_parse_midstream_sharding(void);
void test_suite_generate_checksum_advanced(void);
void test_suite_generate_flags_advanced(void);
void test_suite_roundtrip(void);
void test_suite_parse_version(void);
void test_suite_generate_bytes_written(void);
void test_suite_parse_container_delivery(void);
void test_suite_generate_container_groups(void);
