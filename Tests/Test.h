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
