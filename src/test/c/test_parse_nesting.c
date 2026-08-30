#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Result.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"

static int success_count = 0;
static int failure_count = 0;

/*
 * Container nesting.
 *
 * Containers are parsed by recursion, one frame pair per level, so a file's
 * nesting depth becomes the parser's call depth. A container header is only
 * twelve bytes, so depth is very cheap to buy: before the ceiling existed,
 * about seven thousand levels -- an 84 KB file -- ran a one-megabyte stack
 * out and the process died inside the allocator, nowhere near the cause.
 *
 * The builder in IFF_TestBuilder caps its own nesting well below the limit
 * under test, so these cases assemble the bytes directly.
 */

/* n nested 'CAT ' containers, twelve bytes each, sized from the inside out. */
static VPS_TYPE_RESULT build_nested_cats(VPS_TYPE_SIZE n, struct VPS_Data **out)
{
	struct VPS_Data *data = 0;
	VPS_TYPE_SIZE total = 12 * n;
	VPS_TYPE_SIZE i;

	if (VPS_Data_Allocate(&data, total, total)) return VPS_FAIL;
	if (VPS_Data_Construct(data))
	{
		VPS_Data_Release(data);
		return VPS_FAIL;
	}

	for (i = 0; i < n; ++i)
	{
		unsigned char *p = data->bytes + 12 * i;

		/* Each level encloses every level after it, plus its own type. */
		VPS_TYPE_32U size = (VPS_TYPE_32U)(4 + 12 * (n - i - 1));

		memcpy(p, "CAT ", 4);
		p[4] = (unsigned char)(size >> 24);
		p[5] = (unsigned char)(size >> 16);
		p[6] = (unsigned char)(size >> 8);
		p[7] = (unsigned char)(size);
		memcpy(p + 8, "TEST", 4);
	}

	data->limit = total;
	*out = data;

	return VPS_OK;
}

/* Parses a nest of the given depth; reports whether the scan succeeded. */
static VPS_TYPE_RESULT scan_nested_cats(VPS_TYPE_SIZE depth, char *out_accepted)
{
	struct VPS_Data *data = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	VPS_TYPE_RESULT result = VPS_FAIL;

	if (build_nested_cats(depth, &data)) return VPS_FAIL;

	if (IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (IFF_Parser_Factory_CreateFromData(factory, data, &parser)) goto cleanup;

	*out_accepted = IFF_Parser_Scan(parser) == IFF_OK;
	result = VPS_OK;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	VPS_Data_Release(data);

	return result;
}

/**
 * @test test_nesting_within_limit_parses
 * @brief Nesting up to the ceiling is ordinary, accepted input.
 */
static char test_nesting_within_limit_parses(void)
{
	char accepted = 0;

	TEST_ASSERT_OK(scan_nested_cats(1, &accepted));
	TEST_ASSERT(accepted);

	TEST_ASSERT_OK(scan_nested_cats(IFF_PARSER_MAX_NESTING_DEPTH / 2, &accepted));
	TEST_ASSERT(accepted);

	/* Exactly at the ceiling still parses: the limit is inclusive. */
	TEST_ASSERT_OK(scan_nested_cats(IFF_PARSER_MAX_NESTING_DEPTH, &accepted));
	TEST_ASSERT(accepted);

	return 1;
}

/**
 * @test test_nesting_beyond_limit_refused
 * @brief One level past the ceiling is refused rather than followed.
 */
static char test_nesting_beyond_limit_refused(void)
{
	char accepted = 1;

	TEST_ASSERT_OK(scan_nested_cats(IFF_PARSER_MAX_NESTING_DEPTH + 1, &accepted));
	TEST_ASSERT(!accepted);

	return 1;
}

/**
 * @test test_nesting_pathological_depth_refused
 * @brief A file that is nothing but nested headers is refused, not fatal.
 *
 * Twenty thousand levels is 240 KB and comfortably past what the stack can
 * carry. Reaching the end of this test at all is the assertion: without the
 * ceiling the process does not return from the scan.
 */
static char test_nesting_pathological_depth_refused(void)
{
	char accepted = 1;

	TEST_ASSERT_OK(scan_nested_cats(20000, &accepted));
	TEST_ASSERT(!accepted);

	return 1;
}

/**
 * @test test_nesting_depth_resets_between_scans
 * @brief The depth counter unwinds, so sequential parses are unaffected.
 *
 * The counter is decremented on the way back out rather than reset at entry,
 * so a leak would show up as a later parse being refused for depth it never
 * used. A refused parse must not poison the parser that follows it.
 */
static char test_nesting_depth_resets_between_scans(void)
{
	char accepted = 0;

	TEST_ASSERT_OK(scan_nested_cats(IFF_PARSER_MAX_NESTING_DEPTH + 1, &accepted));
	TEST_ASSERT(!accepted);

	/* A shallow file still parses after the refusal. */
	TEST_ASSERT_OK(scan_nested_cats(4, &accepted));
	TEST_ASSERT(accepted);

	/* And so does one right at the ceiling. */
	TEST_ASSERT_OK(scan_nested_cats(IFF_PARSER_MAX_NESTING_DEPTH, &accepted));
	TEST_ASSERT(accepted);

	return 1;
}

void test_suite_parse_nesting(void)
{
	success_count = 0;
	failure_count = 0;

	RUN_TEST(test_nesting_within_limit_parses);
	RUN_TEST(test_nesting_beyond_limit_refused);
	RUN_TEST(test_nesting_pathological_depth_refused);
	RUN_TEST(test_nesting_depth_resets_between_scans);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
