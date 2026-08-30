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
 * Containers used to be parsed by recursion, one C stack frame pair per
 * level, so a file's nesting depth became the process's call depth. A
 * container header is twelve bytes, which makes depth very cheap to buy: an
 * 84 KB file of nothing but nested 'CAT ' headers ran a one-megabyte stack
 * out, and the process died inside the allocator, nowhere near the cause.
 *
 * The traversal is a flat loop over the session's scope stack now, so a
 * level costs one heap scope and nothing on the C stack. These tests hold
 * that: depths far past what any stack could carry parse normally, and the
 * only thing that stops them is running out of memory.
 *
 * The builder in IFF_TestBuilder caps its own nesting well below what is
 * interesting here, so these cases assemble the bytes directly.
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
 * @test test_nesting_shallow_parses
 * @brief Ordinary nesting depths parse, as they always did.
 */
static char test_nesting_shallow_parses(void)
{
	char accepted = 0;

	TEST_ASSERT_OK(scan_nested_cats(1, &accepted));
	TEST_ASSERT(accepted);

	TEST_ASSERT_OK(scan_nested_cats(8, &accepted));
	TEST_ASSERT(accepted);

	TEST_ASSERT_OK(scan_nested_cats(64, &accepted));
	TEST_ASSERT(accepted);

	return 1;
}

/**
 * @test test_nesting_past_stack_capacity_parses
 * @brief Depths that no call stack could carry parse normally.
 *
 * Regression: 20000 levels is 240 KB of input and roughly twenty thousand
 * frame pairs. Under the recursive parser this did not return -- the process
 * died. Reaching the assertions at all is most of what this test checks; that
 * the parse is also *accepted* is the rest, since a depth limit would refuse
 * it rather than crash.
 */
static char test_nesting_past_stack_capacity_parses(void)
{
	char accepted = 0;

	TEST_ASSERT_OK(scan_nested_cats(20000, &accepted));
	TEST_ASSERT(accepted);

	return 1;
}

/**
 * @test test_nesting_unwinds_between_scans
 * @brief A deep parse leaves nothing behind for the next one.
 *
 * The scope stack is the traversal's own stack now, so a parse that fails to
 * unwind it would show up as the parse after it behaving oddly rather than as
 * anything local. A shallow file after a very deep one must be unaffected.
 */
static char test_nesting_unwinds_between_scans(void)
{
	char accepted = 0;

	TEST_ASSERT_OK(scan_nested_cats(10000, &accepted));
	TEST_ASSERT(accepted);

	TEST_ASSERT_OK(scan_nested_cats(4, &accepted));
	TEST_ASSERT(accepted);

	TEST_ASSERT_OK(scan_nested_cats(10000, &accepted));
	TEST_ASSERT(accepted);

	return 1;
}

/**
 * @test test_nesting_truncated_is_refused
 * @brief A deep nest whose declared sizes do not close is still refused.
 *
 * Depth being unlimited must not mean malformed input is tolerated: the
 * boundary checks that close each level still apply at every one of them.
 */
static char test_nesting_truncated_is_refused(void)
{
	struct VPS_Data *data = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	char verdict = 0;

	TEST_ASSERT_OK(build_nested_cats(500, &data));

	/* Cut the last level off. Every enclosing size now over-runs the data. */
	data->limit -= 12;

	TEST_ASSERT_OK(IFF_Parser_Factory_Allocate(&factory));
	TEST_ASSERT_OK(IFF_Parser_Factory_Construct(factory));
	if (IFF_Parser_Factory_CreateFromData(factory, data, &parser)) goto cleanup;

	TEST_ASSERT_FAIL(IFF_Parser_Scan(parser));

	verdict = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	VPS_Data_Release(data);

	return verdict;
}

void test_suite_parse_nesting(void)
{
	success_count = 0;
	failure_count = 0;

	RUN_TEST(test_nesting_shallow_parses);
	RUN_TEST(test_nesting_past_stack_capacity_parses);
	RUN_TEST(test_nesting_unwinds_between_scans);
	RUN_TEST(test_nesting_truncated_is_refused);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
