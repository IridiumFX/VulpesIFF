#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Result.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

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

/*
 * Writing deep nesting.
 *
 * The generator had the same shape of problem as the parser: encoding a form
 * called back into itself for every form that form contained, so a document's
 * depth became the call depth. It is a stack of explicit frames now.
 *
 * The encoder below writes one form inside another until its counter runs
 * out, which is the smallest thing that exercises that path.
 */

struct PRIVATE_DeepState
{
	VPS_TYPE_SIZE remaining;
	char yielded;
};

static IFF_TYPE_RESULT deep_begin_encode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	struct PRIVATE_DeepState *s = calloc(1, sizeof(struct PRIVATE_DeepState));

	(void)state;

	if (!s) return IFF_FAIL;

	s->remaining = (VPS_TYPE_SIZE)(uintptr_t)source_entity;
	*custom_state = s;

	return IFF_OK;
}

static IFF_TYPE_RESULT deep_produce_chunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	(void)state; (void)custom_state; (void)out_tag; (void)out_data;

	*out_done = 1;

	return IFF_OK;
}

static IFF_TYPE_RESULT deep_produce_nested_form
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_form_type
	, void **out_nested_entity
	, char *out_done
)
{
	struct PRIVATE_DeepState *s = custom_state;

	(void)state;

	/* One child per level, then this level is finished. */
	if (s->yielded || s->remaining == 0)
	{
		*out_done = 1;
		return IFF_OK;
	}

	s->yielded = 1;

	IFF_Tag_Construct(out_form_type, (const unsigned char *)"DEEP", 4, IFF_TAG_TYPE_TAG);
	*out_nested_entity = (void *)(uintptr_t)(s->remaining - 1);
	*out_done = 0;

	return IFF_OK;
}

static IFF_TYPE_RESULT deep_end_encode
(
	struct IFF_Generator_State *state
	, void *custom_state
)
{
	(void)state;

	free(custom_state);

	return IFF_OK;
}

/* Writes `depth` forms nested one inside the next; reports the byte count. */
static VPS_TYPE_RESULT write_nested_forms(VPS_TYPE_SIZE depth, VPS_TYPE_SIZE *out_bytes)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *encoder = 0;
	struct VPS_Data *output = 0;
	struct IFF_Tag deep_tag;
	VPS_TYPE_RESULT result = VPS_FAIL;

	IFF_Tag_Construct(&deep_tag, (const unsigned char *)"DEEP", 4, IFF_TAG_TYPE_TAG);

	if (IFF_Generator_Factory_Allocate(&factory)) return VPS_FAIL;
	if (IFF_Generator_Factory_Construct(factory)) goto cleanup;

	if (IFF_FormEncoder_Allocate(&encoder)) goto cleanup;
	if (IFF_FormEncoder_Construct(encoder, deep_begin_encode, deep_produce_chunk,
		deep_produce_nested_form, deep_end_encode))
	{
		IFF_FormEncoder_Release(encoder);
		goto cleanup;
	}

	if (IFF_Generator_Factory_RegisterFormEncoder(factory, &deep_tag, encoder)) goto cleanup;
	if (IFF_Generator_Factory_CreateToData(factory, &gen)) goto cleanup;

	if (IFF_Generator_EncodeForm(gen, &deep_tag, (void *)(uintptr_t)depth)) goto cleanup;
	if (IFF_Generator_Flush(gen)) goto cleanup;
	if (IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	*out_bytes = output ? output->limit : 0;
	result = VPS_OK;

cleanup:

	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(factory);

	return result;
}

/**
 * @test test_nesting_write_shallow
 * @brief Ordinary nesting writes, and each level costs a header.
 */
static char test_nesting_write_shallow(void)
{
	VPS_TYPE_SIZE small = 0;
	VPS_TYPE_SIZE larger = 0;

	TEST_ASSERT_OK(write_nested_forms(2, &small));
	TEST_ASSERT(small > 0);

	TEST_ASSERT_OK(write_nested_forms(10, &larger));
	TEST_ASSERT(larger > small);

	return 1;
}

/**
 * @test test_nesting_write_past_stack_capacity
 * @brief Writing deeper than any call stack could carry.
 *
 * Regression: the encoder recursed once per level, so this many nested forms
 * did not return -- the process died, the same way the parser did before its
 * traversal moved to the heap.
 */
static char test_nesting_write_past_stack_capacity(void)
{
	VPS_TYPE_SIZE bytes = 0;

	TEST_ASSERT_OK(write_nested_forms(20000, &bytes));
	TEST_ASSERT(bytes > 20000);

	return 1;
}

/**
 * @test test_nesting_roundtrip_deep
 * @brief What the generator writes deep, the parser reads back.
 *
 * The two sides moved off the stack independently; this is the check that
 * they still agree about the same document.
 */
static char test_nesting_roundtrip_deep(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *encoder = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct IFF_Tag deep_tag;
	char verdict = 0;

	IFF_Tag_Construct(&deep_tag, (const unsigned char *)"DEEP", 4, IFF_TAG_TYPE_TAG);

	TEST_ASSERT_OK(IFF_Generator_Factory_Allocate(&factory));
	TEST_ASSERT_OK(IFF_Generator_Factory_Construct(factory));
	TEST_ASSERT_OK(IFF_FormEncoder_Allocate(&encoder));
	TEST_ASSERT_OK(IFF_FormEncoder_Construct(encoder, deep_begin_encode, deep_produce_chunk,
		deep_produce_nested_form, deep_end_encode));
	TEST_ASSERT_OK(IFF_Generator_Factory_RegisterFormEncoder(factory, &deep_tag, encoder));
	TEST_ASSERT_OK(IFF_Generator_Factory_CreateToData(factory, &gen));

	TEST_ASSERT_OK(IFF_Generator_EncodeForm(gen, &deep_tag, (void *)(uintptr_t)5000));
	TEST_ASSERT_OK(IFF_Generator_Flush(gen));
	TEST_ASSERT_OK(IFF_Generator_GetOutputData(gen, &output));
	TEST_ASSERT(output != 0);

	if (IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT_OK(IFF_Parser_Scan(parser));

	verdict = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(factory);

	return verdict;
}

void test_suite_nesting(void)
{
	success_count = 0;
	failure_count = 0;

	RUN_TEST(test_nesting_shallow_parses);
	RUN_TEST(test_nesting_past_stack_capacity_parses);
	RUN_TEST(test_nesting_unwinds_between_scans);
	RUN_TEST(test_nesting_truncated_is_refused);
	RUN_TEST(test_nesting_write_shallow);
	RUN_TEST(test_nesting_write_past_stack_capacity);
	RUN_TEST(test_nesting_roundtrip_deep);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
