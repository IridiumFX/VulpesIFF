#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_List.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"

// =========================================================================
// Helpers
// =========================================================================

static char PRIVATE_CreateMemoryGenerator
(
	struct IFF_Generator_Factory **out_factory
	, struct IFF_Generator **out_gen
)
{
	if (!IFF_Generator_Factory_Allocate(out_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(*out_factory)) return 0;
	if (!IFF_Generator_Factory_CreateToData(*out_factory, out_gen)) return 0;

	return 1;
}

static void PRIVATE_Cleanup
(
	struct IFF_Generator *gen
	, struct IFF_Generator_Factory *factory
)
{
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(factory);
}

static struct VPS_Data PRIVATE_WrapData
(
	unsigned char *bytes
	, VPS_TYPE_SIZE size
)
{
	struct VPS_Data wrap;
	memset(&wrap, 0, sizeof(wrap));
	wrap.bytes = bytes;
	wrap.size = size;
	wrap.limit = size;
	wrap.own_bytes = 0;
	return wrap;
}

// =========================================================================
// Test 49: CreateToData — GetOutputData returns non-null after Flush
// =========================================================================
static char test_gen_create_to_data(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	TEST_ASSERT(IFF_Generator_GetOutputData(gen, &output));
	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 50: New generator has IFF-85 default flags (all zero)
// =========================================================================
static char test_gen_default_flags(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	TEST_ASSERT(gen->flags.as_int == IFF_HEADER_FLAGS_1985.as_int);

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 51: Flush with no content succeeds (empty output)
// =========================================================================
static char test_gen_flush_empty(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	TEST_ASSERT(IFF_Generator_Flush(gen));

	TEST_ASSERT(IFF_Generator_GetOutputData(gen, &output));
	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit == 0);

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 52: Flush with open scope fails
// =========================================================================
static char test_gen_flush_open_scope_fails(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;

	// Flush without EndForm should fail.
	TEST_ASSERT(!IFF_Generator_Flush(gen));

	// Clean up the scope so Release doesn't leak.
	IFF_Generator_EndForm(gen);

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 53: WriteChunk at root level (no container) fails
// =========================================================================
static char test_gen_chunk_at_root_fails(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 4);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	// Chunks require a FORM or PROP container; root rejects them.
	TEST_ASSERT(!IFF_Generator_WriteChunk(gen, &tag, &wrap));

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 54: FORM allows chunks
// =========================================================================
static char test_gen_form_allows_chunks(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 4);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 55: LIST rejects chunks
// =========================================================================
static char test_gen_list_rejects_chunks(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 4);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap));
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 56: CAT rejects chunks
// =========================================================================
static char test_gen_cat_rejects_chunks(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 4);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap));
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 57: PROP allows chunks
// =========================================================================
static char test_gen_prop_allows_chunks(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Tag list_type;
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&list_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 4);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	// PROP must be inside a LIST.
	if (!IFF_Generator_BeginList(gen, &list_type)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap));
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 58: FORM allows nested FORM (FORM supports nested containers)
// =========================================================================
static char test_gen_form_allows_nested_form(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 59: FORM allows nested LIST (FORM supports nested containers)
// =========================================================================
static char test_gen_form_allows_nested_list(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_BeginList(gen, &type_tag));
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 60: PROP rejects nested container
// =========================================================================
static char test_gen_prop_rejects_container(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(!IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 61: CAT rejects PROP
// =========================================================================
static char test_gen_cat_rejects_prop(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	struct IFF_Tag prop_type;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&prop_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(!IFF_Generator_BeginProp(gen, &prop_type));
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 62: LIST allows all container types (FORM, LIST, CAT, PROP)
// =========================================================================
static char test_gen_list_allows_all_containers(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	struct IFF_Tag wildcard_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &type_tag)) goto cleanup;

	// FORM inside LIST
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// Nested LIST inside LIST
	TEST_ASSERT(IFF_Generator_BeginList(gen, &type_tag));
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	// CAT inside LIST
	TEST_ASSERT(IFF_Generator_BeginCat(gen, &wildcard_tag));
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	// PROP inside LIST
	TEST_ASSERT(IFF_Generator_BeginProp(gen, &type_tag));
	if (!IFF_Generator_EndProp(gen)) goto cleanup;

	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 63: CAT allows FORM, LIST, CAT (but not PROP — tested separately)
// =========================================================================
static char test_gen_cat_allows_form_list_cat(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag wildcard_tag;
	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &wildcard_tag)) goto cleanup;

	// FORM inside CAT
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// LIST inside CAT
	TEST_ASSERT(IFF_Generator_BeginList(gen, &type_tag));
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	// Nested CAT inside CAT
	TEST_ASSERT(IFF_Generator_BeginCat(gen, &wildcard_tag));
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 64: Root allows FORM, LIST, CAT. PROP at root fails.
// =========================================================================
static char test_gen_root_allows_form_list_cat(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	struct IFF_Tag wildcard_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	// FORM at root
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// LIST at root
	TEST_ASSERT(IFF_Generator_BeginList(gen, &type_tag));
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	// CAT at root
	TEST_ASSERT(IFF_Generator_BeginCat(gen, &wildcard_tag));
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	// PROP at root fails (PROP only valid inside LIST)
	TEST_ASSERT(!IFF_Generator_BeginProp(gen, &type_tag));

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 65: STRICT_CONTAINERS — matching types succeed
//
// WriteHeader sets STRICT. LIST(ILBM) > FORM(ILBM). Types match.
// =========================================================================
static char test_gen_strict_match(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &type_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &type_tag));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 66: STRICT_CONTAINERS — mismatching types fail
//
// WriteHeader sets STRICT. LIST(ILBM) > FORM(8SVX). Types mismatch.
// =========================================================================
static char test_gen_strict_mismatch(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag list_type;
	struct IFF_Tag form_type;

	IFF_Tag_Construct(&list_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&form_type, (const unsigned char *)"8SVX", 4, IFF_TAG_TYPE_TAG);

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &list_type)) goto cleanup;
	TEST_ASSERT(!IFF_Generator_BeginForm(gen, &form_type));
	if (!IFF_Generator_EndList(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

// =========================================================================
// Test 67: STRICT_CONTAINERS — wildcard parent allows any child
//
// WriteHeader sets STRICT. CAT("    ") > FORM(ILBM). Wildcard allows any.
// =========================================================================
static char test_gen_strict_wildcard(void)
{
	struct IFF_Generator_Factory *factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag wildcard_tag;
	struct IFF_Tag form_type;

	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&form_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!PRIVATE_CreateMemoryGenerator(&factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &wildcard_tag)) goto cleanup;
	TEST_ASSERT(IFF_Generator_BeginForm(gen, &form_type));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndCat(gen)) goto cleanup;

	result = 1;

cleanup:
	PRIVATE_Cleanup(gen, factory);
	return result;
}

void test_suite_generate_validation(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_create_to_data);
	RUN_TEST(test_gen_default_flags);
	RUN_TEST(test_gen_flush_empty);
	RUN_TEST(test_gen_flush_open_scope_fails);
	RUN_TEST(test_gen_chunk_at_root_fails);
	RUN_TEST(test_gen_form_allows_chunks);
	RUN_TEST(test_gen_list_rejects_chunks);
	RUN_TEST(test_gen_cat_rejects_chunks);
	RUN_TEST(test_gen_prop_allows_chunks);
	RUN_TEST(test_gen_form_allows_nested_form);
	RUN_TEST(test_gen_form_allows_nested_list);
	RUN_TEST(test_gen_prop_rejects_container);
	RUN_TEST(test_gen_cat_rejects_prop);
	RUN_TEST(test_gen_list_allows_all_containers);
	RUN_TEST(test_gen_cat_allows_form_list_cat);
	RUN_TEST(test_gen_root_allows_form_list_cat);
	RUN_TEST(test_gen_strict_match);
	RUN_TEST(test_gen_strict_mismatch);
	RUN_TEST(test_gen_strict_wildcard);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
