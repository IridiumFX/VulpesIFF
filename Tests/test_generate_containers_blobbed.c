#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

// =========================================================================
// Helpers
// =========================================================================

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

/**
 * Test 118: Empty blobbed FORM (W13)
 *
 * BeginForm + EndForm with no chunks.
 * Output: FORM(4) + size(4, value=4) + type(4) = 12 bytes.
 */
static char test_gen_form_empty_blobbed(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	// Build reference.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	TEST_ASSERT(actual->limit == expected->limit);
	TEST_ASSERT(actual->limit == 12);
	TEST_ASSERT(memcmp(actual->bytes, expected->bytes, actual->limit) == 0);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 119: Nested blobbed accumulation (W17)
 *
 * CAT > LIST > FORM with chunk. Generator byte-identical to TestBuilder.
 */
static char test_gen_nested_blobbed_accumulation(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {1,2,3,4,5,6,7,8,9,10};

	struct IFF_Tag wildcard_tag;
	struct IFF_Tag list_type_tag;
	struct IFF_Tag form_type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&list_type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&form_type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(bmhd_data, 10);

	// Build reference.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "    ")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &wildcard_tag)) goto cleanup;
	if (!IFF_Generator_BeginList(gen, &list_type_tag)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &form_type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_EndCat(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	TEST_ASSERT(actual->limit == expected->limit);
	TEST_ASSERT(memcmp(actual->bytes, expected->bytes, actual->limit) == 0);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 120: Blobbed size patching verification (W18)
 *
 * FORM with two chunks. Verify FORM size field matches content total.
 * FORM size = type(4) + chunk1(tag+size+data) + chunk2(tag+size+data)
 *           = 4 + (4+4+10) + (4+4+4) = 34
 */
static char test_gen_blobbed_size_patching(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data bmhd_wrap;
	struct VPS_Data body_wrap;

	VPS_TYPE_32U form_size;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	bmhd_wrap = PRIVATE_WrapData(bmhd_data, 10);
	body_wrap = PRIVATE_WrapData(body_data, 4);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	// Read FORM size field at offset 4 (after FORM tag).
	form_size = VPS_Endian_Read32UBE(output->bytes + 4);

	// Expected: type(4) + BMHD(4+4+10) + BODY(4+4+4) = 34
	TEST_ASSERT(form_size == 34);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 121: PROP in blobbed mode (W19)
 *
 * LIST with PROP (2 property chunks) then FORM.
 * Generator output matches TestBuilder. Parse roundtrip succeeds.
 */
static char test_gen_prop_blobbed(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char cmap_data[6] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag list_type;
	struct IFF_Tag prop_type;
	struct IFF_Tag form_type;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag cmap_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data bmhd_wrap;
	struct VPS_Data cmap_wrap;
	struct VPS_Data body_wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	IFF_Tag_Construct(&list_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&prop_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&form_type, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&cmap_tag, (const unsigned char *)"CMAP", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	bmhd_wrap = PRIVATE_WrapData(bmhd_data, 10);
	cmap_wrap = PRIVATE_WrapData(cmap_data, 6);
	body_wrap = PRIVATE_WrapData(body_data, 4);

	// Build reference.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "CMAP", cmap_data, 6)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginList(gen, &list_type)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &prop_type)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &cmap_tag, &cmap_wrap)) goto cleanup;
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &form_type)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	TEST_ASSERT(actual->limit == expected->limit);
	TEST_ASSERT(memcmp(actual->bytes, expected->bytes, actual->limit) == 0);

	// Parse roundtrip.
	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, actual, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

void test_suite_generate_containers_blobbed(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_form_empty_blobbed);
	RUN_TEST(test_gen_nested_blobbed_accumulation);
	RUN_TEST(test_gen_blobbed_size_patching);
	RUN_TEST(test_gen_prop_blobbed);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
