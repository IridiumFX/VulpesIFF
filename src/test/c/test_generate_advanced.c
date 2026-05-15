#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * Test 21: Generator progressive mode round-trip
 *
 * Generate an IFF-2025 progressive FORM, verify the parser can consume it.
 *
 * ' IFF' [12] [ver=40, rev=0, flags={operating=PROGRESSIVE}]
 * FORM ILBM          (no size — progressive mode)
 *   BMHD [10] [10 zero bytes]
 *   BODY [4]  [4 zero bytes]
 * ' END' [0]
 */
static char test_generate_progressive_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag body_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data body_wrap;

	// Build header: IFF-2025 progressive mode.
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;
	body_wrap.own_bytes = 0;

	// Create generator in memory mode.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Generate progressive FORM.
	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

	// Feed to parser.
	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);

	return result;
}

/**
 * Test 22: Generator binary layout verification
 *
 * Compare generator output byte-for-byte against TestBuilder output
 * for an IFF-85 FORM.
 *
 * FORM [34] ILBM
 *   BMHD [10] [10 zero bytes]
 *   BODY [4]  [4 zero bytes]
 */
static char test_generate_binary_layout(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag body_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data body_wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;
	body_wrap.own_bytes = 0;

	// Build reference with TestBuilder.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual with Generator.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	// Compare byte-for-byte.
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
 * Test 23: Generator filler and odd-size chunk padding
 *
 * Verify WriteFiller emits filler directive AND odd-size chunks get
 * padding bytes. Compare generator output against TestBuilder reference.
 *
 * ' IFF' [12] [ver=40, rev=0, flags=0]
 * FORM [body] ILBM
 *   BMHD [5] [0x01..0x05] [0x00 pad]
 *   '    ' [8] [8 zero bytes]
 */
static char test_generate_filler_and_padding(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char bmhd_data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	unsigned char filler_data[8] = {0};

	struct IFF_Header header;
	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;

	struct VPS_Data bmhd_wrap;

	// IFF-2025 header with default flags (blobbed mode).
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 5;
	bmhd_wrap.limit = 5;
	bmhd_wrap.own_bytes = 0;

	// Build reference with TestBuilder.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 5)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", filler_data, 8)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual with Generator.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteFiller(gen, 8)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	// Compare byte-for-byte.
	TEST_ASSERT(actual->limit == expected->limit);
	TEST_ASSERT(memcmp(actual->bytes, expected->bytes, actual->limit) == 0);

	result = 1;

cleanup:

	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

void test_suite_generate_advanced(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_generate_progressive_roundtrip);
	RUN_TEST(test_generate_binary_layout);
	RUN_TEST(test_generate_filler_and_padding);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
