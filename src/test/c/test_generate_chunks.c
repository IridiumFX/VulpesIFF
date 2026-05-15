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
 * Test 86: WriteChunk basic (W39)
 *
 * Generator FORM with a 10-byte chunk. Roundtrip to parser.
 */
static char test_gen_chunk_basic(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[10] = {1,2,3,4,5,6,7,8,9,10};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 10);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output->limit > 0);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 87: WriteChunk empty (W40)
 *
 * Generator FORM with a zero-byte chunk (limit=0 VPS_Data).
 * Output: tag + size(0), no payload.
 */
static char test_gen_chunk_empty(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"EMTY", 4, IFF_TAG_TYPE_TAG);

	memset(&wrap, 0, sizeof(wrap));
	wrap.limit = 0;
	wrap.own_bytes = 0;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output->limit > 0);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 88: WriteChunk odd size with padding (W41)
 *
 * Generator FORM with a 5-byte chunk. Padding byte should be emitted.
 * Roundtrip to parser.
 */
static char test_gen_chunk_odd_padding(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"TEST", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 5);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	// FORM(4) + size(4) + type(4) + chunk_tag(4) + chunk_size(4) + data(5) + pad(1) = 26
	TEST_ASSERT(output->limit == 26);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 89: WriteChunk odd size with NO_PADDING (W42)
 *
 * WriteHeader(NO_PADDING). Generator FORM with 5-byte chunk.
 * No padding byte. Roundtrip to parser.
 */
static char test_gen_chunk_odd_no_padding(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	struct IFF_Header header;
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"TEST", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 5);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 90: WriteChunk binary layout matches TestBuilder (W44)
 *
 * Generator and TestBuilder produce identical bytes for FORM ILBM { BMHD [10] }.
 */
static char test_gen_chunk_binary_layout(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char data[10] = {1,2,3,4,5,6,7,8,9,10};
	struct IFF_Tag type_tag;
	struct IFF_Tag chunk_tag;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&chunk_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_WrapData(data, 10);

	// Build reference.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &chunk_tag, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
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

void test_suite_generate_chunks(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_chunk_basic);
	RUN_TEST(test_gen_chunk_empty);
	RUN_TEST(test_gen_chunk_odd_padding);
	RUN_TEST(test_gen_chunk_odd_no_padding);
	RUN_TEST(test_gen_chunk_binary_layout);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
