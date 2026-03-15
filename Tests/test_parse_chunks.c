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

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * Test 75: Chunk with even size (R46)
 *
 * FORM ILBM { BMHD [10] [data] }
 * Even size — no padding byte required.
 */
static char test_chunk_even_size(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[10] = {1,2,3,4,5,6,7,8,9,10};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 76: Chunk with odd size, padded (R47)
 *
 * FORM ILBM { TEST [5] [data] [0x00 pad] }
 * Parser reads 1 pad byte after odd-size chunk.
 */
static char test_chunk_odd_size_padded(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "TEST", data, 5)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 77: Chunk with zero size (R48)
 *
 * FORM ILBM { EMTY [0] }
 * No payload bytes after the size field.
 */
static char test_chunk_zero_size(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "EMTY", 0, 0)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 78: Chunk with odd size, NO_PADDING flag (R49)
 *
 * ' IFF' [12] [flags={NO_PADDING}]
 * FORM ILBM { TEST [5] [data] BMHD [4] [data] }
 * No pad byte between the two chunks.
 */
static char test_chunk_odd_no_padding_flag(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data5[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	unsigned char data4[4] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "TEST", data5, 5)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", data4, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 79: Chunk with large payload (R50)
 *
 * FORM ILBM { DATA [1024] [1024 bytes] }
 */
static char test_chunk_large_payload(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[1024];
	VPS_TYPE_SIZE i;

	for (i = 0; i < 1024; i++)
	{
		data[i] = (unsigned char)(i & 0xFF);
	}

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 1024)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 80: Chunk with unknown tag skipped (R51)
 *
 * FORM ILBM { ZZZZ [4] [data]  BMHD [10] [data] }
 * Parser has no decoder for ZZZZ. It reads and skips it.
 * Parse succeeds.
 */
static char test_chunk_unknown_tag_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char unknown_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	unsigned char bmhd_data[10] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "ZZZZ", unknown_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

void test_suite_parse_chunks(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_chunk_even_size);
	RUN_TEST(test_chunk_odd_size_padded);
	RUN_TEST(test_chunk_zero_size);
	RUN_TEST(test_chunk_odd_no_padding_flag);
	RUN_TEST(test_chunk_large_payload);
	RUN_TEST(test_chunk_unknown_tag_skipped);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
