#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf; d.size = size; d.limit = size;
	return d;
}

/**
 * Generic: generate FORM with header flags, verify output matches TestBuilder
 * and parse roundtrip succeeds.
 */
static char PRIVATE_GenFlagTest
(
	struct IFF_Header *header
	, unsigned char *chunk_data
	, VPS_TYPE_SIZE chunk_size
)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *output = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(chunk_data, chunk_size);

	// Generator output.
	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);

	// TestBuilder reference.
	if (!IFF_TestBuilder_Allocate(&builder)) goto cleanup;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;
	if (!IFF_TestBuilder_AddHeader(builder, header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", chunk_data, chunk_size)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Compare.
	TEST_ASSERT(output->limit == expected->limit);
	TEST_ASSERT(memcmp(output->bytes, expected->bytes, output->limit) == 0);

	// Parse roundtrip.
	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	IFF_TestBuilder_Release(builder);
	return result;
}

/** W77: gen_tag_sizing_8 */
static char test_gen_tag_sizing_8(void)
{
	unsigned char data[10] = {0};
	struct IFF_Header h;
	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;
	h.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;
	return PRIVATE_GenFlagTest(&h, data, 10);
}

/** W78: gen_tag_sizing_16 */
static char test_gen_tag_sizing_16(void)
{
	unsigned char data[10] = {0};
	struct IFF_Header h;
	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;
	h.flags.as_fields.tag_sizing = IFF_Header_TagSizing_16;
	return PRIVATE_GenFlagTest(&h, data, 10);
}

/** W80: gen_le_unsigned_combined */
static char test_gen_le_unsigned_combined(void)
{
	unsigned char data[10] = {0};
	struct IFF_Header h;
	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;
	h.flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN
		| IFF_Header_Flag_Typing_UNSIGNED_SIZES;
	return PRIVATE_GenFlagTest(&h, data, 10);
}

/** W82: gen_sharding_enabled — WriteShard succeeds with SHARDING flag */
static char test_gen_sharding_enabled(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char chunk_data[10] = {0};
	unsigned char shard_data[6] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data chunk_wrap, shard_wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	chunk_wrap = PRIVATE_Wrap(chunk_data, 10);
	shard_wrap = PRIVATE_Wrap(shard_data, 6);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &chunk_wrap)) goto cleanup;
	TEST_ASSERT(IFF_Generator_WriteShard(gen, &shard_wrap));
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

/** W83: gen_64bit_8tag_progressive */
static char test_gen_64bit_8tag_progressive(void)
{
	unsigned char data[10] = {0};
	struct IFF_Header h;
	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;
	h.flags.as_fields.sizing = IFF_Header_Sizing_64;
	h.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;
	h.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;
	return PRIVATE_GenFlagTest(&h, data, 10);
}

/** W84: gen_16bit_le_no_padding */
static char test_gen_16bit_le_no_padding(void)
{
	unsigned char data[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
	struct IFF_Header h;
	h.version = IFF_Header_Version_2025;
	h.revision = 0;
	h.flags.as_int = 0;
	h.flags.as_fields.sizing = IFF_Header_Sizing_16;
	h.flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN;
	h.flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;
	return PRIVATE_GenFlagTest(&h, data, 5);
}

/** W85: gen_full_featured — all flags active */
static char test_gen_full_featured(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char chunk_data[10] = {0};
	unsigned char shard_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data chunk_wrap, shard_wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.sizing = IFF_Header_Sizing_64;
	header.flags.as_fields.tag_sizing = IFF_Header_TagSizing_16;
	header.flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN
		| IFF_Header_Flag_Typing_UNSIGNED_SIZES;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	chunk_wrap = PRIVATE_Wrap(chunk_data, 10);
	shard_wrap = PRIVATE_Wrap(shard_data, 4);

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &chunk_wrap)) goto cleanup;
	if (!IFF_Generator_WriteShard(gen, &shard_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	return result;
}

void test_suite_generate_flags_advanced(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_tag_sizing_8);
	RUN_TEST(test_gen_tag_sizing_16);
	RUN_TEST(test_gen_le_unsigned_combined);
	RUN_TEST(test_gen_sharding_enabled);
	RUN_TEST(test_gen_64bit_8tag_progressive);
	RUN_TEST(test_gen_16bit_le_no_padding);
	RUN_TEST(test_gen_full_featured);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
