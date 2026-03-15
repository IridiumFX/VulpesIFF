#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"
#include "IFF_TestDecoders.h"

/**
 * Helper: serialize an IFF directive payload with given flags.
 */
static void PRIVATE_SerializeIFFPayload
(
	unsigned char *out
	, const struct IFF_Header *header
)
{
	VPS_Endian_Write16UBE(out + 0, header->version);
	VPS_Endian_Write16UBE(out + 2, header->revision);
	VPS_Endian_Write64UBE(out + 4, header->flags.as_int);
}

/**
 * R64: midstream_iff_enables_sharding
 *
 * ' IFF' inside FORM enables SHARDING. Subsequent '    ' directives
 * dispatched to decoder as shards (not consumed as filler).
 *
 * Flow: IFF-2025 header (no sharding) → FORM(ILBM) → mid-stream ' IFF'
 * with SHARDING flag → BMHD chunk → shard → EndForm.
 * ShardCountingChunkDecoder tracks process_shard calls.
 * Expected: process_shard called 2 times (BMHD + shard).
 */
static char test_midstream_iff_enables_sharding(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct IFF_ChunkDecoder *chunk_dec = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char shard_data[4] = {1, 2, 3, 4};
	unsigned char iff_payload[12];

	struct IFF_Header header;
	struct IFF_Header midstream_header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	// Outer header: no sharding.
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	// Mid-stream header: enables sharding.
	midstream_header.version = IFF_Header_Version_2025;
	midstream_header.revision = 0;
	midstream_header.flags.as_int = 0;
	midstream_header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	PRIVATE_SerializeIFFPayload(iff_payload, &midstream_header);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;

	// Mid-stream ' IFF' directive enables SHARDING.
	if (!IFF_TestBuilder_AddDirective(builder, " IFF", iff_payload, 12)) goto cleanup;

	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreateFormDecoder(&form_dec)) goto cleanup;
	if (!IFF_TestDecoders_CreateShardCountingChunkDecoder(&chunk_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterFormDecoder(factory, &ilbm_tag, form_dec)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterChunkDecoder(factory, &chunk_key, chunk_dec)) goto cleanup;
	form_dec = 0;
	chunk_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	IFF_TestDecoders_ShardCallCount = 0;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(IFF_TestDecoders_ShardCallCount == 2);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_FormDecoder_Release(form_dec);
	IFF_ChunkDecoder_Release(chunk_dec);
	IFF_TestBuilder_Release(builder);
	return result;
}

void test_suite_parse_midstream_sharding(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_midstream_iff_enables_sharding);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
