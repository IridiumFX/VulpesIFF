#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Parser_State.h>

#include "Test.h"
#include "IFF_TestBuilder.h"
#include "IFF_TestDecoders.h"

#define IFF_HEADER_FLAGS_SHARDING 0

static void PRIVATE_Cleanup
(
	struct IFF_Parser *parser
	, struct IFF_Parser_Factory *factory
	, struct IFF_TestBuilder *builder
	, struct IFF_FormDecoder *form_dec
	, struct IFF_ChunkDecoder *chunk_dec
)
{
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
}

/**
 * R79: shard_single
 *
 * SHARDING enabled. FORM(ILBM) with BMHD(10) + one shard(4).
 * ShardCountingChunkDecoder's process_shard called twice
 * (once for chunk data, once for shard data).
 */
static char test_shard_single(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct IFF_ChunkDecoder *chunk_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char shard_data[4] = {1, 2, 3, 4};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
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

	// process_shard called twice: once for BMHD chunk, once for shard.
	TEST_ASSERT(IFF_TestDecoders_ShardCallCount == 2);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec, chunk_dec);
	return result;
}

/**
 * R80: shard_multiple
 *
 * SHARDING enabled. BMHD chunk + three shards.
 * process_shard called 4 times total.
 */
static char test_shard_multiple(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct IFF_ChunkDecoder *chunk_dec = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char shard1[4] = {1, 2, 3, 4};
	unsigned char shard2[6] = {5, 6, 7, 8, 9, 10};
	unsigned char shard3[2] = {11, 12};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard1, 4)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard2, 6)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard3, 2)) goto cleanup;
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
	TEST_ASSERT(IFF_TestDecoders_ShardCallCount == 4);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec, chunk_dec);
	return result;
}

/**
 * R81: shard_flush_on_next_chunk
 *
 * SHARDING enabled. BMHD(10) + shard(4) + BODY(6).
 * BODY arrival flushes the pending BMHD decoder (end_decode called).
 * FormDecoder sees chunk_count == 2 (BMHD sequence + BODY).
 */
static char test_shard_flush_on_next_chunk(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct IFF_ChunkDecoder *chunk_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char shard_data[4] = {1, 2, 3, 4};
	unsigned char body_data[6] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 6)) goto cleanup;
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
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	// BMHD sequence (chunk + shard) produces 1 decoded result,
	// BODY has no decoder so raw wrap produces 1 result.
	TEST_ASSERT(fs->chunk_count == 2);
	TEST_ASSERT(IFF_TestDecoders_ShardCallCount == 2);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec, chunk_dec);
	return result;
}

/**
 * R82: shard_flush_on_scope_exit
 *
 * SHARDING enabled. BMHD(10) + shard(4). EndForm triggers flush.
 */
static char test_shard_flush_on_scope_exit(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct IFF_ChunkDecoder *chunk_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char shard_data[4] = {1, 2, 3, 4};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
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
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->chunk_count == 1);
	TEST_ASSERT(IFF_TestDecoders_ShardCallCount == 2);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec, chunk_dec);
	return result;
}

/**
 * R83: shard_flush_on_nested_container
 *
 * SHARDING enabled. LIST > FORM(ILBM) { BMHD + shard }.
 * Scope exit of FORM triggers flush. Parse succeeds.
 */
static char test_shard_flush_on_nested_container(void)
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
	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
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
	PRIVATE_Cleanup(parser, factory, builder, form_dec, chunk_dec);
	return result;
}

/**
 * R84: shard_no_pending_decoder
 *
 * SHARDING enabled. '    ' shard with no preceding chunk (no decoder).
 * Silently consumed. Parse succeeds.
 */
static char test_shard_no_pending_decoder(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char shard_data[4] = {1, 2, 3, 4};
	unsigned char body_data[4] = {0};

	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_SHARDING;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	// Shard BEFORE any chunk — no decoder pending.
	if (!IFF_TestBuilder_AddDirective(builder, "    ", shard_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
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
 * R85: shard_disabled_acts_as_filler
 *
 * SHARDING NOT enabled. '    ' directive inside FORM treated as filler.
 * No decoder interaction. Parse succeeds.
 */
static char test_shard_disabled_acts_as_filler(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char filler_data[8] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0; // No SHARDING flag.

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", filler_data, 8)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
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

void test_suite_parse_sharding(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_shard_single);
	RUN_TEST(test_shard_multiple);
	RUN_TEST(test_shard_flush_on_next_chunk);
	RUN_TEST(test_shard_flush_on_scope_exit);
	RUN_TEST(test_shard_flush_on_nested_container);
	RUN_TEST(test_shard_no_pending_decoder);
	RUN_TEST(test_shard_disabled_acts_as_filler);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
