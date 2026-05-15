#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>

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

/**
 * Test 15: FormDecoder lifecycle — begin, process_chunk x3, end
 *
 * Binary layout (IFF-85, blobbed):
 *   FORM [42] ILBM
 *     BMHD [10] [10 zero bytes]
 *     BODY [4]  [4 zero bytes]
 *     CMAP [6]  [6 zero bytes]
 *
 * Setup: Register TestFormDecoder for ILBM, TestChunkDecoder for (ILBM, BMHD).
 *
 * Expected: Scan succeeds, Complete, final_entity != 0,
 *           chunk_count == 3, has_bmhd == 1
 */
static char test_decode_form_lifecycle(void)
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
	unsigned char body_data[4] = {0};
	unsigned char cmap_data[6] = {0};

	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "CMAP", cmap_data, 6)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	// Create decoders.
	if (!IFF_TestDecoders_CreateFormDecoder(&form_dec)) goto cleanup;
	if (!IFF_TestDecoders_CreateChunkDecoder(&chunk_dec)) goto cleanup;

	// Create factory and register decoders.
	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterFormDecoder(factory, &ilbm_tag, form_dec)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterChunkDecoder(factory, &chunk_key, chunk_dec)) goto cleanup;

	// Decoders are now owned by the factory dictionaries — don't double-release.
	form_dec = 0;
	chunk_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->chunk_count == 3);
	TEST_ASSERT(fs->has_bmhd == 1);

	result = 1;

cleanup:

	// Free the final entity (TestFormState) if it was produced.
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

/**
 * Test 16: ChunkDecoder lifecycle verification
 *
 * Same image as test 15. The TestChunkDecoder wraps the BMHD raw data
 * as ContextualData. TestFormDecoder's process_chunk detects has_bmhd
 * by checking that BMHD's contextual_data is non-null.
 *
 * This is effectively verified by test 15's has_bmhd == 1 assertion,
 * but this test uses a FORM with ONLY a BMHD chunk to isolate the
 * chunk decoder behavior.
 *
 * Binary layout (IFF-85):
 *   FORM [22] ILBM
 *     BMHD [10] [10 zero bytes]
 *
 * Expected: chunk_count == 1, has_bmhd == 1
 */
static char test_decode_chunk_decoder_lifecycle(void)
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

	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Chunk_Key chunk_key;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Chunk_Key_Construct(&chunk_key, &ilbm_tag, &bmhd_tag);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreateFormDecoder(&form_dec)) goto cleanup;
	if (!IFF_TestDecoders_CreateChunkDecoder(&chunk_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterFormDecoder(factory, &ilbm_tag, form_dec)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterChunkDecoder(factory, &chunk_key, chunk_dec)) goto cleanup;
	form_dec = 0;
	chunk_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->chunk_count == 1);
	TEST_ASSERT(fs->has_bmhd == 1);

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

/**
 * Test 17: PROP pulling via FindProp from within a FormDecoder
 *
 * Binary layout (IFF-85, blobbed):
 *   LIST [~] ILBM
 *     PROP [~] ILBM
 *       BMHD [10] [10 bytes, filled with 0x01]
 *     FORM [~] ILBM
 *       BODY [4]  [4 zero bytes]
 *
 * Setup: Register PropAwareFormDecoder for ILBM.
 *        Its begin_decode calls FindProp(BMHD) and sets prop_found=1.
 *
 * Expected: Scan succeeds, Complete, prop_found == 1
 */
static char test_decode_prop_pulling(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10];
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;

	memset(bmhd_data, 0x01, 10);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreatePropAwareFormDecoder(&form_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterFormDecoder(factory, &ilbm_tag, form_dec)) goto cleanup;
	form_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->prop_found == 1);
	TEST_ASSERT(fs->chunk_count == 1);

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
	IFF_TestBuilder_Release(builder);

	return result;
}

void test_suite_parse_decoders(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_decode_form_lifecycle);
	RUN_TEST(test_decode_chunk_decoder_lifecycle);
	RUN_TEST(test_decode_prop_pulling);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
