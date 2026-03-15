#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"
#include "test_harness/IFF_TestBuilder.h"
#include "test_harness/IFF_TestEncoders.h"

/**
 * Test 24: EncodeForm drives FormEncoder callbacks
 *
 * Verify EncodeForm produces a valid IFF-85 FORM via the FormEncoder
 * lifecycle and the parser can consume the output.
 *
 * FORM [body] ILBM
 *   BMHD [10] [10 zero bytes]
 *   BODY [4]  [4 zero bytes]
 */
static char test_encode_form_lifecycle(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *form_enc = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;

	struct TestSourceEntity entity;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	// Set up source entity with 2 chunks.
	entity.chunk_count = 2;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_data;
	entity.chunks[0].size = 10;
	entity.chunks[1].tag = "BODY";
	entity.chunks[1].data = body_data;
	entity.chunks[1].size = 4;

	// Create factory, register FormEncoder, create generator.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;

	if (!IFF_TestEncoders_CreateFormEncoder(&form_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, form_enc)) goto cleanup;

	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Drive encoder.
	if (!IFF_Generator_EncodeForm(gen, &ilbm_tag, &entity)) goto cleanup;
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
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);

	return result;
}

/**
 * Test 25: ChunkEncoder transforms data before writing
 *
 * The doubler encoder turns 3 bytes {0xAA, 0xBB, 0xCC} into
 * 6 bytes {0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC}.
 * Compare generator output against TestBuilder reference.
 *
 * FORM [body] ILBM
 *   BMHD [6] [0xAA 0xAA 0xBB 0xBB 0xCC 0xCC]
 *   BODY [4] [4 zero bytes]
 */
static char test_encode_chunk_encoder_transform(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *form_enc = 0;
	struct IFF_ChunkEncoder *chunk_enc = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	unsigned char bmhd_src[3] = {0xAA, 0xBB, 0xCC};
	unsigned char bmhd_doubled[6] = {0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC};
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;

	struct TestSourceEntity entity;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);

	// Source entity: BMHD with 3 bytes (pre-transform), BODY with 4 zeros.
	entity.chunk_count = 2;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_src;
	entity.chunks[0].size = 3;
	entity.chunks[1].tag = "BODY";
	entity.chunks[1].data = body_data;
	entity.chunks[1].size = 4;

	// Build reference with TestBuilder using post-transform data.
	if (!IFF_TestBuilder_Allocate(&builder)) goto cleanup;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_doubled, 6)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Create factory, register FormEncoder + DoublerChunkEncoder.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;

	if (!IFF_TestEncoders_CreateFormEncoder(&form_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, form_enc)) goto cleanup;

	if (!IFF_TestEncoders_CreateDoublerChunkEncoder(&chunk_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterChunkEncoder(gen_factory, &bmhd_tag, chunk_enc)) goto cleanup;

	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Drive encoder.
	if (!IFF_Generator_EncodeForm(gen, &ilbm_tag, &entity)) goto cleanup;
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
 * Test 26: EncodeForm works in progressive mode
 *
 * Verify EncodeForm emits END directives in progressive mode and the
 * parser can consume the output.
 *
 * ' IFF' [12] [ver=40, rev=0, flags={operating=PROGRESSIVE}]
 * FORM ILBM
 *   BMHD [10] [10 zero bytes]
 * ' END' [0]
 */
static char test_encode_progressive_form(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *form_enc = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;

	struct TestSourceEntity entity;

	// Progressive mode header.
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	// Source entity with 1 chunk.
	entity.chunk_count = 1;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_data;
	entity.chunks[0].size = 10;

	// Create factory, register FormEncoder, create generator.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;

	if (!IFF_TestEncoders_CreateFormEncoder(&form_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, form_enc)) goto cleanup;

	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Write header + encode form.
	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_EncodeForm(gen, &ilbm_tag, &entity)) goto cleanup;
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

void test_suite_generate_encoders(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_encode_form_lifecycle);
	RUN_TEST(test_encode_chunk_encoder_transform);
	RUN_TEST(test_encode_progressive_form);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
