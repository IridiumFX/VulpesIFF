#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_ChunkEncoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestEncoders.h"

/**
 * W67: form_encoder_empty
 *
 * EmptyFormEncoder produces 0 chunks (produce_chunk immediately sets done=1).
 * Empty FORM emitted. Parse succeeds.
 */
static char test_form_encoder_empty(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormEncoder *enc = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	struct IFF_Tag ilbm_tag;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_TestEncoders_CreateEmptyFormEncoder(&enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, enc)) goto cleanup;
	enc = 0;

	TEST_ASSERT(IFF_Generator_EncodeForm(gen, &ilbm_tag, 0));
	TEST_ASSERT(IFF_Generator_Flush(gen));

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

	// Parse: empty FORM should succeed.
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
	IFF_FormEncoder_Release(enc);
	return result;
}

/**
 * W68: form_encoder_begin_fails
 *
 * FailBeginFormEncoder's begin_encode returns 0. EncodeForm returns 0.
 */
static char test_form_encoder_begin_fails(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *enc = 0;
	char result = 0;

	struct IFF_Tag ilbm_tag;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_TestEncoders_CreateFailBeginFormEncoder(&enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, enc)) goto cleanup;
	enc = 0;

	// EncodeForm should fail because begin_encode returns 0.
	TEST_ASSERT(!IFF_Generator_EncodeForm(gen, &ilbm_tag, 0));

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_FormEncoder_Release(enc);
	return result;
}

/**
 * W69: form_encoder_produce_chunk_fails
 *
 * FailSecondChunkFormEncoder: first chunk succeeds, second fails.
 * EncodeForm returns 0.
 */
static char test_form_encoder_produce_chunk_fails(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *enc = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;

	struct TestSourceEntity entity;
	entity.chunk_count = 2;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_data;
	entity.chunks[0].size = 10;
	entity.chunks[1].tag = "BODY";
	entity.chunks[1].data = body_data;
	entity.chunks[1].size = 4;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_TestEncoders_CreateFailSecondChunkFormEncoder(&enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, enc)) goto cleanup;
	enc = 0;

	// EncodeForm: first chunk OK, second fails.
	TEST_ASSERT(!IFF_Generator_EncodeForm(gen, &ilbm_tag, &entity));

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_FormEncoder_Release(enc);
	return result;
}

/**
 * W70: form_encoder_unregistered
 *
 * EncodeForm called with form type "ANIM" — not registered. Returns 0.
 */
static char test_form_encoder_unregistered(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Tag anim_tag;

	IFF_Tag_Construct(&anim_tag, (const unsigned char *)"ANIM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// No encoder registered for ANIM. Should fail.
	TEST_ASSERT(!IFF_Generator_EncodeForm(gen, &anim_tag, 0));

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * W72: chunk_encoder_selective
 *
 * ChunkEncoder registered for BMHD only (doubles bytes).
 * FormEncoder produces BMHD(3 bytes) + BODY(4 bytes).
 * BMHD should be transformed (doubled to 6 bytes).
 * BODY should pass through untransformed (4 bytes).
 */
static char test_chunk_encoder_selective(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormEncoder *form_enc = 0;
	struct IFF_ChunkEncoder *chunk_enc = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[3] = {0x11, 0x22, 0x33};
	unsigned char body_data[4] = {0xAA, 0xBB, 0xCC, 0xDD};

	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;

	struct TestSourceEntity entity;
	entity.chunk_count = 2;
	entity.chunks[0].tag = "BMHD";
	entity.chunks[0].data = bmhd_data;
	entity.chunks[0].size = 3;
	entity.chunks[1].tag = "BODY";
	entity.chunks[1].data = body_data;
	entity.chunks[1].size = 4;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_TestEncoders_CreateFormEncoder(&form_enc)) goto cleanup;
	if (!IFF_TestEncoders_CreateDoublerChunkEncoder(&chunk_enc)) goto cleanup;

	if (!IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &ilbm_tag, form_enc)) goto cleanup;
	if (!IFF_Generator_Factory_RegisterChunkEncoder(gen_factory, &bmhd_tag, chunk_enc)) goto cleanup;
	form_enc = 0;
	chunk_enc = 0;

	TEST_ASSERT(IFF_Generator_EncodeForm(gen, &ilbm_tag, &entity));
	TEST_ASSERT(IFF_Generator_Flush(gen));

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);

	// Verify sizes:
	// FORM(4) + size(4) + ILBM(4) = 12 header
	// BMHD(4) + size(4) + doubled_data(6) = 14
	// BODY(4) + size(4) + data(4) = 12
	// Total = 12 + 14 + 12 = 38
	TEST_ASSERT(output->limit == 38);

	// Parse roundtrip.
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
	IFF_FormEncoder_Release(form_enc);
	IFF_ChunkEncoder_Release(chunk_enc);
	return result;
}

void test_suite_generate_encoders_advanced(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_form_encoder_empty);
	RUN_TEST(test_form_encoder_begin_fails);
	RUN_TEST(test_form_encoder_produce_chunk_fails);
	RUN_TEST(test_form_encoder_unregistered);
	RUN_TEST(test_chunk_encoder_selective);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
