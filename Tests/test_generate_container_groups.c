#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_DataWriter.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Chunk_Key.h>
#include <IFF/IFF_ContextualData.h>
#include <IFF/IFF_FormDecoder.h>
#include <IFF/IFF_FormEncoder.h>
#include <IFF/IFF_ChunkDecoder.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_State.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestDecoders.h"

/* ================================================================== */
/* Test encoder: FORM AAAA with one chunk, then CAT BBBB x2 + CCCC   */
/* ================================================================== */

struct GroupEncoderState
{
	int chunk_index;
	int group_index;
	int entity_index;
	unsigned char data[4];
};

static char group_begin_encode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	struct GroupEncoderState *s = calloc(1, sizeof(*s));
	if (!s) return 0;
	s->data[0] = 0xAA; s->data[1] = 0xBB; s->data[2] = 0xCC; s->data[3] = 0xDD;
	*custom_state = s;
	return 1;
}

static char group_produce_chunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	struct GroupEncoderState *s = custom_state;

	if (s->chunk_index >= 1)
	{
		*out_done = 1;
		return 1;
	}

	IFF_Tag_Construct(out_tag, (const unsigned char *)"DATA", 4, IFF_TAG_TYPE_TAG);
	VPS_Data_Allocate(out_data, 4, 4);
	memcpy((*out_data)->bytes, s->data, 4);
	s->chunk_index++;
	*out_done = 0;
	return 1;
}

// Two groups: CAT BBBB (2 entities), CAT CCCC (1 entity)
static char group_begin_container_group
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_container_variant
	, struct IFF_Tag *out_container_type
	, char *out_done
)
{
	struct GroupEncoderState *s = custom_state;

	if (s->group_index >= 2)
	{
		*out_done = 1;
		return 1;
	}

	*out_container_variant = IFF_TAG_SYSTEM_CAT;

	if (s->group_index == 0)
		IFF_Tag_Construct(out_container_type, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);
	else
		IFF_Tag_Construct(out_container_type, (const unsigned char *)"CCCC", 4, IFF_TAG_TYPE_TAG);

	s->entity_index = 0;
	s->group_index++;
	*out_done = 0;
	return 1;
}

static char group_produce_grouped_form
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_form_type
	, void **out_entity
	, char *out_done
)
{
	struct GroupEncoderState *s = custom_state;

	int limit = (s->group_index == 1) ? 2 : 1; // First group: 2, second: 1

	if (s->entity_index >= limit)
	{
		*out_done = 1;
		return 1;
	}

	if (s->group_index == 1)
		IFF_Tag_Construct(out_form_type, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);
	else
		IFF_Tag_Construct(out_form_type, (const unsigned char *)"CCCC", 4, IFF_TAG_TYPE_TAG);

	// The inner forms need a source entity for their encoder.
	// We'll use a dummy entity (the encoder will just produce one chunk).
	*out_entity = s;
	s->entity_index++;
	*out_done = 0;
	return 1;
}

static char group_produce_nested_form
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_form_type
	, void **out_entity
	, char *out_done
)
{
	*out_done = 1;
	return 1;
}

static char group_end_encode
(
	struct IFF_Generator_State *state
	, void *custom_state
)
{
	free(custom_state);
	return 1;
}

/* Inner FORM encoder — produces one DATA chunk */

struct InnerEncoderState
{
	unsigned char data[4];
	char chunk_produced;
};

static char inner_begin_encode
(
	struct IFF_Generator_State *state
	, void *source_entity
	, void **custom_state
)
{
	struct InnerEncoderState *s = calloc(1, sizeof(*s));
	if (!s) return 0;
	s->data[0] = 0xAA; s->data[1] = 0xBB; s->data[2] = 0xCC; s->data[3] = 0xDD;
	*custom_state = s;
	return 1;
}

static char inner_produce_chunk
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_tag
	, struct VPS_Data **out_data
	, char *out_done
)
{
	struct InnerEncoderState *s = custom_state;

	if (s->chunk_produced)
	{
		*out_done = 1;
		return 1;
	}

	IFF_Tag_Construct(out_tag, (const unsigned char *)"DATA", 4, IFF_TAG_TYPE_TAG);
	VPS_Data_Allocate(out_data, 4, 4);
	memcpy((*out_data)->bytes, s->data, 4);
	s->chunk_produced = 1;
	*out_done = 0;
	return 1;
}

static char inner_produce_nested_form
(
	struct IFF_Generator_State *state
	, void *custom_state
	, struct IFF_Tag *out_form_type
	, void **out_entity
	, char *out_done
)
{
	*out_done = 1;
	return 1;
}

static char inner_end_encode
(
	struct IFF_Generator_State *state
	, void *custom_state
)
{
	free(custom_state);
	return 1;
}

/* ================================================================== */
/* W103: roundtrip_container_groups                                   */
/* Generate FORM AAAA with CAT BBBB (2 forms) + CAT CCCC (1 form).   */
/* Parse back and verify structure via ContainerAwareFormDecoder.      */
/* ================================================================== */

static char test_roundtrip_container_groups(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_FormEncoder *aaaa_enc = 0;
	struct IFF_FormEncoder *bbbb_enc = 0;
	struct IFF_FormEncoder *cccc_enc = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;

	struct IFF_Tag aaaa_tag, bbbb_tag, cccc_tag;
	IFF_Tag_Construct(&aaaa_tag, (const unsigned char *)"AAAA", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bbbb_tag, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&cccc_tag, (const unsigned char *)"CCCC", 4, IFF_TAG_TYPE_TAG);

	/* Build generator with encoders */
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;

	/* AAAA encoder with container groups */
	if (!IFF_FormEncoder_Allocate(&aaaa_enc)) goto cleanup;
	IFF_FormEncoder_Construct(aaaa_enc,
		group_begin_encode, group_produce_chunk,
		group_produce_nested_form, group_end_encode);
	aaaa_enc->begin_container_group = group_begin_container_group;
	aaaa_enc->produce_grouped_form = group_produce_grouped_form;

	IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &aaaa_tag, aaaa_enc);
	aaaa_enc = 0;

	/* BBBB inner encoder */
	if (!IFF_FormEncoder_Allocate(&bbbb_enc)) goto cleanup;
	IFF_FormEncoder_Construct(bbbb_enc,
		inner_begin_encode, inner_produce_chunk,
		inner_produce_nested_form, inner_end_encode);
	IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &bbbb_tag, bbbb_enc);
	bbbb_enc = 0;

	/* CCCC inner encoder (same as BBBB) */
	if (!IFF_FormEncoder_Allocate(&cccc_enc)) goto cleanup;
	IFF_FormEncoder_Construct(cccc_enc,
		inner_begin_encode, inner_produce_chunk,
		inner_produce_nested_form, inner_end_encode);
	IFF_Generator_Factory_RegisterFormEncoder(gen_factory, &cccc_tag, cccc_enc);
	cccc_enc = 0;

	/* Generate */
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_EncodeForm(gen, &aaaa_tag, 0)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	/* Parse back */
	{
		struct IFF_FormDecoder *aaaa_dec = 0;
		struct IFF_FormDecoder *bbbb_dec = 0;
		struct IFF_FormDecoder *cccc_dec = 0;

		if (!IFF_TestDecoders_CreateContainerAwareFormDecoder(&aaaa_dec)) goto cleanup;
		if (!IFF_TestDecoders_CreateInnerFormDecoder(&bbbb_dec))
		{
			IFF_FormDecoder_Release(aaaa_dec);
			goto cleanup;
		}
		if (!IFF_TestDecoders_CreateInnerFormDecoder(&cccc_dec))
		{
			IFF_FormDecoder_Release(aaaa_dec);
			IFF_FormDecoder_Release(bbbb_dec);
			goto cleanup;
		}

		if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
		if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;

		IFF_Parser_Factory_RegisterFormDecoder(parse_factory, &aaaa_tag, aaaa_dec);
		IFF_Parser_Factory_RegisterFormDecoder(parse_factory, &bbbb_tag, bbbb_dec);
		IFF_Parser_Factory_RegisterFormDecoder(parse_factory, &cccc_tag, cccc_dec);

		if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;
	}

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;

	/* Verify: 1 chunk (DATA), 3 nested forms total */
	TEST_ASSERT(fs->chunk_count == 1);
	TEST_ASSERT(fs->nested_form_count == 3);

	/* Verify event sequence: ENTER BBBB, entity, entity, LEAVE BBBB,
	   ENTER CCCC, entity, LEAVE CCCC */
	TEST_ASSERT(fs->event_count == 7);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[0].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_LEAVE);
	TEST_ASSERT(fs->events[4].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[4].tag, "CCCC") == 0);
	TEST_ASSERT(fs->events[6].type == CONTAINER_EVENT_LEAVE);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_FormEncoder_Release(aaaa_enc);
	IFF_FormEncoder_Release(bbbb_enc);
	IFF_FormEncoder_Release(cccc_enc);
	return result;
}

void test_suite_generate_container_groups(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_roundtrip_container_groups);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
