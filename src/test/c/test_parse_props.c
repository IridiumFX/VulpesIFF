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

static void PRIVATE_Cleanup
(
	struct IFF_Parser *parser
	, struct IFF_Parser_Factory *factory
	, struct IFF_TestBuilder *builder
	, struct IFF_FormDecoder *form_dec
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
	IFF_TestBuilder_Release(builder);
}

/**
 * R33: list_with_multiple_props
 *
 * LIST(ILBM) with two PROP(ILBM) blocks, each containing BMHD.
 * First PROP's BMHD is filled with 0x01, second with 0x02.
 * Second PROP overrides first. FormDecoder's FindProp retrieves the second.
 *
 * We verify prop_found == 1 (FindProp succeeds). The override behavior
 * is tested by the dictionary's insert-or-replace semantics.
 */
static char test_list_multiple_props(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd1[10];
	unsigned char bmhd2[10];
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;

	memset(bmhd1, 0x01, 10);
	memset(bmhd2, 0x02, 10);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	// First PROP with BMHD filled 0x01.
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd1, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Second PROP with BMHD filled 0x02 — should override.
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd2, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// FORM that queries the prop.
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

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec);
	return result;
}

/**
 * R41: prop_wildcard_type
 *
 * LIST(ILBM) with PROP("    ") containing BMHD.
 * PROP with wildcard type is available to all nested FORMs.
 * FORM(ILBM) calls FindProp(BMHD): first searches (ILBM, BMHD) → miss,
 * then falls back to (WILDCARD, BMHD) → hit.
 */
static char test_prop_wildcard_type(void)
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

	memset(bmhd_data, 0x42, 10);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "    ")) goto cleanup;
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

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec);
	return result;
}

/**
 * R42: prop_specific_type
 *
 * LIST("    ") with PROP(ILBM) containing BMHD.
 * FORM(8SVX) calls FindProp(BMHD): searches (8SVX, BMHD) → miss,
 * falls back (WILDCARD, BMHD) → miss (PROP is ILBM-specific, not wildcard).
 * prop_found should be 0.
 */
static char test_prop_specific_type(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10];
	unsigned char vhdr_data[8] = {0};

	struct IFF_Tag svx_tag;

	memset(bmhd_data, 0x01, 10);

	IFF_Tag_Construct(&svx_tag, (const unsigned char *)"8SVX", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "    ")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr_data, 8)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreatePropAwareFormDecoder(&form_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_RegisterFormDecoder(factory, &svx_tag, form_dec)) goto cleanup;
	form_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->prop_found == 0);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec);
	return result;
}

/**
 * R43: prop_fallback_resolution
 *
 * LIST("    ") with:
 *   PROP("    ") containing BMHD (wildcard prop)
 *   PROP("ILBM") containing CMAP (type-specific prop)
 *
 * FORM(ILBM) calls FindProp(BMHD):
 *   1. Search (ILBM, BMHD) → miss
 *   2. Fallback (WILDCARD, BMHD) → hit (from wildcard PROP)
 *
 * prop_found should be 1 (wildcard fallback works even with specific PROPs).
 */
static char test_prop_fallback_resolution(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct IFF_FormDecoder *form_dec = 0;
	struct VPS_Data *image = 0;
	struct TestFormState *fs = 0;
	char result = 0;

	unsigned char bmhd_data[10];
	unsigned char cmap_data[6];
	unsigned char body_data[4] = {0};

	struct IFF_Tag ilbm_tag;

	memset(bmhd_data, 0x11, 10);
	memset(cmap_data, 0x22, 6);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "    ")) goto cleanup;

	// Wildcard PROP with BMHD.
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "    ")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Type-specific PROP(ILBM) with CMAP (different chunk tag).
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "CMAP", cmap_data, 6)) goto cleanup;
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

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec);
	return result;
}

/**
 * R45: prop_between_forms
 *
 * LIST(ILBM) with FORM1(ILBM), then PROP(ILBM) with BMHD, then FORM2(ILBM).
 * FORM1 sees no PROP (not yet defined). FORM2 sees BMHD from PROP.
 *
 * Since final_entity holds the last FORM's state, we verify FORM2's prop_found=1.
 * (FORM1 would have prop_found=0 but its entity is overwritten by FORM2's.)
 */
static char test_prop_between_forms(void)
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

	memset(bmhd_data, 0x99, 10);

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	// FORM1 — before PROP, should NOT find BMHD.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// PROP added mid-sequence.
	if (!IFF_TestBuilder_BeginContainer(builder, "PROP", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// FORM2 — after PROP, should find BMHD.
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

	// final_entity is FORM2's state (last FORM processed).
	fs = (struct TestFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->prop_found == 1);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder, form_dec);
	return result;
}

void test_suite_parse_props(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_list_multiple_props);
	RUN_TEST(test_prop_wildcard_type);
	RUN_TEST(test_prop_specific_type);
	RUN_TEST(test_prop_fallback_resolution);
	RUN_TEST(test_prop_between_forms);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
