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

/* ================================================================== */
/* Helper: register container-aware decoder for AAAA, inner for BBBB  */
/* and optionally CCCC.                                               */
/* ================================================================== */

static char setup_factory
(
	struct IFF_Parser_Factory **out_factory,
	struct IFF_FormDecoder **out_aaaa_dec,
	char register_cccc
)
{
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_FormDecoder *bbbb_dec = 0;
	struct IFF_FormDecoder *cccc_dec = 0;
	struct IFF_Parser_Factory *factory = 0;

	struct IFF_Tag aaaa_tag, bbbb_tag, cccc_tag;

	IFF_Tag_Construct(&aaaa_tag, (const unsigned char *)"AAAA", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bbbb_tag, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&cccc_tag, (const unsigned char *)"CCCC", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestDecoders_CreateContainerAwareFormDecoder(&aaaa_dec)) return 0;
	if (!IFF_TestDecoders_CreateInnerFormDecoder(&bbbb_dec))
	{
		IFF_FormDecoder_Release(aaaa_dec);
		return 0;
	}

	if (register_cccc)
	{
		if (!IFF_TestDecoders_CreateInnerFormDecoder(&cccc_dec))
		{
			IFF_FormDecoder_Release(aaaa_dec);
			IFF_FormDecoder_Release(bbbb_dec);
			return 0;
		}
	}

	if (!IFF_Parser_Factory_Allocate(&factory)) return 0;
	if (!IFF_Parser_Factory_Construct(factory)) return 0;

	IFF_Parser_Factory_RegisterFormDecoder(factory, &aaaa_tag, aaaa_dec);
	IFF_Parser_Factory_RegisterFormDecoder(factory, &bbbb_tag, bbbb_dec);
	if (cccc_dec)
		IFF_Parser_Factory_RegisterFormDecoder(factory, &cccc_tag, cccc_dec);

	*out_factory = factory;
	*out_aaaa_dec = aaaa_dec;
	return 1;
}

/* ================================================================== */
/* R109: cat_entity_delivery                                          */
/* FORM AAAA { DATA [4], CAT BBBB { FORM BBBB { DATA [4] } x3 } }   */
/* All 3 entities from FORM BBBBs delivered to AAAA's decoder.        */
/* ================================================================== */

static char test_cat_entity_delivery(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = { 0x01, 0x02, 0x03, 0x04 };

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	for (int i = 0; i < 3; i++)
	{
		if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
		if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
		if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	}
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 0)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->chunk_count == 1);
	TEST_ASSERT(fs->nested_form_count == 3);
	TEST_ASSERT(fs->container_depth == 0);

	// Event log: ENTER(BBBB), ENTITY x3, LEAVE(BBBB)
	TEST_ASSERT(fs->event_count == 5);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[0].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[1].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[2].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[4].type == CONTAINER_EVENT_LEAVE);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R110: two_cats_group_boundaries                                    */
/* FORM AAAA { CAT BBBB { FORM BBBB x2 }, CAT CCCC { FORM CCCC x1 } */
/* Two groups distinguishable via enter/leave events.                 */
/* ================================================================== */

static char test_two_cats_group_boundaries(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;

	// CAT BBBB with 2 FORMs
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	for (int i = 0; i < 2; i++)
	{
		if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
		if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
		if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	}
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// CAT CCCC with 1 FORM
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "CCCC")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "CCCC")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 1)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->nested_form_count == 3);
	TEST_ASSERT(fs->container_depth == 0);

	// Event log: ENTER(BBBB), ENTITY, ENTITY, LEAVE(BBBB),
	//            ENTER(CCCC), ENTITY, LEAVE(CCCC)
	TEST_ASSERT(fs->event_count == 7);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[0].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[1].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[2].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_LEAVE);
	TEST_ASSERT(strcmp(fs->events[3].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[4].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[4].tag, "CCCC") == 0);
	TEST_ASSERT(fs->events[5].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[6].type == CONTAINER_EVENT_LEAVE);
	TEST_ASSERT(strcmp(fs->events[6].tag, "CCCC") == 0);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R111: consecutive_same_type_cats                                    */
/* FORM AAAA { CAT BBBB { FORM BBBB }, CAT BBBB { FORM BBBB } }     */
/* Two consecutive CATs of same type are distinguishable.             */
/* ================================================================== */

static char test_consecutive_same_type_cats(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;

	// First CAT BBBB
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Second CAT BBBB
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 0)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->nested_form_count == 2);

	// Two distinct ENTER/LEAVE pairs
	TEST_ASSERT(fs->event_count == 6);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(fs->events[1].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[2].type == CONTAINER_EVENT_LEAVE);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(fs->events[4].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[5].type == CONTAINER_EVENT_LEAVE);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R112: list_cat_nested_delivery                                     */
/* FORM AAAA { LIST XXXX { CAT BBBB { FORM BBBB x2 } } }            */
/* Entities bubble through LIST and CAT to reach AAAA.                */
/* ================================================================== */

static char test_list_cat_nested_delivery(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "XXXX")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	for (int i = 0; i < 2; i++)
	{
		if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
		if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
		if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	}
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 0)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->nested_form_count == 2);
	TEST_ASSERT(fs->container_depth == 0);

	// Event log: ENTER(LIST XXXX), ENTER(CAT BBBB), ENTITY, ENTITY,
	//            LEAVE(CAT BBBB), LEAVE(LIST XXXX)
	TEST_ASSERT(fs->event_count == 6);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[0].tag, "XXXX") == 0);
	TEST_ASSERT(fs->events[0].depth == 1);
	TEST_ASSERT(fs->events[1].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[1].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[1].depth == 2);
	TEST_ASSERT(fs->events[2].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[2].depth == 2);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[4].type == CONTAINER_EVENT_LEAVE);
	TEST_ASSERT(fs->events[5].type == CONTAINER_EVENT_LEAVE);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R113: root_cat_entity_delivery                                     */
/* CAT BBBB { FORM BBBB { DATA [4] } x2 }  (root level, no parent)  */
/* Entities go to session->final_entity. No crash.                    */
/* ================================================================== */

static char test_root_cat_entity_delivery(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *bbbb_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;
	unsigned char data[4] = {0};

	struct IFF_Tag bbbb_tag;
	IFF_Tag_Construct(&bbbb_tag, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	for (int i = 0; i < 2; i++)
	{
		if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
		if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
		if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	}
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreateFormDecoder(&bbbb_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	IFF_Parser_Factory_RegisterFormDecoder(factory, &bbbb_tag, bbbb_dec);
	bbbb_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	// Last entity wins at root level.
	TEST_ASSERT(parser->session->final_entity != 0);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_FormDecoder_Release(bbbb_dec);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R114: root_list_cat_entity_delivery                                */
/* LIST XXXX { CAT BBBB { FORM BBBB { DATA } } }  (root level)       */
/* Multi-level at root. Entity goes to session->final_entity.         */
/* ================================================================== */

static char test_root_list_cat_entity_delivery(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *bbbb_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;
	unsigned char data[4] = {0};

	struct IFF_Tag bbbb_tag;
	IFF_Tag_Construct(&bbbb_tag, (const unsigned char *)"BBBB", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "XXXX")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_TestDecoders_CreateFormDecoder(&bbbb_dec)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	IFF_Parser_Factory_RegisterFormDecoder(factory, &bbbb_tag, bbbb_dec);
	bbbb_dec = 0;

	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->final_entity != 0);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_FormDecoder_Release(bbbb_dec);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R115: direct_nested_form_regression                                */
/* FORM AAAA { FORM BBBB { DATA } }  (no CAT/LIST)                   */
/* Direct nesting still works after the fix.                          */
/* ================================================================== */

static char test_direct_nested_form_regression(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 0)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->nested_form_count == 1);
	// No container events — direct FORM-in-FORM.
	TEST_ASSERT(fs->event_count == 1);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTITY);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/* ================================================================== */
/* R116: list_entity_delivery                                         */
/* FORM AAAA { LIST BBBB { FORM BBBB x2 } }                          */
/* Entities from FORMs inside a LIST bubble to AAAA.                  */
/* ================================================================== */

static char test_list_entity_delivery(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_FormDecoder *aaaa_dec = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	struct ContainerAwareFormState *fs = 0;
	char result = 0;
	unsigned char data[4] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "AAAA")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "BBBB")) goto cleanup;
	for (int i = 0; i < 2; i++)
	{
		if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "BBBB")) goto cleanup;
		if (!IFF_TestBuilder_AddChunk(builder, "DATA", data, 4)) goto cleanup;
		if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	}
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!setup_factory(&factory, &aaaa_dec, 0)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->final_entity != 0);

	fs = (struct ContainerAwareFormState *)parser->session->final_entity;
	TEST_ASSERT(fs->nested_form_count == 2);

	// Event log: ENTER(LIST BBBB), ENTITY, ENTITY, LEAVE(LIST BBBB)
	TEST_ASSERT(fs->event_count == 4);
	TEST_ASSERT(fs->events[0].type == CONTAINER_EVENT_ENTER);
	TEST_ASSERT(strcmp(fs->events[0].tag, "BBBB") == 0);
	TEST_ASSERT(fs->events[1].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[2].type == CONTAINER_EVENT_ENTITY);
	TEST_ASSERT(fs->events[3].type == CONTAINER_EVENT_LEAVE);

	result = 1;

cleanup:
	if (parser && parser->session && parser->session->final_entity)
	{
		free(parser->session->final_entity);
		parser->session->final_entity = 0;
	}
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

void test_suite_parse_container_delivery(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_cat_entity_delivery);
	RUN_TEST(test_two_cats_group_boundaries);
	RUN_TEST(test_consecutive_same_type_cats);
	RUN_TEST(test_list_cat_nested_delivery);
	RUN_TEST(test_root_cat_entity_delivery);
	RUN_TEST(test_root_list_cat_entity_delivery);
	RUN_TEST(test_direct_nested_form_regression);
	RUN_TEST(test_list_entity_delivery);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
