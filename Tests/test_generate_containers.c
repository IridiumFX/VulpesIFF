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
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"

/**
 * Test 9: Generator round-trip — LIST with PROP + FORM
 *
 * Generate: LIST ILBM { PROP ILBM { BMHD, CMAP }, FORM ILBM { BODY } }
 * Feed output to parser and verify success.
 */
static char test_generate_list_with_prop_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char cmap_data[6] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag cmap_tag;
	struct IFF_Tag body_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data cmap_wrap;
	struct VPS_Data body_wrap;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&cmap_tag, (const unsigned char *)"CMAP", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	memset(&cmap_wrap, 0, sizeof(cmap_wrap));
	cmap_wrap.bytes = cmap_data;
	cmap_wrap.size = 6;
	cmap_wrap.limit = 6;
	cmap_wrap.own_bytes = 0;

	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;
	body_wrap.own_bytes = 0;

	// Create generator in memory mode.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Generate: LIST ILBM { PROP ILBM { BMHD, CMAP }, FORM ILBM { BODY } }
	if (!IFF_Generator_BeginList(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_BeginProp(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &cmap_tag, &cmap_wrap)) goto cleanup;
	if (!IFF_Generator_EndProp(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
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
 * Test 10: Generator round-trip — CAT with two differently-typed FORMs
 *
 * Generate: CAT "    " { FORM ILBM { BMHD }, FORM 8SVX { VHDR } }
 */
static char test_generate_cat_with_forms_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char vhdr_data[8] = {0};

	struct IFF_Tag wildcard_tag;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag svx_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag vhdr_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data vhdr_wrap;

	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&svx_tag, (const unsigned char *)"8SVX", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&vhdr_tag, (const unsigned char *)"VHDR", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	memset(&vhdr_wrap, 0, sizeof(vhdr_wrap));
	vhdr_wrap.bytes = vhdr_data;
	vhdr_wrap.size = 8;
	vhdr_wrap.limit = 8;
	vhdr_wrap.own_bytes = 0;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginCat(gen, &wildcard_tag)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &svx_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &vhdr_tag, &vhdr_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndCat(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

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
 * Test 11: Generator round-trip — nested LIST > LIST > FORM
 *
 * Generate: LIST "    " { LIST ILBM { FORM ILBM { BMHD, BODY } } }
 * 3-level deep blobbed accumulation.
 */
static char test_generate_nested_list_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag wildcard_tag;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag body_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data body_wrap;

	IFF_Tag_Construct(&wildcard_tag, (const unsigned char *)"    ", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;
	body_wrap.own_bytes = 0;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginList(gen, &wildcard_tag)) goto cleanup;
	if (!IFF_Generator_BeginList(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_EndList(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

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

void test_suite_generate_containers(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_generate_list_with_prop_roundtrip);
	RUN_TEST(test_generate_cat_with_forms_roundtrip);
	RUN_TEST(test_generate_nested_list_roundtrip);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
