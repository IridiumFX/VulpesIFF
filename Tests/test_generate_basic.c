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
 * Test 4: Generator round-trip
 *
 * Use the generator in memory mode to produce an IFF-85 FORM,
 * then feed the output to the parser and verify it succeeds.
 */
static char test_generate_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Tag type_tag;
	struct IFF_Tag bmhd_tag;
	struct IFF_Tag body_tag;

	struct VPS_Data bmhd_wrap;
	struct VPS_Data body_wrap;

	// Construct tags manually to match the expected canonical form.
	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);

	// Wrap data buffers (non-owning).
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

	// Create generator in memory mode.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Generate an IFF-85 FORM.
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	// Get the output data.
	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

	// Feed the generated output to the parser.
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

void test_suite_generate_basic(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_generate_roundtrip);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
