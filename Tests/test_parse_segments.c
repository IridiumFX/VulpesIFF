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

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * Test 12: ' DEF' directive is silently consumed
 *
 * Binary layout:
 *   ' IFF' [12] [ver=40, rev=0, flags=IFF_HEADER_FLAGS_1985]
 *   ' DEF' [12] [num_options(4BE)=1, id_size(4BE)=4, id_data="seg1"]
 *   FORM [22] ILBM
 *     BMHD [10] [10 zero bytes]
 *
 * The parser reads ' DEF' via generic directive handling and skips it.
 *
 * Expected: Scan succeeds, Complete, iff85_locked == 0
 */
static char test_parse_def_directive_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	// DEF payload: num_options(4 BE)=1, id_size(4 BE)=4, id_data="seg1"
	unsigned char def_payload[12];
	def_payload[0] = 0; def_payload[1] = 0; def_payload[2] = 0; def_payload[3] = 1;
	def_payload[4] = 0; def_payload[5] = 0; def_payload[6] = 0; def_payload[7] = 4;
	memcpy(def_payload + 8, "seg1", 4);

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " DEF", def_payload, 12)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 13: Multiple consecutive top-level FORMs
 *
 * Binary layout:
 *   ' IFF' [12] [ver=40, rev=0, flags=IFF_HEADER_FLAGS_1985]
 *   FORM [22] ILBM
 *     BMHD [10] [10 zero bytes]
 *   FORM [20] 8SVX
 *     VHDR [8]  [8 zero bytes]
 *
 * The root scope boundary is unbounded (limit=0), so the segment-level
 * parse loop processes both FORMs before hitting EOF -> Complete.
 *
 * Expected: Scan succeeds, Complete, iff85_locked == 0
 */
static char test_parse_multiple_top_level_forms(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char vhdr_data[8] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr_data, 8)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 14: Optional ' REF' directive skipped without resolver
 *
 * Binary layout:
 *   ' IFF' [12] [ver=40, rev=0, flags=IFF_HEADER_FLAGS_1985]
 *   ' REF' [8]  [num_options(4BE)=1, id_size(4BE)=0]
 *   FORM [22] ILBM
 *     BMHD [10] [10 zero bytes]
 *
 * With no segment_resolver registered, HandleSegmentRef consumes
 * the directive chunk and returns 1 (silent skip). Parsing continues
 * to the FORM.
 *
 * Expected: Scan succeeds, Complete, iff85_locked == 0
 */
static char test_parse_optional_ref_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	// REF payload: num_options(4 BE)=1, id_size(4 BE)=0 (optional marker)
	unsigned char ref_payload[8];
	ref_payload[0] = 0; ref_payload[1] = 0; ref_payload[2] = 0; ref_payload[3] = 1;
	ref_payload[4] = 0; ref_payload[5] = 0; ref_payload[6] = 0; ref_payload[7] = 0;

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " REF", ref_payload, 8)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

void test_suite_parse_segments(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_parse_def_directive_skipped);
	RUN_TEST(test_parse_multiple_top_level_forms);
	RUN_TEST(test_parse_optional_ref_skipped);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
