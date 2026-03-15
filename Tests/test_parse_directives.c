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
 * Test 81: ' END' with non-zero size fails (R53)
 *
 * ' IFF' [12] [flags={PROGRESSIVE}]
 * FORM ILBM
 *   BMHD [10] [data]
 *   ' END' [4] [4 bytes]    <-- non-zero size, parse fails
 *
 * The parser reads ' END', checks that size == 0, and fails.
 */
static char test_end_nonzero_size_fails(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char end_data[4] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;

	// Progressive mode: BeginContainer writes tag + type (no size).
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;

	// Write an ' END' with non-zero size (4 bytes of data).
	if (!IFF_TestBuilder_AddDirective(builder, " END", end_data, 4)) goto cleanup;

	// No EndContainer — we manually wrote the END.
	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(!IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Failed);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 82: Filler ('    ') skipped in IFF-2025 mode (R54)
 *
 * ' IFF' [12] [flags=0]
 * FORM ILBM
 *   '    ' [0]        <-- filler directive, skipped
 *   BMHD [10] [data]
 */
static char test_filler_skipped_iff2025(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, "    ", 0, 0)) goto cleanup;
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
 * Test 83: Unknown directive (' FOO') skipped in IFF-2025 mode (R55)
 *
 * ' IFF' [12] [flags=0]
 * FORM ILBM
 *   ' FOO' [0]        <-- unknown directive, silently consumed
 *   BMHD [10] [data]
 */
static char test_unknown_directive_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " FOO", 0, 0)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
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
 * Test 84: ' VER' directive skipped in IFF-2025 mode (R59)
 *
 * ' IFF' [12] [flags=0]
 * FORM ILBM
 *   ' VER' [0]        <-- version directive, read and skipped
 *   BMHD [10] [data]
 */
static char test_ver_directive_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " VER", 0, 0)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
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
 * Test 85: ' REV' directive skipped in IFF-2025 mode (R60)
 *
 * ' IFF' [12] [flags=0]
 * FORM ILBM
 *   ' REV' [0]        <-- revision directive, read and skipped
 *   BMHD [10] [data]
 */
static char test_rev_directive_skipped(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = IFF_HEADER_FLAGS_1985;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " REV", 0, 0)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
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

void test_suite_parse_directives(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_end_nonzero_size_fails);
	RUN_TEST(test_filler_skipped_iff2025);
	RUN_TEST(test_unknown_directive_skipped);
	RUN_TEST(test_ver_directive_skipped);
	RUN_TEST(test_rev_directive_skipped);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
