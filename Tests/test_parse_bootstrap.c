#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * Test 27: IFF-85 LIST locks session
 *
 * Binary layout:
 *   LIST [size] ILBM
 *     FORM [size] ILBM
 *       BMHD [10] [data]
 *
 * Expected: iff85_locked == 1, Complete
 */
static char test_iff85_list_locks_session(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 28: IFF-85 CAT locks session
 *
 * Binary layout:
 *   CAT  [size] "    "
 *     FORM [size] ILBM
 *       BMHD [10] [data]
 *
 * Expected: iff85_locked == 1, Complete
 */
static char test_iff85_cat_locks_session(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "    ")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 29: IFF-85 rejects non-filler directives
 *
 * Binary layout:
 *   FORM [size] ILBM
 *     ' VER' [0]
 *     BMHD [10] [data]
 *
 * The ' VER' directive inside the FORM triggers the iff85_locked guard,
 * which rejects all directives except filler ('    '). Parse fails.
 *
 * Expected: Scan fails, session_state == Failed
 */
static char test_iff85_rejects_directive(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " VER", 0, 0)) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

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
 * Test 30: IFF-85 allows filler directive ('    ')
 *
 * Binary layout:
 *   FORM [size] ILBM
 *     '    ' [0]        <-- filler directive (all spaces)
 *     BMHD [10] [data]
 *
 * The filler directive is the only directive permitted in IFF-85 mode.
 * The parser reads and skips it via the generic directive handler.
 *
 * Expected: Scan succeeds, Complete
 */
static char test_iff85_allows_filler(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

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
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 31: IFF-85 default flags
 *
 * Parse a minimal IFF-85 FORM using the default TestBuilder settings
 * (4-byte tags, 32-bit BE sizes, padding enabled). The fact that the
 * parser succeeds proves the IFF-85 defaults are correctly applied.
 *
 * Expected: iff85_locked == 1, Complete
 */
static char test_iff85_default_flags(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	// Use a 5-byte (odd) chunk to verify padding is applied.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "TEST", data, 5)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 32: IFF-2025 header with default flags
 *
 * Binary layout:
 *   ' IFF' [12] [ver=40, rev=0, flags=0]
 *   FORM [size] ILBM
 *     ' VER' [0]
 *     BMHD [10] [data]
 *
 * The ' IFF' header sets iff85_locked == 0, so the ' VER' directive
 * inside the FORM is accepted (unlike IFF-85 mode).
 *
 * Expected: iff85_locked == 0, Complete
 */
static char test_iff2025_header_default_flags(void)
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
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 33: IFF-85 empty FORM succeeds
 *
 * Binary layout:
 *   FORM [4] ILBM
 *     (no chunks)
 *
 * A FORM with only its type tag and no chunks is valid per the spec.
 *
 * Expected: iff85_locked == 1, Complete
 */
static char test_iff85_empty_form_succeeds(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

/**
 * Test 34: IFF-85 nested LIST containing FORM
 *
 * Binary layout:
 *   LIST [size] "    "
 *     FORM [size] ILBM
 *       BMHD [10] [data]
 *     FORM [size] 8SVX
 *       VHDR [8] [data]
 *
 * Multi-container IFF-85 stream without headers. The LIST uses a wildcard
 * type ("    ") and contains two differently-typed FORMs.
 *
 * Expected: iff85_locked == 1, Complete
 */
static char test_iff85_nested_list_with_forms(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char vhdr_data[8] = {0};

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "    ")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr_data, 8)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 1);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

void test_suite_parse_bootstrap(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_iff85_list_locks_session);
	RUN_TEST(test_iff85_cat_locks_session);
	RUN_TEST(test_iff85_rejects_directive);
	RUN_TEST(test_iff85_allows_filler);
	RUN_TEST(test_iff85_default_flags);
	RUN_TEST(test_iff2025_header_default_flags);
	RUN_TEST(test_iff85_empty_form_succeeds);
	RUN_TEST(test_iff85_nested_list_with_forms);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
