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
 * Test 18: Mid-stream ' IFF' narrows sizing from 32-bit to 16-bit
 *
 * Binary layout (IFF-2025, via TestBuilder):
 *   ' IFF' [12] [ver=40, rev=0, flags={sizing=32, blobbed}]
 *   LIST [total_size_32bit] ILBM
 *     FORM [form1_size_32bit] ILBM
 *       BMHD [10_32bit] [10 zero bytes]
 *     ' IFF' [12] [ver=40, rev=0, flags={sizing=16}]  <-- narrows
 *     FORM [form2_size_16bit] ILBM
 *       BODY [4_16bit] [4 zero bytes]
 *
 * After the mid-stream ' IFF', the parser updates the current scope flags
 * to use 16-bit sizing. The second FORM and its chunks use 16-bit sizes.
 *
 * The scope guard (Guard 1: size widening) does NOT fire because 16-bit
 * is narrower than the parent's 32-bit.
 *
 * Expected: Scan succeeds, Complete, iff85_locked == 0
 */
static char test_midstream_iff_narrows_size(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	// Initial header: 32-bit sizing (default), blobbed (default).
	struct IFF_Header header_32;
	header_32.version = IFF_Header_Version_2025;
	header_32.revision = 0;
	header_32.flags.as_int = 0; // All defaults = 32-bit, blobbed, 4-byte tags

	// Mid-stream header: narrows to 16-bit sizing.
	struct IFF_Header header_16;
	header_16.version = IFF_Header_Version_2025;
	header_16.revision = 0;
	header_16.flags.as_int = 0;
	header_16.flags.as_fields.sizing = IFF_Header_Sizing_16;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	// 1. Write initial header (sets builder to 32-bit sizes).
	if (!IFF_TestBuilder_AddHeader(builder, &header_32)) goto cleanup;

	// 2. Begin LIST with 32-bit sizes.
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	// 3. First FORM with 32-bit sizes.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// 4. Mid-stream ' IFF' directive (written with current 32-bit size format).
	//    AddHeader updates builder to 16-bit sizes automatically.
	if (!IFF_TestBuilder_AddHeader(builder, &header_16)) goto cleanup;

	// 5. Second FORM with 16-bit sizes (builder is now in 16-bit mode).
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// 6. End LIST — must use original 32-bit size for the patch.
	//    Temporarily restore size_length for correct patching.
	builder->size_length = 4;
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
 * Test 19: Mid-stream ' IFF' rejects progressive-in-blobbed (scope guard 2)
 *
 * Binary layout (IFF-2025, via TestBuilder):
 *   ' IFF' [12] [ver=40, rev=0, flags={operating=BLOBBED}]
 *   LIST [total_size] ILBM
 *     FORM [form_size] ILBM
 *       ' IFF' [12] [ver=40, rev=0, flags={operating=PROGRESSIVE}]  <-- rejected
 *       BMHD [10] [10 zero bytes]   <-- won't be reached
 *
 * The ' IFF' directive inside the FORM triggers ExecuteDirective's scope
 * guard 2. At this depth the scope_stack is [LIST, root]:
 *   head = LIST scope, head->next = root scope.
 * The root scope has operating=BLOBBED, new flags request PROGRESSIVE.
 * Guard fires → ExecuteDirective returns 0 → parse fails.
 *
 * Expected: Scan returns 0, session_state == Failed
 */
static char test_midstream_iff_rejects_progressive_in_blobbed(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	// Outer header: blobbed (default), 32-bit.
	struct IFF_Header header_blobbed;
	header_blobbed.version = IFF_Header_Version_2025;
	header_blobbed.revision = 0;
	header_blobbed.flags.as_int = 0; // BLOBBED is default (0)

	// Illegal mid-stream: requests progressive.
	struct IFF_Header header_progressive;
	header_progressive.version = IFF_Header_Version_2025;
	header_progressive.revision = 0;
	header_progressive.flags.as_int = 0;
	header_progressive.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_blobbed)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;

	// Write the illegal mid-stream ' IFF' directive manually.
	// We use AddHeader which serializes the IFF directive payload.
	// But AddHeader will also set builder to progressive mode, which
	// we don't want. So we use AddDirective with manual payload instead.
	{
		unsigned char iff_payload[12];
		VPS_Endian_Write16UBE(iff_payload, header_progressive.version);
		VPS_Endian_Write16UBE(iff_payload + 2, header_progressive.revision);
		VPS_Endian_Write64UBE(iff_payload + 4, header_progressive.flags.as_int);
		if (!IFF_TestBuilder_AddDirective(builder, " IFF", iff_payload, 12)) goto cleanup;
	}

	// Add chunk data so the FORM has content after the directive
	// (though it won't be reached due to parse failure).
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	// Scan should fail due to scope guard rejection.
	TEST_ASSERT(!IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Failed);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);

	return result;
}

void test_suite_parse_flags(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_midstream_iff_narrows_size);
	RUN_TEST(test_midstream_iff_rejects_progressive_in_blobbed);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
