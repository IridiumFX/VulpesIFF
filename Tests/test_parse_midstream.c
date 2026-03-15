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

// =========================================================================
// Helpers
// =========================================================================

static void PRIVATE_SerializeIFFPayload
(
	unsigned char *out
	, const struct IFF_Header *header
)
{
	VPS_Endian_Write16UBE(out, header->version);
	VPS_Endian_Write16UBE(out + 2, header->revision);
	VPS_Endian_Write64UBE(out + 4, header->flags.as_int);
}

/**
 * Test 99: Mid-stream ' IFF' narrows tag_sizing 8 to 4 (R62)
 *
 * ' IFF' [12] [flags={tag_sizing=8}]
 * LIST ILBM
 *   FORM ILBM { BMHD [10] }   (8-byte tags)
 *   ' IFF' [12] [flags={tag_sizing=4}]
 *   FORM ILBM { BODY [4] }    (4-byte tags)
 */
static char test_midstream_narrows_tags(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header_8;
	header_8.version = IFF_Header_Version_2025;
	header_8.revision = 0;
	header_8.flags.as_int = 0;
	header_8.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;

	struct IFF_Header header_4;
	header_4.version = IFF_Header_Version_2025;
	header_4.revision = 0;
	header_4.flags.as_int = 0;
	header_4.flags.as_fields.tag_sizing = IFF_Header_TagSizing_4;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_8)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Mid-stream: narrow to 4-byte tags.
	if (!IFF_TestBuilder_AddHeader(builder, &header_4)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Restore 8-byte tags for LIST EndContainer.
	builder->tag_length = 8;
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
 * Test 100: Mid-stream ' IFF' enables NO_PADDING (R63)
 *
 * ' IFF' [12] [flags=0]  (default: padding enabled)
 * LIST ILBM
 *   FORM ILBM { TEST [5] [data] [pad] }   (padded)
 *   ' IFF' [12] [flags={NO_PADDING}]
 *   FORM ILBM { BODY [3] [data] }          (no pad)
 */
static char test_midstream_enables_no_padding(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data5[5] = {1, 2, 3, 4, 5};
	unsigned char data3[3] = {6, 7, 8};

	struct IFF_Header header_default;
	header_default.version = IFF_Header_Version_2025;
	header_default.revision = 0;
	header_default.flags.as_int = 0;

	struct IFF_Header header_nopad;
	header_nopad.version = IFF_Header_Version_2025;
	header_nopad.revision = 0;
	header_nopad.flags.as_int = 0;
	header_nopad.flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_default)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	// First FORM with padded odd chunk.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "TEST", data5, 5)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Mid-stream: enable NO_PADDING.
	if (!IFF_TestBuilder_AddHeader(builder, &header_nopad)) goto cleanup;

	// Second FORM with unpadded odd chunk.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", data3, 3)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Restore padding for LIST EndContainer.
	builder->no_padding = 0;
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
 * Test 101: Guard fires — sizing widening 16 to 32 (R65)
 *
 * ' IFF' [12] [flags={sizing=16}]
 * LIST ILBM
 *   FORM ILBM
 *     ' IFF' [12] [flags={sizing=32}]   <-- guard fires (widening)
 *     BMHD [10] [data]
 */
static char test_guard_sizing_widening(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header_16;
	header_16.version = IFF_Header_Version_2025;
	header_16.revision = 0;
	header_16.flags.as_int = 0;
	header_16.flags.as_fields.sizing = IFF_Header_Sizing_16;

	struct IFF_Header header_32;
	header_32.version = IFF_Header_Version_2025;
	header_32.revision = 0;
	header_32.flags.as_int = 0;
	header_32.flags.as_fields.sizing = IFF_Header_Sizing_32;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_16)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;

	// Write illegal mid-stream ' IFF' via AddDirective (don't change builder state).
	{
		unsigned char iff_payload[12];
		PRIVATE_SerializeIFFPayload(iff_payload, &header_32);
		if (!IFF_TestBuilder_AddDirective(builder, " IFF", iff_payload, 12)) goto cleanup;
	}

	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
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
 * Test 102: Guard fires — tag widening 4 to 8 (R66)
 *
 * ' IFF' [12] [flags={tag_sizing=4}]
 * LIST ILBM
 *   FORM ILBM
 *     ' IFF' [12] [flags={tag_sizing=8}]   <-- guard fires (widening)
 *     BMHD [10] [data]
 */
static char test_guard_tag_widening(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header_default;
	header_default.version = IFF_Header_Version_2025;
	header_default.revision = 0;
	header_default.flags.as_int = 0; // tag_sizing=4 (default)

	struct IFF_Header header_tag8;
	header_tag8.version = IFF_Header_Version_2025;
	header_tag8.revision = 0;
	header_tag8.flags.as_int = 0;
	header_tag8.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_default)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;

	// Write illegal mid-stream ' IFF' via AddDirective.
	{
		unsigned char iff_payload[12];
		PRIVATE_SerializeIFFPayload(iff_payload, &header_tag8);
		if (!IFF_TestBuilder_AddDirective(builder, " IFF", iff_payload, 12)) goto cleanup;
	}

	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
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
 * Test 103: Progressive-to-blobbed is allowed (R68)
 *
 * ' IFF' [12] [flags={operating=PROGRESSIVE}]
 * LIST ILBM           (progressive: no size, terminated by END)
 *   ' IFF' [12] [flags={operating=BLOBBED}]
 *   FORM [size] ILBM  (blobbed: has size field)
 *     BMHD [10] [data]
 * ' END' [0]          (terminates LIST)
 */
static char test_guard_prog_to_blobbed_ok(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	struct IFF_Header header_prog;
	header_prog.version = IFF_Header_Version_2025;
	header_prog.revision = 0;
	header_prog.flags.as_int = 0;
	header_prog.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	struct IFF_Header header_blobbed;
	header_blobbed.version = IFF_Header_Version_2025;
	header_blobbed.revision = 0;
	header_blobbed.flags.as_int = 0; // BLOBBED is default

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_prog)) goto cleanup;

	// LIST in progressive mode (no size field).
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	// Mid-stream: switch to blobbed.
	if (!IFF_TestBuilder_AddHeader(builder, &header_blobbed)) goto cleanup;

	// FORM in blobbed mode (has size field).
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Restore progressive for LIST EndContainer (writes END).
	builder->is_progressive = 1;
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
 * Test 104: Sizing narrowing 64 to 32 is allowed (R69)
 *
 * ' IFF' [12] [flags={sizing=64}]
 * LIST ILBM
 *   FORM ILBM { BMHD [10] }     (64-bit sizes)
 *   ' IFF' [12] [flags={sizing=32}]
 *   FORM ILBM { BODY [4] }      (32-bit sizes)
 */
static char test_guard_sizing_narrowing_ok(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header_64;
	header_64.version = IFF_Header_Version_2025;
	header_64.revision = 0;
	header_64.flags.as_int = 0;
	header_64.flags.as_fields.sizing = IFF_Header_Sizing_64;

	struct IFF_Header header_32;
	header_32.version = IFF_Header_Version_2025;
	header_32.revision = 0;
	header_32.flags.as_int = 0;
	header_32.flags.as_fields.sizing = IFF_Header_Sizing_32;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_64)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Mid-stream: narrow to 32-bit.
	if (!IFF_TestBuilder_AddHeader(builder, &header_32)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Restore 64-bit sizes for LIST EndContainer.
	builder->size_length = 8;
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
 * Test 105: Tag narrowing 16 to 8 is allowed (R70)
 *
 * ' IFF' [12] [flags={tag_sizing=16}]
 * LIST ILBM
 *   FORM ILBM { BMHD [10] }     (16-byte tags)
 *   ' IFF' [12] [flags={tag_sizing=8}]
 *   FORM ILBM { BODY [4] }      (8-byte tags)
 */
static char test_guard_tag_narrowing_ok(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};
	unsigned char body_data[4] = {0};

	struct IFF_Header header_tag16;
	header_tag16.version = IFF_Header_Version_2025;
	header_tag16.revision = 0;
	header_tag16.flags.as_int = 0;
	header_tag16.flags.as_fields.tag_sizing = IFF_Header_TagSizing_16;

	struct IFF_Header header_tag8;
	header_tag8.version = IFF_Header_Version_2025;
	header_tag8.revision = 0;
	header_tag8.flags.as_int = 0;
	header_tag8.flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header_tag16)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd_data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Mid-stream: narrow to 8-byte tags.
	if (!IFF_TestBuilder_AddHeader(builder, &header_tag8)) goto cleanup;

	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	// Restore 16-byte tags for LIST EndContainer.
	builder->tag_length = 16;
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

void test_suite_parse_midstream(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_midstream_narrows_tags);
	RUN_TEST(test_midstream_enables_no_padding);
	RUN_TEST(test_guard_sizing_widening);
	RUN_TEST(test_guard_tag_widening);
	RUN_TEST(test_guard_prog_to_blobbed_ok);
	RUN_TEST(test_guard_sizing_narrowing_ok);
	RUN_TEST(test_guard_tag_narrowing_ok);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
