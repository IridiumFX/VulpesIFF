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
// Helper: build a simple IFF-2025 stream with the given header flags and
// a FORM containing one chunk. Returns 1 on parse success (Complete).
// =========================================================================
static char PRIVATE_BuildAndParse
(
	union IFF_Header_Flags flags
	, const unsigned char *chunk_data
	, VPS_TYPE_SIZE chunk_size
	, struct IFF_Parser **out_parser
	, struct IFF_Parser_Factory **out_factory
	, struct IFF_TestBuilder **out_builder
)
{
	struct IFF_Header header;
	struct VPS_Data *image = 0;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags = flags;

	if (!IFF_TestBuilder_Allocate(out_builder)) return 0;
	if (!IFF_TestBuilder_Construct(*out_builder)) return 0;

	if (!IFF_TestBuilder_AddHeader(*out_builder, &header)) return 0;
	if (!IFF_TestBuilder_BeginContainer(*out_builder, "FORM", "ILBM")) return 0;
	if (!IFF_TestBuilder_AddChunk(*out_builder, "BMHD", chunk_data, chunk_size)) return 0;
	if (!IFF_TestBuilder_EndContainer(*out_builder)) return 0;

	if (!IFF_TestBuilder_GetResult(*out_builder, &image)) return 0;

	if (!IFF_Parser_Factory_Allocate(out_factory)) return 0;
	if (!IFF_Parser_Factory_Construct(*out_factory)) return 0;
	if (!IFF_Parser_Factory_CreateFromData(*out_factory, image, out_parser)) return 0;

	return 1;
}

static void PRIVATE_Cleanup
(
	struct IFF_Parser *parser
	, struct IFF_Parser_Factory *factory
	, struct IFF_TestBuilder *builder
)
{
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
}

// =========================================================================
// Test 35: sizing=32 (default) — 4-byte BE sizes
// =========================================================================
static char test_flags_sizing_32_default(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.sizing = IFF_Header_Sizing_32;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 36: sizing=64 — 8-byte sizes
// =========================================================================
static char test_flags_sizing_64(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.sizing = IFF_Header_Sizing_64;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 37: sizing=16 — 2-byte sizes
// =========================================================================
static char test_flags_sizing_16(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.sizing = IFF_Header_Sizing_16;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 38: tag_sizing=4 (default)
// =========================================================================
static char test_flags_tag_sizing_4_default(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.tag_sizing = IFF_Header_TagSizing_4;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 39: tag_sizing=8
// =========================================================================
static char test_flags_tag_sizing_8(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.tag_sizing = IFF_Header_TagSizing_8;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 40: tag_sizing=16
// =========================================================================
static char test_flags_tag_sizing_16(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.tag_sizing = IFF_Header_TagSizing_16;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 41: typing=LITTLE_ENDIAN — LE size fields
// =========================================================================
static char test_flags_little_endian(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 42: typing=UNSIGNED_SIZES
// =========================================================================
static char test_flags_unsigned_sizes(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.typing = IFF_Header_Flag_Typing_UNSIGNED_SIZES;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 43: typing=LE | UNSIGNED — both active
// =========================================================================
static char test_flags_le_unsigned(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[10] = {0};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.typing = IFF_Header_Flag_Typing_LITTLE_ENDIAN
		| IFF_Header_Flag_Typing_UNSIGNED_SIZES;

	if (!PRIVATE_BuildAndParse(flags, data, 10, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 44: structuring=NO_PADDING — odd chunk without pad byte
// =========================================================================
static char test_flags_no_padding(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	union IFF_Header_Flags flags;

	flags.as_int = 0;
	flags.as_fields.structuring = IFF_Header_Flag_Structuring_NO_PADDING;

	// NO_PADDING: TestBuilder's AddHeader sets builder->no_padding = 1,
	// so AddChunk won't write a pad byte after the 5-byte chunk.
	if (!PRIVATE_BuildAndParse(flags, data, 5, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 45: Default padding — odd chunk with pad byte
// =========================================================================
static char test_flags_default_padding(void)
{
	struct IFF_Parser *parser = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_TestBuilder *builder = 0;
	char result = 0;
	unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
	union IFF_Header_Flags flags;

	flags.as_int = 0; // Default structuring: padding enabled.

	if (!PRIVATE_BuildAndParse(flags, data, 5, &parser, &factory, &builder)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 46: STRICT_CONTAINERS — matching types succeed
//
// LIST(ILBM) > FORM(ILBM). Types match. Parse succeeds.
// =========================================================================
static char test_flags_strict_containers_match(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 47: STRICT_CONTAINERS — mismatching types fail
//
// LIST(ILBM) > FORM(8SVX). Types mismatch. Parse fails.
// =========================================================================
static char test_flags_strict_containers_mismatch(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "LIST", "ILBM")) goto cleanup;
	// FORM type 8SVX does not match LIST type ILBM — strict rejects this.
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "VHDR", data, 8)) goto cleanup;
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
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

// =========================================================================
// Test 48: STRICT_CONTAINERS — wildcard parent allows any child type
//
// CAT("    ") > FORM(ILBM). Wildcard parent permits any child. Succeeds.
// =========================================================================
static char test_flags_strict_wildcard_parent(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.structuring = IFF_Header_Flag_Structuring_STRICT_CONTAINERS;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "CAT ", "    ")) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BMHD", data, 10)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	PRIVATE_Cleanup(parser, factory, builder);
	return result;
}

void test_suite_parse_header_flags(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_flags_sizing_32_default);
	RUN_TEST(test_flags_sizing_64);
	RUN_TEST(test_flags_sizing_16);
	RUN_TEST(test_flags_tag_sizing_4_default);
	RUN_TEST(test_flags_tag_sizing_8);
	RUN_TEST(test_flags_tag_sizing_16);
	RUN_TEST(test_flags_little_endian);
	RUN_TEST(test_flags_unsigned_sizes);
	RUN_TEST(test_flags_le_unsigned);
	RUN_TEST(test_flags_no_padding);
	RUN_TEST(test_flags_default_padding);
	RUN_TEST(test_flags_strict_containers_match);
	RUN_TEST(test_flags_strict_containers_mismatch);
	RUN_TEST(test_flags_strict_wildcard_parent);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
