#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Endian.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * R9: iff2025_version_zero_locks_85
 *
 * ' IFF' with version=0 activates IFF-85 mode. iff85_locked == 1.
 * The flags from the directive are ignored; IFF-85 defaults apply.
 */
static char test_version_zero_locks_85(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	header.version = IFF_Header_Version_1985; // version = 0
	header.revision = 0;
	header.flags.as_int = 0;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
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
 * R10: iff2025_unknown_version_fails
 *
 * ' IFF' with version=99. Parse fails (unrecognized version).
 */
static char test_unknown_version_fails(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	header.version = 99; // Unknown version
	header.revision = 0;
	header.flags.as_int = 0;

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	// Parse should fail due to unrecognized version.
	TEST_ASSERT(!IFF_Parser_Scan(parser));

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * R11: iff2025_unknown_flag_values_fail
 *
 * ' IFF' version=40 whose flags carry a value outside the specification's
 * exhaustive definitions (unknown sizing/tag_sizing/operating/encoding
 * enumeration, undefined typing/structuring bits, nonzero reserved field).
 * Each variant must fail the parse instead of silently misparsing with
 * defaulted field widths.
 */
static char test_unknown_flag_values_fail(void)
{
	struct Variant
	{
		const char *label;
		union IFF_Header_Flags flags;
	};

	struct Variant variants[7];
	VPS_TYPE_SIZE i;

	for (i = 0; i < 7; ++i)
	{
		variants[i].flags.as_int = 0;
	}
	variants[0].label = "sizing";
	variants[0].flags.as_fields.sizing = 7;
	variants[1].label = "tag_sizing";
	variants[1].flags.as_fields.tag_sizing = 3;
	variants[2].label = "operating";
	variants[2].flags.as_fields.operating = 2;
	variants[3].label = "encoding";
	variants[3].flags.as_fields.encoding = 1;
	variants[4].label = "typing";
	variants[4].flags.as_fields.typing = 4;
	variants[5].label = "structuring";
	variants[5].flags.as_fields.structuring = 8;
	variants[6].label = "reserved";
	variants[6].flags.as_fields.reserved = 1;

	for (i = 0; i < 7; ++i)
	{
		struct IFF_TestBuilder *builder = 0;
		struct IFF_Parser_Factory *factory = 0;
		struct IFF_Parser *parser = 0;
		struct VPS_Data *image = 0;
		char scan_result = 1;

		unsigned char body_data[4] = {0};

		struct IFF_Header header;
		header.version = IFF_Header_Version_2025;
		header.revision = 0;
		header.flags = variants[i].flags;

		if (!IFF_TestBuilder_Allocate(&builder)) return 0;
		if (!IFF_TestBuilder_Construct(builder)
			|| !IFF_TestBuilder_AddHeader(builder, &header)
			|| !IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")
			|| !IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)
			|| !IFF_TestBuilder_EndContainer(builder)
			|| !IFF_TestBuilder_GetResult(builder, &image)
			|| !IFF_Parser_Factory_Allocate(&factory)
			|| !IFF_Parser_Factory_Construct(factory)
			|| !IFF_Parser_Factory_CreateFromData(factory, image, &parser))
		{
			IFF_Parser_Release(parser);
			IFF_Parser_Factory_Release(factory);
			IFF_TestBuilder_Release(builder);
			return 0;
		}

		scan_result = IFF_Parser_Scan(parser);

		IFF_Parser_Release(parser);
		IFF_Parser_Factory_Release(factory);
		IFF_TestBuilder_Release(builder);

		if (scan_result)
		{
			printf("    [variant '%s' was accepted]\n", variants[i].label);
			return 0;
		}
	}

	return 1;
}

void test_suite_parse_version(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_version_zero_locks_85);
	RUN_TEST(test_unknown_version_fails);
	RUN_TEST(test_unknown_flag_values_fail);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
