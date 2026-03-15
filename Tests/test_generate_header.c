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
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"
#include "IFF_TestBuilder.h"

/**
 * Test 91: WriteHeader at root succeeds (W6)
 *
 * WriteHeader at root level produces ' IFF' directive in output.
 */
static char test_gen_header_at_root(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag type_tag;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	TEST_ASSERT(IFF_Generator_WriteHeader(gen, &header));

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	TEST_ASSERT(output->limit > 0);

	// Verify the output is parseable and uses IFF-2025 mode.
	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 92: WriteHeader inside container fails (W7)
 */
static char test_gen_header_inside_container_fails(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag type_tag;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;

	// WriteHeader inside FORM should fail.
	TEST_ASSERT(!IFF_Generator_WriteHeader(gen, &header));

	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 93: WriteHeader updates generator flags (W8)
 *
 * WriteHeader with progressive mode. gen->flags should be updated.
 */
static char test_gen_header_updates_flags(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	char result = 0;

	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Before WriteHeader: default IFF-85 flags.
	TEST_ASSERT(gen->flags.as_fields.operating == IFF_Header_Operating_BLOBBED);

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;

	// After WriteHeader: flags updated to progressive.
	TEST_ASSERT(gen->flags.as_fields.operating == IFF_Header_Operating_PROGRESSIVE);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

/**
 * Test 94: WriteHeader binary layout (W9)
 *
 * Generator WriteHeader output matches TestBuilder AddHeader.
 * Compare the first 20 bytes: ' IFF'(4) + size(4, value 12) + ver(2) + rev(2) + flags(8).
 */
static char test_gen_header_binary_layout(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *actual = 0;
	struct VPS_Data *expected = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag type_tag;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	// Build reference with TestBuilder.
	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &expected)) goto cleanup;

	// Build actual with generator.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &actual)) goto cleanup;

	// Compare entire output.
	TEST_ASSERT(actual->limit == expected->limit);
	TEST_ASSERT(memcmp(actual->bytes, expected->bytes, actual->limit) == 0);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

/**
 * Test 95: WriteHeader always uses IFF-85 config for its own encoding (W10)
 *
 * First WriteHeader sets sizing=16. The header directive itself was still
 * written with IFF-85 config (4-byte tags, 32-bit BE sizes). Verify
 * by checking the first 20 bytes: tag(4) + size_32be(4) + payload(12).
 */
static char test_gen_header_uses_iff85_config(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Data *output = 0;
	char result = 0;

	struct IFF_Header header;
	struct IFF_Tag type_tag;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.sizing = IFF_Header_Sizing_16;

	IFF_Tag_Construct(&type_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) return 0;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &type_tag)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	// The header directive must use IFF-85 encoding:
	// Bytes 0-3: ' IFF' tag (4 bytes, left-padded: 0x20 0x49 0x46 0x46)
	TEST_ASSERT(output->bytes[0] == ' ');
	TEST_ASSERT(output->bytes[1] == 'I');
	TEST_ASSERT(output->bytes[2] == 'F');
	TEST_ASSERT(output->bytes[3] == 'F');

	// Bytes 4-7: size as 32-bit BE (value 12 = 0x00 0x00 0x00 0x0C)
	TEST_ASSERT(output->bytes[4] == 0x00);
	TEST_ASSERT(output->bytes[5] == 0x00);
	TEST_ASSERT(output->bytes[6] == 0x00);
	TEST_ASSERT(output->bytes[7] == 0x0C);

	// After the header (20 bytes), the FORM tag uses 4-byte tags but
	// 16-bit sizes (as set by the header flags).
	// Bytes 20-23: 'FORM' tag
	TEST_ASSERT(output->bytes[20] == 'F');
	TEST_ASSERT(output->bytes[21] == 'O');
	TEST_ASSERT(output->bytes[22] == 'R');
	TEST_ASSERT(output->bytes[23] == 'M');

	// Bytes 24-25: FORM size as 16-bit BE (type tag only = 4 bytes = 0x00 0x04)
	TEST_ASSERT(output->bytes[24] == 0x00);
	TEST_ASSERT(output->bytes[25] == 0x04);

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	return result;
}

void test_suite_generate_header(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_header_at_root);
	RUN_TEST(test_gen_header_inside_container_fails);
	RUN_TEST(test_gen_header_updates_flags);
	RUN_TEST(test_gen_header_binary_layout);
	RUN_TEST(test_gen_header_uses_iff85_config);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
