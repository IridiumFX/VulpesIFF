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
 * R58: ref_mandatory_no_resolver
 *
 * ' REF' at root level with mandatory option (id_size=4, "test").
 * No segment resolver registered. Conformance matrix says parse should fail.
 *
 * REF payload layout (32-bit sizes):
 *   num_options(4 bytes BE) = 1
 *   id_size(4 bytes BE)     = 4
 *   id_data(4 bytes)        = "test"
 */
static char test_ref_mandatory_no_resolver(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *image = 0;
	char result = 0;

	unsigned char body_data[4] = {0};
	unsigned char ref_payload[12];

	struct IFF_Header header;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	// Build REF payload: num_options=1, id_size=4, id_data="test"
	VPS_Endian_Write32UBE(ref_payload + 0, 1);       // num_options = 1
	VPS_Endian_Write32UBE(ref_payload + 4, 4);       // id_size = 4 (mandatory)
	memcpy(ref_payload + 8, "test", 4);               // id_data

	if (!IFF_TestBuilder_Allocate(&builder)) return 0;
	if (!IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (!IFF_TestBuilder_AddHeader(builder, &header)) goto cleanup;
	if (!IFF_TestBuilder_AddDirective(builder, " REF", ref_payload, 12)) goto cleanup;
	if (!IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (!IFF_TestBuilder_AddChunk(builder, "BODY", body_data, 4)) goto cleanup;
	if (!IFF_TestBuilder_EndContainer(builder)) goto cleanup;

	if (!IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(factory, image, &parser)) goto cleanup;

	// Enable strict references: mandatory REF without resolver should fail.
	parser->strict_references = 1;

	TEST_ASSERT(!IFF_Parser_Scan(parser));

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);
	IFF_TestBuilder_Release(builder);
	return result;
}

void test_suite_parse_ref_mandatory(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_ref_mandatory_no_resolver);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
