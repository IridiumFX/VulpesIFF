#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Hash_Utils.h>
#include <vulpes/VPS_Compare_Utils.h>

#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_ChecksumAlgorithm.h>
#include <IFF/IFF_DataTap.h>
#include <IFF/IFF_WriteTap.h>
#include <IFF/IFF_Reader.h>
#include <IFF/IFF_Writer.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "Test.h"
#include "IFF_TestChecksumAlgorithm.h"

static struct VPS_Set *PRIVATE_CreateAlgoSet(void)
{
	struct VPS_Set *algo_set = 0;
	struct VPS_Data *algo_id = 0;

	if (!VPS_Data_Allocate(&algo_id, 9, 9)) return 0;
	if (!VPS_Data_Construct(algo_id))
	{
		VPS_Data_Release(algo_id);
		return 0;
	}
	memcpy(algo_id->bytes, "TEST-XOR", 9);
	algo_id->limit = 9;

	if (!VPS_Set_Allocate(&algo_set, 7))
	{
		VPS_Data_Release(algo_id);
		return 0;
	}

	if (!VPS_Set_Construct
	(
		algo_set
		, VPS_Hash_Utils_Data
		, VPS_Compare_Utils_Data
		, (char (*)(void *))VPS_Data_Release
		, 2, 75, 8
	))
	{
		VPS_Set_Release(algo_set);
		VPS_Data_Release(algo_id);
		return 0;
	}

	if (!VPS_Set_Add(algo_set, algo_id))
	{
		VPS_Set_Release(algo_set);
		return 0;
	}

	return algo_set;
}

/**
 * W5: flush_with_open_span_fails
 *
 * BeginChecksumSpan without EndChecksumSpan. Flush fails.
 */
static char test_gen_flush_open_span_fails(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;

	algo_set = PRIVATE_CreateAlgoSet();
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	// Intentionally NO EndChecksumSpan.
	if (!IFF_Generator_EndForm(gen)) goto cleanup;

	// Flush should fail due to open span.
	TEST_ASSERT(!IFF_Generator_Flush(gen));

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W59: checksum_span_blobbed
 *
 * Blobbed FORM with CHK..SUM around a chunk. Parse verifies checksum.
 */
static char test_gen_checksum_blobbed(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[10] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0; // Blobbed.

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 10;
	body_wrap.limit = 10;

	algo_set = PRIVATE_CreateAlgoSet();
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W60: checksum_span_progressive
 *
 * Progressive FORM with CHK..SUM around a chunk. Parse verifies.
 */
static char test_gen_checksum_progressive(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[10] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 10;
	body_wrap.limit = 10;

	algo_set = PRIVATE_CreateAlgoSet();
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W61: checksum_span_empty
 *
 * BeginChecksumSpan + EndChecksumSpan with no data between.
 * SUM emitted with checksum of empty input. Parse succeeds.
 */
static char test_gen_checksum_empty_span(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[4] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 4;
	body_wrap.limit = 4;

	algo_set = PRIVATE_CreateAlgoSet();
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	// Empty span: CHK immediately followed by SUM.
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	VPS_Set_Release(algo_set);
	return result;
}

void test_suite_generate_checksum_span(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_flush_open_span_fails);
	RUN_TEST(test_gen_checksum_blobbed);
	RUN_TEST(test_gen_checksum_progressive);
	RUN_TEST(test_gen_checksum_empty_span);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
