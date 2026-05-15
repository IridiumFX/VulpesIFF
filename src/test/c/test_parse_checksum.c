#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Dictionary.h>
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
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>
#include <IFF/IFF_Generator.h>
#include <IFF/IFF_Generator_Factory.h>

#include "Test.h"
#include "IFF_TestChecksumAlgorithm.h"

/**
 * Test 20: Checksum round-trip — generator writes CHK/SUM, parser verifies
 *
 * Generator path:
 *   WriteHeader(IFF-2025, default flags)
 *   BeginForm(ILBM)
 *     BeginChecksumSpan({TEST-XOR})
 *     WriteChunk(BMHD, 10 zero bytes)
 *     EndChecksumSpan
 *   EndForm
 *   Flush → GetOutputData
 *
 * The generator computes the TEST-XOR checksum of all bytes in the span
 * and embeds the ' CHK' and ' SUM' directives around the chunk.
 *
 * Parser path:
 *   Register TEST-XOR on parser's DataTap
 *   Scan → parser reads ' CHK', accumulates bytes, reads ' SUM', verifies
 *
 * Expected: Output produced, parser scan succeeds, Complete, iff85_locked == 0
 */
static char test_checksum_roundtrip(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	struct VPS_Data *algo_id = 0;
	char result = 0;

	unsigned char bmhd_data[10] = {0};

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag;
	struct IFF_Tag bmhd_tag;
	struct VPS_Data bmhd_wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0; // defaults: blobbed, 32-bit, 4-byte tags

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&bmhd_tag, (const unsigned char *)"BMHD", 4, IFF_TAG_TYPE_TAG);

	memset(&bmhd_wrap, 0, sizeof(bmhd_wrap));
	bmhd_wrap.bytes = bmhd_data;
	bmhd_wrap.size = 10;
	bmhd_wrap.limit = 10;
	bmhd_wrap.own_bytes = 0;

	// --- Build the VPS_Set of algorithm identifiers ---
	// The set contains VPS_Data* items. Each item's bytes is the algorithm
	// identifier string. DataTap_StartSpan extracts (const char*)bytes
	// for dictionary lookup.

	if (!VPS_Data_Allocate(&algo_id, 9, 9)) goto cleanup;
	if (!VPS_Data_Construct(algo_id)) goto cleanup;
	memcpy(algo_id->bytes, "TEST-XOR", 9); // includes null terminator
	algo_id->limit = 9;

	if (!VPS_Set_Allocate(&algo_set, 7)) goto cleanup;
	if (!VPS_Set_Construct
	(
		algo_set
		, VPS_Hash_Utils_Data
		, VPS_Compare_Utils_Data
		, (char (*)(void *))VPS_Data_Release
		, 2, 75, 8
	))
	{
		goto cleanup;
	}

	if (!VPS_Set_Add(algo_set, algo_id)) goto cleanup;
	algo_id = 0; // set owns it now

	// --- Generator: create output with checksum span ---

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;

	// Register the algorithm on the generator's write tap.
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &bmhd_tag, &bmhd_wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);
	TEST_ASSERT(output->limit > 0);

	// --- Parser: verify the checksum ---

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;

	// Register the same algorithm on the parser's data tap.
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);
	TEST_ASSERT(parser->session->iff85_locked == 0);

	result = 1;

cleanup:

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(parse_factory);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gen_factory);
	VPS_Set_Release(algo_set);
	VPS_Data_Release(algo_id);

	return result;
}

void test_suite_parse_checksum(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_checksum_roundtrip);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
