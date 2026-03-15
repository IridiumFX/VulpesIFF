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

#include <IFF/IFF_Checksum_LRC.h>
#include <IFF/IFF_Checksum_RFC1071.h>
#include <IFF/IFF_Checksum_CRC32C.h>
#include <IFF/IFF_Checksum_CRC64ECMA.h>

#include "Test.h"

static struct VPS_Set *PRIVATE_CreateAlgoSet(const char *id, VPS_TYPE_SIZE id_len)
{
	struct VPS_Set *algo_set = 0;
	struct VPS_Data *algo_id = 0;

	if (!VPS_Data_Allocate(&algo_id, id_len, id_len)) return 0;
	if (!VPS_Data_Construct(algo_id)) { VPS_Data_Release(algo_id); return 0; }
	memcpy(algo_id->bytes, id, id_len);
	algo_id->limit = id_len;

	if (!VPS_Set_Allocate(&algo_set, 7)) { VPS_Data_Release(algo_id); return 0; }
	if (!VPS_Set_Construct(algo_set, VPS_Hash_Utils_Data, VPS_Compare_Utils_Data,
		(char (*)(void *))VPS_Data_Release, 2, 75, 8))
	{
		VPS_Set_Release(algo_set);
		VPS_Data_Release(algo_id);
		return 0;
	}

	if (!VPS_Set_Add(algo_set, algo_id)) { VPS_Set_Release(algo_set); return 0; }

	return algo_set;
}

/**
 * Generic roundtrip test for a given checksum algorithm.
 * Generates FORM with CHK..SUM around a known data pattern,
 * then parses and verifies the checksum.
 */
static char PRIVATE_TestAlgorithmRoundtrip
(
	const struct IFF_ChecksumAlgorithm *algo
	, const char *algo_id
	, VPS_TYPE_SIZE algo_id_len
)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	// Known data pattern for reproducible checksums.
	unsigned char body_data[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	memset(&body_wrap, 0, sizeof(body_wrap));
	body_wrap.bytes = body_data;
	body_wrap.size = 16;
	body_wrap.limit = 16;

	algo_set = PRIVATE_CreateAlgoSet(algo_id, algo_id_len);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, algo)) goto cleanup;

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
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, algo)) goto cleanup;

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

/** R92: LRC-ISO-1155 algorithm roundtrip */
static char test_checksum_lrc(void)
{
	return PRIVATE_TestAlgorithmRoundtrip(IFF_Checksum_LRC_Get(), "LRC-ISO-1155", 13);
}

/** R93: RFC-1071 algorithm roundtrip */
static char test_checksum_rfc1071(void)
{
	return PRIVATE_TestAlgorithmRoundtrip(IFF_Checksum_RFC1071_Get(), "RFC-1071", 9);
}

/** R94: CRC-32C algorithm roundtrip */
static char test_checksum_crc32c(void)
{
	return PRIVATE_TestAlgorithmRoundtrip(IFF_Checksum_CRC32C_Get(), "CRC-32C", 8);
}

/** R95: CRC-64/ECMA algorithm roundtrip */
static char test_checksum_crc64ecma(void)
{
	return PRIVATE_TestAlgorithmRoundtrip(IFF_Checksum_CRC64ECMA_Get(), "CRC64-ECMA", 11);
}

void test_suite_parse_checksum_algorithms(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_checksum_lrc);
	RUN_TEST(test_checksum_rfc1071);
	RUN_TEST(test_checksum_crc32c);
	RUN_TEST(test_checksum_crc64ecma);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
