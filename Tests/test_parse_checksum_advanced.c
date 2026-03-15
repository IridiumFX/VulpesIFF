#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Endian.h>
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

#include "Test.h"
#include "IFF_TestChecksumAlgorithm.h"

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

static struct VPS_Set *PRIVATE_CreateDualAlgoSet(const char *id1, VPS_TYPE_SIZE len1,
	const char *id2, VPS_TYPE_SIZE len2)
{
	struct VPS_Set *algo_set = 0;
	struct VPS_Data *a1 = 0, *a2 = 0;

	if (!VPS_Data_Allocate(&a1, len1, len1)) return 0;
	if (!VPS_Data_Construct(a1)) { VPS_Data_Release(a1); return 0; }
	memcpy(a1->bytes, id1, len1);
	a1->limit = len1;

	if (!VPS_Data_Allocate(&a2, len2, len2)) { VPS_Data_Release(a1); return 0; }
	if (!VPS_Data_Construct(a2)) { VPS_Data_Release(a2); VPS_Data_Release(a1); return 0; }
	memcpy(a2->bytes, id2, len2);
	a2->limit = len2;

	if (!VPS_Set_Allocate(&algo_set, 7)) { VPS_Data_Release(a1); VPS_Data_Release(a2); return 0; }
	if (!VPS_Set_Construct(algo_set, VPS_Hash_Utils_Data, VPS_Compare_Utils_Data,
		(char (*)(void *))VPS_Data_Release, 2, 75, 8))
	{
		VPS_Set_Release(algo_set);
		VPS_Data_Release(a1);
		VPS_Data_Release(a2);
		return 0;
	}

	if (!VPS_Set_Add(algo_set, a1)) { VPS_Set_Release(algo_set); VPS_Data_Release(a2); return 0; }
	if (!VPS_Set_Add(algo_set, a2)) { VPS_Set_Release(algo_set); return 0; }

	return algo_set;
}

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf;
	d.size = size;
	d.limit = size;
	return d;
}

/**
 * R87: checksum_mismatch_fails
 *
 * Generate valid CHK..SUM with TEST-XOR. Corrupt the SUM checksum value
 * in the output. Parser detects mismatch. Parse fails.
 */
static char test_checksum_mismatch_fails(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[10];
	memset(body_data, 0x42, 10);

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	body_wrap = PRIVATE_Wrap(body_data, 10);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
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

	// Corrupt the SUM checksum value. Find ' SUM' tag in the output
	// and flip the last byte of the directive (the checksum byte).
	{
		VPS_TYPE_SIZE i;
		char found = 0;
		for (i = 0; i + 3 < output->limit; ++i)
		{
			if (memcmp(output->bytes + i, " SUM", 4) == 0)
			{
				// SUM found. The checksum value is the last byte before the
				// FORM boundary. Corrupt the byte just before the FORM end.
				VPS_TYPE_SIZE sum_size = VPS_Endian_Read32UBE(output->bytes + i + 4);
				VPS_TYPE_SIZE sum_end = i + 4 + 4 + sum_size; // tag + size_field + payload
				if (sum_end > 0 && sum_end <= output->limit)
				{
					output->bytes[sum_end - 1] ^= 0xFF;
				}
				found = 1;
				break;
			}
		}
		TEST_ASSERT(found);
	}

	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	// Parse should fail due to checksum mismatch.
	TEST_ASSERT(!IFF_Parser_Scan(parser));

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
 * R88: checksum_empty_span
 *
 * CHK immediately followed by SUM with no data between.
 * Checksum of empty byte sequence verified. Parse succeeds.
 */
static char test_checksum_empty_span(void)
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
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	body_wrap = PRIVATE_Wrap(body_data, 4);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	// No data between CHK and SUM.
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

/**
 * R89: checksum_nested_spans
 *
 * Two CHK..SUM pairs nested: outer covers inner CHK+data+SUM.
 * Both verified independently. Parse succeeds.
 */
static char test_checksum_nested_spans(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *outer_set = 0;
	struct VPS_Set *inner_set = 0;
	char result = 0;

	unsigned char body_data[10] = {0};

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	body_wrap = PRIVATE_Wrap(body_data, 10);

	outer_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	inner_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!outer_set || !inner_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;

	// Outer span.
	if (!IFF_Generator_BeginChecksumSpan(gen, outer_set)) goto cleanup;

	// Inner span (nested inside outer).
	if (!IFF_Generator_BeginChecksumSpan(gen, inner_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;

	// End outer span (covers inner CHK + data + inner SUM).
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
	VPS_Set_Release(outer_set);
	VPS_Set_Release(inner_set);
	return result;
}

/**
 * R90: checksum_multiple_algorithms
 *
 * CHK lists two algorithm IDs (TEST-XOR and LRC-ISO-1155).
 * Both checksums computed and verified in SUM. Parse succeeds.
 */
static char test_checksum_multiple_algorithms(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[10];
	memset(body_data, 0x55, 10);

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();
	const struct IFF_ChecksumAlgorithm *lrc_algo = IFF_Checksum_LRC_Get();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	body_wrap = PRIVATE_Wrap(body_data, 10);

	algo_set = PRIVATE_CreateDualAlgoSet("TEST-XOR", 9, "LRC-ISO-1155", 13);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, lrc_algo)) goto cleanup;

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
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, lrc_algo)) goto cleanup;

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
 * R91: checksum_partial_algorithm_support
 *
 * CHK lists 2 algorithms (TEST-XOR and LRC-ISO-1155).
 * Parser only has TEST-XOR registered (not LRC).
 * Registered one is verified, unregistered is skipped. Parse succeeds.
 */
static char test_checksum_partial_algorithm_support(void)
{
	struct IFF_Generator_Factory *gen_factory = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *parse_factory = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char body_data[10];
	memset(body_data, 0xAA, 10);

	struct IFF_Header header;
	struct IFF_Tag ilbm_tag, body_tag;
	struct VPS_Data body_wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();
	const struct IFF_ChecksumAlgorithm *lrc_algo = IFF_Checksum_LRC_Get();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm_tag, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body_tag, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	body_wrap = PRIVATE_Wrap(body_data, 10);

	algo_set = PRIVATE_CreateDualAlgoSet("TEST-XOR", 9, "LRC-ISO-1155", 13);
	if (!algo_set) goto cleanup;

	// Generator has both algorithms.
	if (!IFF_Generator_Factory_Allocate(&gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gen_factory)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gen_factory, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, lrc_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm_tag)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body_tag, &body_wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	// Parser only has TEST-XOR, not LRC.
	if (!IFF_Parser_Factory_Allocate(&parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(parse_factory)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(parse_factory, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;
	// Intentionally NOT registering LRC on parser.

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

void test_suite_parse_checksum_advanced(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_checksum_mismatch_fails);
	RUN_TEST(test_checksum_empty_span);
	RUN_TEST(test_checksum_nested_spans);
	RUN_TEST(test_checksum_multiple_algorithms);
	RUN_TEST(test_checksum_partial_algorithm_support);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
