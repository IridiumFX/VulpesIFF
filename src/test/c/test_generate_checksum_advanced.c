#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>
#include <vulpes/VPS_Set.h>
#include <vulpes/VPS_Endian.h>
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

#include "Test.h"
#include "IFF_TestChecksumAlgorithm.h"

static struct VPS_Set *PRIVATE_CreateAlgoSet(const char *id, VPS_TYPE_SIZE id_len)
{
	struct VPS_Set *s = 0;
	struct VPS_Data *d = 0;

	if (!VPS_Data_Allocate(&d, id_len, id_len)) return 0;
	if (!VPS_Data_Construct(d)) { VPS_Data_Release(d); return 0; }
	memcpy(d->bytes, id, id_len);
	d->limit = id_len;

	if (!VPS_Set_Allocate(&s, 7)) { VPS_Data_Release(d); return 0; }
	if (!VPS_Set_Construct(s, VPS_Hash_Utils_Data, VPS_Compare_Utils_Data,
		(char (*)(void *))VPS_Data_Release, 2, 75, 8))
	{ VPS_Set_Release(s); VPS_Data_Release(d); return 0; }

	if (!VPS_Set_Add(s, d)) { VPS_Set_Release(s); return 0; }
	return s;
}

static struct VPS_Set *PRIVATE_CreateDualAlgoSet(const char *id1, VPS_TYPE_SIZE l1,
	const char *id2, VPS_TYPE_SIZE l2)
{
	struct VPS_Set *s = 0;
	struct VPS_Data *a1 = 0, *a2 = 0;

	if (!VPS_Data_Allocate(&a1, l1, l1)) return 0;
	if (!VPS_Data_Construct(a1)) { VPS_Data_Release(a1); return 0; }
	memcpy(a1->bytes, id1, l1); a1->limit = l1;
	if (!VPS_Data_Allocate(&a2, l2, l2)) { VPS_Data_Release(a1); return 0; }
	if (!VPS_Data_Construct(a2)) { VPS_Data_Release(a2); VPS_Data_Release(a1); return 0; }
	memcpy(a2->bytes, id2, l2); a2->limit = l2;

	if (!VPS_Set_Allocate(&s, 7)) { VPS_Data_Release(a1); VPS_Data_Release(a2); return 0; }
	if (!VPS_Set_Construct(s, VPS_Hash_Utils_Data, VPS_Compare_Utils_Data,
		(char (*)(void *))VPS_Data_Release, 2, 75, 8))
	{ VPS_Set_Release(s); VPS_Data_Release(a1); VPS_Data_Release(a2); return 0; }

	if (!VPS_Set_Add(s, a1)) { VPS_Set_Release(s); VPS_Data_Release(a2); return 0; }
	if (!VPS_Set_Add(s, a2)) { VPS_Set_Release(s); return 0; }
	return s;
}

static struct VPS_Data PRIVATE_Wrap(unsigned char *buf, VPS_TYPE_SIZE size)
{
	struct VPS_Data d;
	memset(&d, 0, sizeof(d));
	d.bytes = buf; d.size = size; d.limit = size;
	return d;
}

/**
 * W62: checksum_span_nested
 *
 * Two nested CHK..SUM spans. Both verify on parse.
 */
static char test_gen_checksum_nested(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *outer = 0, *inner = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	outer = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	inner = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!outer || !inner) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, outer)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, inner)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(outer);
	VPS_Set_Release(inner);
	return result;
}

/**
 * W63: checksum_span_multiple_algorithms
 *
 * BeginChecksumSpan with 2 algorithm IDs (TEST-XOR + LRC-ISO-1155).
 * SUM contains checksums for both. Parse verifies both.
 */
static char test_gen_checksum_multiple_algorithms(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char data[10] = {0};
	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();
	const struct IFF_ChecksumAlgorithm *lrc_algo = IFF_Checksum_LRC_Get();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	algo_set = PRIVATE_CreateDualAlgoSet("TEST-XOR", 9, "LRC-ISO-1155", 13);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, lrc_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, lrc_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W64: checksum_binary_layout_chk
 *
 * Verify CHK directive binary structure in output.
 * CHK payload: version(4 BE)=1, num_ids(4 BE)=1, id_size(4 BE)=9, "TEST-XOR\0"
 */
static char test_gen_checksum_binary_layout_chk(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);

	// Find ' CHK' tag in output and verify structure.
	{
		VPS_TYPE_SIZE i;
		char found = 0;
		for (i = 0; i + 3 < output->limit; ++i)
		{
			if (memcmp(output->bytes + i, " CHK", 4) == 0)
			{
				VPS_TYPE_SIZE payload_size = VPS_Endian_Read32UBE(output->bytes + i + 4);
				VPS_TYPE_SIZE off = i + 8; // start of payload

				// version = 1
				TEST_ASSERT(VPS_Endian_Read32UBE(output->bytes + off) == 1);
				off += 4;
				// num_ids = 1
				TEST_ASSERT(VPS_Endian_Read32UBE(output->bytes + off) == 1);
				off += 4;
				// id_size = 8 (strlen, no null terminator)
				TEST_ASSERT(VPS_Endian_Read32UBE(output->bytes + off) == 8);
				off += 4;
				// id = "TEST-XOR"
				TEST_ASSERT(memcmp(output->bytes + off, "TEST-XOR", 8) == 0);

				found = 1;
				break;
			}
		}
		TEST_ASSERT(found);
	}

	result = 1;

cleanup:
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W65: checksum_binary_layout_sum
 *
 * Verify SUM directive is present and parseable.
 * SUM follows the data chunk and contains the computed checksum.
 */
static char test_gen_checksum_binary_layout_sum(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *algo_set = 0;
	char result = 0;

	unsigned char data[4] = {0};
	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	const struct IFF_ChecksumAlgorithm *xor_algo = IFF_TestChecksumAlgorithm_GetXOR();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 4);

	algo_set = PRIVATE_CreateAlgoSet("TEST-XOR", 9);
	if (!algo_set) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, xor_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, algo_set)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;
	TEST_ASSERT(output != 0);

	// Find ' SUM' tag in the output and verify it exists.
	{
		VPS_TYPE_SIZE i;
		char found = 0;
		for (i = 0; i + 3 < output->limit; ++i)
		{
			if (memcmp(output->bytes + i, " SUM", 4) == 0)
			{
				VPS_TYPE_SIZE payload_size = VPS_Endian_Read32UBE(output->bytes + i + 4);
				TEST_ASSERT(payload_size > 0);

				// Verify version = 1
				VPS_TYPE_SIZE off = i + 8;
				TEST_ASSERT(VPS_Endian_Read32UBE(output->bytes + off) == 1);

				found = 1;
				break;
			}
		}
		TEST_ASSERT(found);
	}

	// Parse roundtrip is the ultimate validation.
	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, xor_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(algo_set);
	return result;
}

/**
 * W66: checksum_span_nested_progressive
 *
 * Two nested CHK..SUM spans in PROGRESSIVE mode, verified with the additive
 * RFC-1071 algorithm. Guards two regressions at once:
 * - the generator must feed the inner SUM tag only to the span being ended
 *   (the outer span receives the whole SUM chunk through the WriteTap once);
 *   with an order-independent XOR algorithm a double-feed cancels out, so
 *   this test deliberately uses an additive checksum;
 * - RFC-1071 must carry its byte-offset parity across update calls, because
 *   the parser and generator split the same stream into different buffers.
 */
static char test_gen_checksum_nested_progressive(void)
{
	struct IFF_Generator_Factory *gf = 0;
	struct IFF_Generator *gen = 0;
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data *output = 0;
	struct VPS_Set *outer = 0, *inner = 0;
	char result = 0;

	unsigned char data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	struct IFF_Header header;
	struct IFF_Tag ilbm, body;
	struct VPS_Data wrap;

	const struct IFF_ChecksumAlgorithm *rfc_algo = IFF_Checksum_RFC1071_Get();

	header.version = IFF_Header_Version_2025;
	header.revision = 0;
	header.flags.as_int = 0;
	header.flags.as_fields.operating = IFF_Header_Operating_PROGRESSIVE;

	IFF_Tag_Construct(&ilbm, (const unsigned char *)"ILBM", 4, IFF_TAG_TYPE_TAG);
	IFF_Tag_Construct(&body, (const unsigned char *)"BODY", 4, IFF_TAG_TYPE_TAG);
	wrap = PRIVATE_Wrap(data, 10);

	outer = PRIVATE_CreateAlgoSet("RFC-1071", 9);
	inner = PRIVATE_CreateAlgoSet("RFC-1071", 9);
	if (!outer || !inner) goto cleanup;

	if (!IFF_Generator_Factory_Allocate(&gf)) goto cleanup;
	if (!IFF_Generator_Factory_Construct(gf)) goto cleanup;
	if (!IFF_Generator_Factory_CreateToData(gf, &gen)) goto cleanup;
	if (!IFF_WriteTap_RegisterAlgorithm(gen->writer->tap, rfc_algo)) goto cleanup;

	if (!IFF_Generator_WriteHeader(gen, &header)) goto cleanup;
	if (!IFF_Generator_BeginForm(gen, &ilbm)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, outer)) goto cleanup;
	if (!IFF_Generator_BeginChecksumSpan(gen, inner)) goto cleanup;
	if (!IFF_Generator_WriteChunk(gen, &body, &wrap)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndChecksumSpan(gen)) goto cleanup;
	if (!IFF_Generator_EndForm(gen)) goto cleanup;
	if (!IFF_Generator_Flush(gen)) goto cleanup;

	if (!IFF_Generator_GetOutputData(gen, &output)) goto cleanup;

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;
	if (!IFF_Parser_Factory_CreateFromData(pf, output, &parser)) goto cleanup;
	if (!IFF_DataTap_RegisterAlgorithm(parser->reader->tap, rfc_algo)) goto cleanup;

	TEST_ASSERT(IFF_Parser_Scan(parser));
	TEST_ASSERT(parser->session->session_state == IFF_Parser_SessionState_Complete);

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	IFF_Generator_Release(gen);
	IFF_Generator_Factory_Release(gf);
	VPS_Set_Release(outer);
	VPS_Set_Release(inner);
	return result;
}

/**
 * W67: malformed_container_boundaries
 *
 * Hand-crafted malformed blobbed streams must fail the parse:
 * - a FORM declaring size 0 (smaller than its own type tag) must not be
 *   treated as unbounded;
 * - a FORM whose contents are truncated before the declared boundary must
 *   not report success.
 */
static char test_gen_malformed_container_boundaries(void)
{
	struct IFF_Parser_Factory *pf = 0;
	struct IFF_Parser *parser = 0;
	struct VPS_Data wrap;
	char result = 0;

	/* "FORM" + size 0: no room for the type tag. */
	unsigned char zero_size_form[] =
	{
		'F', 'O', 'R', 'M', 0x00, 0x00, 0x00, 0x00
	};

	/* "FORM" + size 20 + type "ILBM": 16 more content bytes are declared
	 * but the stream ends here. */
	unsigned char truncated_form[] =
	{
		'F', 'O', 'R', 'M', 0x00, 0x00, 0x00, 0x14,
		'I', 'L', 'B', 'M'
	};

	if (!IFF_Parser_Factory_Allocate(&pf)) goto cleanup;
	if (!IFF_Parser_Factory_Construct(pf)) goto cleanup;

	wrap = PRIVATE_Wrap(zero_size_form, sizeof(zero_size_form));
	if (!IFF_Parser_Factory_CreateFromData(pf, &wrap, &parser)) goto cleanup;
	TEST_ASSERT(!IFF_Parser_Scan(parser));
	IFF_Parser_Release(parser);
	parser = 0;

	wrap = PRIVATE_Wrap(truncated_form, sizeof(truncated_form));
	if (!IFF_Parser_Factory_CreateFromData(pf, &wrap, &parser)) goto cleanup;
	TEST_ASSERT(!IFF_Parser_Scan(parser));

	result = 1;

cleanup:
	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(pf);
	return result;
}

void test_suite_generate_checksum_advanced(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_gen_checksum_nested);
	RUN_TEST(test_gen_checksum_multiple_algorithms);
	RUN_TEST(test_gen_checksum_binary_layout_chk);
	RUN_TEST(test_gen_checksum_binary_layout_sum);
	RUN_TEST(test_gen_checksum_nested_progressive);
	RUN_TEST(test_gen_malformed_container_boundaries);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
