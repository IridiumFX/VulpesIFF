#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Result.h>

#include "ILBM/ILBM_Decompression.h"
#include "ILBM/ILBM_Conversion.h"
#include "SVX8/SVX8_Decompression.h"

#include "Test.h"

/*
 * Unit coverage for the codec primitives: the two decompressors and the four
 * ILBM colour conversions. These are pure functions over caller-owned buffers,
 * so they can be driven directly with hand-built inputs.
 */

/* ================================================================== */
/*  ByteRun1 (ILBM BODY compression)                                   */
/* ================================================================== */

/*
 * Test C1: literal runs, replicate runs and the NOP opcode.
 *
 *   0x02 'A' 'B' 'C'  -> literal run of 3
 *   0xFD 'Z'          -> replicate 'Z' four times (-(-3) + 1)
 *   0x80              -> NOP, consumes nothing
 *   0x00 'Q'          -> literal run of 1
 */
static char test_byterun1_opcodes(void)
{
	const VPS_TYPE_8U src[] =
	{
		0x02, 'A', 'B', 'C',
		0xFD, 'Z',
		0x80,
		0x00, 'Q'
	};
	VPS_TYPE_8U dest[8];

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_DecompressByteRun1(dest, src, sizeof(src), sizeof(dest)));
	TEST_ASSERT(memcmp(dest, "ABCZZZZQ", 8) == 0);

	return 1;
}

/*
 * Test C2: a source that cannot fill the destination is a truncated stream.
 * The decoder must report it rather than leaving the tail uninitialised.
 */
static char test_byterun1_truncated_source(void)
{
	const VPS_TYPE_8U src[] = { 0x02, 'A', 'B', 'C' };
	VPS_TYPE_8U dest[16];

	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(dest, src, sizeof(src), sizeof(dest)));

	return 1;
}

/* Test C3: a run that would overrun the destination is rejected. */
static char test_byterun1_dest_overrun(void)
{
	const VPS_TYPE_8U literal[] = { 0x07, 1, 2, 3, 4, 5, 6, 7, 8 };
	const VPS_TYPE_8U replicate[] = { 0xF9, 'Z' }; /* -7 -> 8 copies */
	VPS_TYPE_8U dest[4];

	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(dest, literal, sizeof(literal), sizeof(dest)));
	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(dest, replicate, sizeof(replicate), sizeof(dest)));

	return 1;
}

/* Test C4: a literal run whose payload is cut short is rejected. */
static char test_byterun1_literal_past_source(void)
{
	const VPS_TYPE_8U src[] = { 0x07, 'A', 'B' }; /* claims 8 bytes, supplies 2 */
	VPS_TYPE_8U dest[8];

	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(dest, src, sizeof(src), sizeof(dest)));

	return 1;
}

/* Test C5: null buffers are rejected rather than dereferenced. */
static char test_byterun1_null_arguments(void)
{
	const VPS_TYPE_8U src[] = { 0x00, 'A' };
	VPS_TYPE_8U dest[1];

	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(NULL, src, sizeof(src), 1));
	TEST_ASSERT_FAIL(ILBM_DecompressByteRun1(dest, NULL, 2, 1));

	return 1;
}

/* ================================================================== */
/*  Fibonacci delta (8SVX BODY compression)                            */
/* ================================================================== */

/*
 * Test C6: decode against the standard delta table.
 *
 * src[0] is a pad byte, src[1] the initial accumulator. Each following byte
 * carries two nibbles, high first, each indexing the table:
 *
 *   { -34, -21, -13, -8, -5, -3, -2, -1, 0, 1, 2, 3, 5, 8, 13, 21 }
 *
 *   0x9A -> +1 then +2   : 1, 3
 *   0x08 -> -34 then +0  : 225 (-31 as unsigned), 225
 */
static char test_fibonacci_known_deltas(void)
{
	const VPS_TYPE_8U src[] = { 0x00, 0x00, 0x9A, 0x08 };
	const VPS_TYPE_8U want[] = { 1, 3, 225, 225 };
	VPS_TYPE_8U dest[4];

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(SVX8_DecompressFibonacciDelta(dest, src, sizeof(src), 4));
	TEST_ASSERT(memcmp(dest, want, sizeof(want)) == 0);

	return 1;
}

/* Test C7: the initial accumulator in src[1] seeds the running sum. */
static char test_fibonacci_seed_byte(void)
{
	/* Seed 100, then +1 (nibble 9) and +2 (nibble 10). */
	const VPS_TYPE_8U src[] = { 0x00, 100, 0x9A };
	VPS_TYPE_8U dest[2];

	TEST_ASSERT_OK(SVX8_DecompressFibonacciDelta(dest, src, sizeof(src), 2));
	TEST_ASSERT(dest[0] == 101);
	TEST_ASSERT(dest[1] == 103);

	return 1;
}

/* Test C8: a source too short to produce every sample is a failure. */
static char test_fibonacci_truncated_source(void)
{
	const VPS_TYPE_8U src[] = { 0x00, 0x00, 0x9A };

	VPS_TYPE_8U dest[64];

	TEST_ASSERT_FAIL(SVX8_DecompressFibonacciDelta(dest, src, sizeof(src), 40));

	return 1;
}

/* Test C9: a source with no room for the two-byte header is rejected. */
static char test_fibonacci_missing_header(void)
{
	const VPS_TYPE_8U src[] = { 0x00 };
	VPS_TYPE_8U dest[4];

	TEST_ASSERT_FAIL(SVX8_DecompressFibonacciDelta(dest, src, 1, 2));
	TEST_ASSERT_FAIL(SVX8_DecompressFibonacciDelta(dest, src, 0, 2));
	TEST_ASSERT_FAIL(SVX8_DecompressFibonacciDelta(NULL, src, 4, 2));

	return 1;
}

void test_suite_codec_primitives(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_byterun1_opcodes);
	RUN_TEST(test_byterun1_truncated_source);
	RUN_TEST(test_byterun1_dest_overrun);
	RUN_TEST(test_byterun1_literal_past_source);
	RUN_TEST(test_byterun1_null_arguments);
	RUN_TEST(test_fibonacci_known_deltas);
	RUN_TEST(test_fibonacci_seed_byte);
	RUN_TEST(test_fibonacci_truncated_source);
	RUN_TEST(test_fibonacci_missing_header);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
