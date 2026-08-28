#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vulpes/VPS_Types.h>
#include <vulpes/VPS_Data.h>

#include <IFF/IFF_Result.h>
#include <IFF/IFF_Header.h>
#include <IFF/IFF_Tag.h>
#include <IFF/IFF_Parser.h>
#include <IFF/IFF_Parser_Session.h>
#include <IFF/IFF_Parser_Factory.h>

#include "SVX8/SVX8_Types.h"
#include "SVX8/SVX8_Codec.h"

#include "Test.h"
#include "IFF_TestBuilder.h"

/*
 * End-to-end coverage for the 8SVX codec.
 *
 * SVX8 only ships a load-from-file entry point, so these drive the parser
 * directly the way that loader does: register the decoders, scan an in-memory
 * image, and take ownership of the final entity.
 */

/* Fills a 20-byte VHDR. */
static void build_vhdr
(
	VPS_TYPE_8U *out
	, VPS_TYPE_32U one_shot
	, VPS_TYPE_16U rate
	, VPS_TYPE_8U compression
)
{
	memset(out, 0, 20);
	out[0]  = (VPS_TYPE_8U)(one_shot >> 24);
	out[1]  = (VPS_TYPE_8U)(one_shot >> 16);
	out[2]  = (VPS_TYPE_8U)(one_shot >> 8);
	out[3]  = (VPS_TYPE_8U)(one_shot);
	/* repeatHiSamples and samplesPerHiCycle stay zero */
	out[12] = (VPS_TYPE_8U)(rate >> 8);
	out[13] = (VPS_TYPE_8U)(rate & 0xFF);
	out[14] = 1;              /* ctOctave */
	out[15] = compression;
	out[16] = 0x00;           /* volume 0x00010000 */
	out[17] = 0x01;
	out[18] = 0x00;
	out[19] = 0x00;
}

/*
 * Scans an in-memory 8SVX image and hands back the decoded result.
 * Returns IFF_OK when the parse succeeded; out_result may still be NULL if
 * the codec declined to produce an entity.
 */
static IFF_TYPE_RESULT decode_svx8
(
	const struct VPS_Data *image
	, struct SVX8_Result **out_result
)
{
	struct IFF_Parser_Factory *factory = 0;
	struct IFF_Parser *parser = 0;
	IFF_TYPE_RESULT result;

	*out_result = 0;

	if (IFF_Parser_Factory_Allocate(&factory)) return IFF_FAIL;
	if (IFF_Parser_Factory_Construct(factory))
	{
		IFF_Parser_Factory_Release(factory);
		return IFF_FAIL;
	}

	if (SVX8_RegisterDecoders(factory))
	{
		IFF_Parser_Factory_Release(factory);
		return IFF_FAIL;
	}

	if (IFF_Parser_Factory_CreateFromData(factory, image, &parser))
	{
		IFF_Parser_Factory_Release(factory);
		return IFF_FAIL;
	}

	result = IFF_Parser_Scan(parser);

	if (!result)
	{
		*out_result = (struct SVX8_Result *)parser->session->final_entity;
		parser->session->final_entity = 0;  /* take ownership */
	}

	IFF_Parser_Release(parser);
	IFF_Parser_Factory_Release(factory);

	return result;
}

static void release_svx8(struct SVX8_Result *r)
{
	if (!r) return;

	if (r->samples)
	{
		VPS_Data_Release(r->samples);
	}
	free(r);
}

/*
 * Test A1: an uncompressed 8SVX decodes its header and samples verbatim.
 *
 *   FORM 8SVX
 *     VHDR  4 one-shot samples at 8000 Hz, no compression
 *     BODY  four signed 8-bit samples
 */
static char test_svx8_uncompressed(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct SVX8_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U vhdr[20];
	const VPS_TYPE_8U body[4] = { 0x00, 0x40, 0x80, 0xC0 };

	build_vhdr(vhdr, 4, 8000, 0);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr, sizeof(vhdr))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BODY", body, sizeof(body))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	TEST_ASSERT_OK(decode_svx8(image, &result));

	TEST_ASSERT(result != 0);
	TEST_ASSERT(result->vhdr.oneShotHiSamples == 4);
	TEST_ASSERT(result->vhdr.samplesPerSec == 8000);
	TEST_ASSERT(result->vhdr.sCompression == 0);
	TEST_ASSERT(result->vhdr.volume == 0x00010000);

	TEST_ASSERT(result->samples != 0);
	TEST_ASSERT(result->samples->limit == 4);
	TEST_ASSERT(memcmp(result->samples->bytes, body, 4) == 0);

	verdict = 1;

cleanup:

	release_svx8(result);
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/*
 * Test A2: a Fibonacci-delta 8SVX expands through the decompressor.
 *
 * BODY is a 2-byte header (pad, seed) followed by nibble pairs:
 *   0x9A -> +1 then +2 from a seed of 0  : 1, 3
 *   0x08 -> -34 then +0                  : 225, 225
 */
static char test_svx8_fibonacci_compressed(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct SVX8_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U vhdr[20];
	const VPS_TYPE_8U body[4] = { 0x00, 0x00, 0x9A, 0x08 };
	const VPS_TYPE_8U want[4] = { 1, 3, 225, 225 };

	build_vhdr(vhdr, 4, 8000, 1);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr, sizeof(vhdr))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BODY", body, sizeof(body))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	TEST_ASSERT_OK(decode_svx8(image, &result));

	TEST_ASSERT(result != 0);
	TEST_ASSERT(result->vhdr.sCompression == 1);
	TEST_ASSERT(result->samples != 0);
	TEST_ASSERT(result->samples->limit == 4);
	TEST_ASSERT(memcmp(result->samples->bytes, want, 4) == 0);

	verdict = 1;

cleanup:

	release_svx8(result);
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/* Test A3: an 8SVX with no BODY yields no entity. */
static char test_svx8_missing_body(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct SVX8_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U vhdr[20];

	build_vhdr(vhdr, 4, 8000, 0);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "8SVX")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "VHDR", vhdr, sizeof(vhdr))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	TEST_ASSERT_OK(decode_svx8(image, &result));
	TEST_ASSERT(result == 0);

	verdict = 1;

cleanup:

	release_svx8(result);
	IFF_TestBuilder_Release(builder);

	return verdict;
}

void test_suite_codec_audio(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_svx8_uncompressed);
	RUN_TEST(test_svx8_fibonacci_compressed);
	RUN_TEST(test_svx8_missing_body);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
