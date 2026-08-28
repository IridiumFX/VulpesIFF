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

#include "ILBM/ILBM_Types.h"
#include "ILBM/ILBM_Codec.h"
#include "ILBM/ILBM_Loader.h"
#include "SVX8/SVX8_Types.h"
#include "SVX8/SVX8_Codec.h"

#include "Test.h"
#include "IFF_TestBuilder.h"

/*
 * End-to-end coverage: build a real IFF image with the test builder, run it
 * through the real parser with the codec decoders registered, and check the
 * decoded result. This is the path the loaders take, so it exercises chunk
 * routing, the form decoder lifecycle and the decompressors together.
 */

/* Fills a 20-byte BMHD. Only the fields the decoder reads are meaningful. */
static void build_bmhd
(
	VPS_TYPE_8U *out
	, VPS_TYPE_16U w
	, VPS_TYPE_16U h
	, VPS_TYPE_8U planes
	, VPS_TYPE_8U compression
)
{
	memset(out, 0, 20);
	out[0] = (VPS_TYPE_8U)(w >> 8);  out[1] = (VPS_TYPE_8U)(w & 0xFF);
	out[2] = (VPS_TYPE_8U)(h >> 8);  out[3] = (VPS_TYPE_8U)(h & 0xFF);
	/* x and y stay zero */
	out[8]  = planes;
	out[9]  = 0;            /* masking */
	out[10] = compression;
}

static char rgba_is(const VPS_TYPE_8U *p, int r, int g, int b)
{
	return p[0] == r && p[1] == g && p[2] == b && p[3] == 255;
}

/*
 * Test I1: an uncompressed ILBM decodes to the expected RGBA pixels.
 *
 *   FORM ILBM
 *     BMHD  16x2, 1 plane, uncompressed
 *     CMAP  two colours
 *     BODY  row 0 = colour 1 then colour 0, row 1 = the reverse
 */
static char test_ilbm_uncompressed_image(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct ILBM_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U bmhd[20];
	const VPS_TYPE_8U cmap[6] = { 10, 20, 30, 40, 50, 60 };
	const VPS_TYPE_8U body[4] = { 0xFF, 0x00, 0x00, 0xFF };

	build_bmhd(bmhd, 16, 2, 1, 0);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd, sizeof(bmhd))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "CMAP", cmap, sizeof(cmap))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BODY", body, sizeof(body))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	result = VPS_ILBM_LoadFromData(image);

	TEST_ASSERT(result != 0);
	TEST_ASSERT(result->width == 16);
	TEST_ASSERT(result->height == 2);
	TEST_ASSERT(result->pixels != 0);

	TEST_ASSERT(rgba_is(result->pixels + ((0 * 16) + 0) * 4, 40, 50, 60));
	TEST_ASSERT(rgba_is(result->pixels + ((0 * 16) + 8) * 4, 10, 20, 30));
	TEST_ASSERT(rgba_is(result->pixels + ((1 * 16) + 0) * 4, 10, 20, 30));
	TEST_ASSERT(rgba_is(result->pixels + ((1 * 16) + 8) * 4, 40, 50, 60));

	verdict = 1;

cleanup:

	if (result)
	{
		free(result->pixels);
		free(result);
	}
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/*
 * Test I2: the same image ByteRun1-compressed decodes identically.
 *
 * This is the only coverage of the decompressor inside the real decode path:
 * the BODY here is compressed, so ilbm_end must expand it before converting.
 *
 *   0x01 0xFF 0x00  -> literal run of 2 (row 0)
 *   0x01 0x00 0xFF  -> literal run of 2 (row 1)
 */
static char test_ilbm_byterun1_image(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct ILBM_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U bmhd[20];
	const VPS_TYPE_8U cmap[6] = { 10, 20, 30, 40, 50, 60 };
	const VPS_TYPE_8U body[6] = { 0x01, 0xFF, 0x00, 0x01, 0x00, 0xFF };

	build_bmhd(bmhd, 16, 2, 1, 1);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd, sizeof(bmhd))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "CMAP", cmap, sizeof(cmap))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BODY", body, sizeof(body))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	result = VPS_ILBM_LoadFromData(image);

	TEST_ASSERT(result != 0);
	TEST_ASSERT(result->width == 16);
	TEST_ASSERT(result->height == 2);

	TEST_ASSERT(rgba_is(result->pixels + ((0 * 16) + 0) * 4, 40, 50, 60));
	TEST_ASSERT(rgba_is(result->pixels + ((0 * 16) + 8) * 4, 10, 20, 30));
	TEST_ASSERT(rgba_is(result->pixels + ((1 * 16) + 0) * 4, 10, 20, 30));
	TEST_ASSERT(rgba_is(result->pixels + ((1 * 16) + 8) * 4, 40, 50, 60));

	verdict = 1;

cleanup:

	if (result)
	{
		free(result->pixels);
		free(result);
	}
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/*
 * Test I3: a BODY shorter than the header declares yields no entity rather
 * than over-reading the buffer. The parse itself still succeeds: a malformed
 * payload is a codec concern, not a container one.
 */
static char test_ilbm_short_body_yields_no_entity(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct ILBM_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U bmhd[20];
	const VPS_TYPE_8U cmap[6] = { 1, 2, 3, 4, 5, 6 };
	const VPS_TYPE_8U body[2] = { 0xFF, 0x00 };  /* needs 4 for 16x2x1 */

	build_bmhd(bmhd, 16, 2, 1, 0);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd, sizeof(bmhd))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "CMAP", cmap, sizeof(cmap))) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BODY", body, sizeof(body))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	result = VPS_ILBM_LoadFromData(image);

	TEST_ASSERT(result == 0);

	verdict = 1;

cleanup:

	if (result)
	{
		free(result->pixels);
		free(result);
	}
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/* Test I4: an ILBM with no BODY at all yields no entity. */
static char test_ilbm_missing_body_yields_no_entity(void)
{
	struct IFF_TestBuilder *builder = 0;
	struct VPS_Data *image = 0;
	struct ILBM_Result *result = 0;
	char verdict = 0;

	VPS_TYPE_8U bmhd[20];

	build_bmhd(bmhd, 16, 2, 1, 0);

	if (IFF_TestBuilder_Allocate(&builder)) return 0;
	if (IFF_TestBuilder_Construct(builder)) goto cleanup;

	if (IFF_TestBuilder_BeginContainer(builder, "FORM", "ILBM")) goto cleanup;
	if (IFF_TestBuilder_AddChunk(builder, "BMHD", bmhd, sizeof(bmhd))) goto cleanup;
	if (IFF_TestBuilder_EndContainer(builder)) goto cleanup;
	if (IFF_TestBuilder_GetResult(builder, &image)) goto cleanup;

	result = VPS_ILBM_LoadFromData(image);

	TEST_ASSERT(result == 0);

	verdict = 1;

cleanup:

	if (result)
	{
		free(result->pixels);
		free(result);
	}
	IFF_TestBuilder_Release(builder);

	return verdict;
}

/* Test I5: registration refuses a null factory. */
static char test_register_decoders_reject_null(void)
{
	TEST_ASSERT_FAIL(ILBM_RegisterDecoders(0));
	TEST_ASSERT_FAIL(SVX8_RegisterDecoders(0));

	return 1;
}

void test_suite_codec_images(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_ilbm_uncompressed_image);
	RUN_TEST(test_ilbm_byterun1_image);
	RUN_TEST(test_ilbm_short_body_yields_no_entity);
	RUN_TEST(test_ilbm_missing_body_yields_no_entity);
	RUN_TEST(test_register_decoders_reject_null);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
