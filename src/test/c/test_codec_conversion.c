#include <stdio.h>
#include <string.h>

#include <vulpes/VPS_Types.h>

#include <IFF/IFF_Result.h>

#include "ILBM/ILBM_Conversion.h"

#include "Test.h"

/*
 * Coverage for the four ILBM colour conversions.
 *
 * All of them read interleaved planar data through the same addressing:
 * a row is ((w + 15) / 16) * 2 bytes per plane, and the planes for one row
 * sit consecutively. Every image below is 16 pixels wide so a row is exactly
 * two bytes per plane, which keeps the hand-built bit patterns readable.
 *
 * Bit order within a byte is MSB-first: pixel x uses bit (7 - (x & 7)).
 */

#define PIX(dest, w, x, y) ((dest) + (((VPS_TYPE_SIZE)(y) * (w) + (x)) * 4))

static char rgba_is(const VPS_TYPE_8U *p, int r, int g, int b)
{
	return p[0] == r && p[1] == g && p[2] == b && p[3] == 255;
}

/*
 * Test V1: one bitplane selects between two palette entries.
 *
 *   row 0: 0xFF 0x00  -> colour 1 for x 0-7, colour 0 for x 8-15
 *   row 1: 0x00 0xFF  -> the reverse
 */
static char test_planar_single_plane(void)
{
	const VPS_TYPE_8U body[] = { 0xFF, 0x00, 0x00, 0xFF };
	const VPS_TYPE_8U cmap[] = { 10, 20, 30, 40, 50, 60 };
	VPS_TYPE_8U dest[16 * 2 * 4];

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertPlanarToRGBA(dest, body, 16, 2, 1, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 40, 50, 60));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 8, 0), 10, 20, 30));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 1), 10, 20, 30));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 8, 1), 40, 50, 60));

	return 1;
}

/*
 * Test V2: plane N contributes bit N of the colour index.
 *
 *   plane 0: 0xF0 -> set for x 0-3
 *   plane 1: 0xCC -> set for x 0,1 and x 4,5
 *
 * so x=0 -> 3, x=2 -> 1, x=4 -> 2, x=8 -> 0.
 */
static char test_planar_plane_weighting(void)
{
	const VPS_TYPE_8U body[] = { 0xF0, 0x00, 0xCC, 0x00 };
	const VPS_TYPE_8U cmap[] =
	{
		0, 0, 0,        /* 0 */
		1, 1, 1,        /* 1 */
		2, 2, 2,        /* 2 */
		3, 3, 3         /* 3 */
	};
	VPS_TYPE_8U dest[16 * 4];

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertPlanarToRGBA(dest, body, 16, 1, 2, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 3, 3, 3));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 2, 0), 1, 1, 1));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 4, 0), 2, 2, 2));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 8, 0), 0, 0, 0));

	return 1;
}

/* Test V3: an index past the end of the palette renders opaque black. */
static char test_planar_index_past_palette(void)
{
	const VPS_TYPE_8U body[] = { 0xFF, 0x00 };
	const VPS_TYPE_8U cmap[] = { 99, 99, 99 };  /* one entry: index 0 only */
	VPS_TYPE_8U dest[16 * 4];

	memset(dest, 0xAA, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertPlanarToRGBA(dest, body, 16, 1, 1, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 0, 0, 0));    /* index 1: absent */
	TEST_ASSERT(rgba_is(PIX(dest, 16, 8, 0), 99, 99, 99)); /* index 0: present */

	return 1;
}

/*
 * Test V4: Extra Half-Brite. Bit 5 of the index halves the base colour.
 *
 *   x=0 -> index 1  (plane 0)
 *   x=1 -> index 33 (planes 0 and 5) -> base 1, halved
 */
static char test_ehb_halves_upper_bank(void)
{
	VPS_TYPE_8U body[6 * 2];
	VPS_TYPE_8U cmap[32 * 3];
	VPS_TYPE_8U dest[16 * 4];

	memset(body, 0, sizeof(body));
	body[0 * 2] = 0xC0; /* plane 0: x=0 and x=1 */
	body[5 * 2] = 0x40; /* plane 5: x=1 only    */

	memset(cmap, 0, sizeof(cmap));
	cmap[1 * 3 + 0] = 200;
	cmap[1 * 3 + 1] = 100;
	cmap[1 * 3 + 2] = 50;

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertEHBToRGBA(dest, body, 16, 1, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 200, 100, 50));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 1, 0), 100, 50, 25));

	return 1;
}

/* Test V5: EHB needs a full 32-entry palette. */
static char test_ehb_rejects_short_palette(void)
{
	VPS_TYPE_8U body[6 * 2] = { 0 };
	VPS_TYPE_8U cmap[16 * 3] = { 0 };
	VPS_TYPE_8U dest[16 * 4];

	TEST_ASSERT_FAIL(ILBM_ConvertEHBToRGBA(dest, body, 16, 1, cmap, sizeof(cmap)));

	return 1;
}

/*
 * Test V6: HAM6 holds the previous colour and modifies one channel.
 *
 *   x=0: 0x02 -> control 0, load palette entry 2
 *   x=1: 0x1F -> control 1, blue  = 0xFF
 *   x=2: 0x2A -> control 2, red   = 0xAA
 *   x=3: 0x35 -> control 3, green = 0x55
 *
 * Each pixel keeps the channels the previous one left alone, which is what
 * makes this mode worth testing across a run rather than per pixel.
 */
static char test_ham6_hold_and_modify(void)
{
	VPS_TYPE_8U body[6 * 2];
	VPS_TYPE_8U cmap[16 * 3];
	VPS_TYPE_8U dest[16 * 4];

	memset(body, 0, sizeof(body));
	body[0 * 2] = 0x50; /* plane 0: x=1, x=3       */
	body[1 * 2] = 0xE0; /* plane 1: x=0, x=1, x=2  */
	body[2 * 2] = 0x50; /* plane 2: x=1, x=3       */
	body[3 * 2] = 0x60; /* plane 3: x=1, x=2       */
	body[4 * 2] = 0x50; /* plane 4: x=1, x=3       */
	body[5 * 2] = 0x30; /* plane 5: x=2, x=3       */

	memset(cmap, 0, sizeof(cmap));
	cmap[2 * 3 + 0] = 11;
	cmap[2 * 3 + 1] = 22;
	cmap[2 * 3 + 2] = 33;

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertHAM6ToRGBA(dest, body, 16, 1, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 11, 22, 33));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 1, 0), 11, 22, 255));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 2, 0), 170, 22, 255));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 3, 0), 170, 85, 255));

	return 1;
}

/*
 * Test V7: HAM8 uses two control bits and a six-bit payload, scaled by 4.
 *
 *   x=0: 0x03 -> control 0, load palette entry 3
 *   x=1: 0x7F -> control 1, blue  = 0x3F << 2
 *   x=2: 0xBF -> control 2, red   = 0x3F << 2
 *   x=3: 0xFF -> control 3, green = 0x3F << 2
 */
static char test_ham8_hold_and_modify(void)
{
	VPS_TYPE_8U body[8 * 2];
	VPS_TYPE_8U cmap[64 * 3];
	VPS_TYPE_8U dest[16 * 4];

	memset(body, 0, sizeof(body));
	body[0 * 2] = 0xF0; /* planes 0,1: x=0..3      */
	body[1 * 2] = 0xF0;
	body[2 * 2] = 0x70; /* planes 2..5: x=1,2,3    */
	body[3 * 2] = 0x70;
	body[4 * 2] = 0x70;
	body[5 * 2] = 0x70;
	body[6 * 2] = 0x50; /* plane 6: x=1, x=3       */
	body[7 * 2] = 0x30; /* plane 7: x=2, x=3       */

	memset(cmap, 0, sizeof(cmap));
	cmap[3 * 3 + 0] = 7;
	cmap[3 * 3 + 1] = 8;
	cmap[3 * 3 + 2] = 9;

	memset(dest, 0, sizeof(dest));

	TEST_ASSERT_OK(ILBM_ConvertHAM8ToRGBA(dest, body, 16, 1, cmap, sizeof(cmap)));

	TEST_ASSERT(rgba_is(PIX(dest, 16, 0, 0), 7, 8, 9));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 1, 0), 7, 8, 252));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 2, 0), 252, 8, 252));
	TEST_ASSERT(rgba_is(PIX(dest, 16, 3, 0), 252, 252, 252));

	return 1;
}

/* Test V8: every conversion rejects null buffers. */
static char test_conversions_reject_null(void)
{
	VPS_TYPE_8U buf[64 * 3] = { 0 };

	TEST_ASSERT_FAIL(ILBM_ConvertPlanarToRGBA(NULL, buf, 16, 1, 1, buf, sizeof(buf)));
	TEST_ASSERT_FAIL(ILBM_ConvertPlanarToRGBA(buf, NULL, 16, 1, 1, buf, sizeof(buf)));
	TEST_ASSERT_FAIL(ILBM_ConvertPlanarToRGBA(buf, buf, 16, 1, 1, NULL, 0));
	TEST_ASSERT_FAIL(ILBM_ConvertEHBToRGBA(NULL, buf, 16, 1, buf, sizeof(buf)));
	TEST_ASSERT_FAIL(ILBM_ConvertHAM6ToRGBA(NULL, buf, 16, 1, buf, sizeof(buf)));
	TEST_ASSERT_FAIL(ILBM_ConvertHAM8ToRGBA(NULL, buf, 16, 1, buf, sizeof(buf)));

	return 1;
}

void test_suite_codec_conversion(void)
{
	int success_count = 0;
	int failure_count = 0;

	RUN_TEST(test_planar_single_plane);
	RUN_TEST(test_planar_plane_weighting);
	RUN_TEST(test_planar_index_past_palette);
	RUN_TEST(test_ehb_halves_upper_bank);
	RUN_TEST(test_ehb_rejects_short_palette);
	RUN_TEST(test_ham6_hold_and_modify);
	RUN_TEST(test_ham8_hold_and_modify);
	RUN_TEST(test_conversions_reject_null);

	printf("\n  Results: %d passed, %d failed\n", success_count, failure_count);
}
