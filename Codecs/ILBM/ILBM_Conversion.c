#include "ILBM/ILBM_Conversion.h"

/*
 * Amiga ILBM planar bitmap layout:
 *
 * For interleaved mode, rows alternate between bitplanes:
 *   Row 0, Plane 0 | Row 0, Plane 1 | ... | Row 0, Plane N-1
 *   Row 1, Plane 0 | Row 1, Plane 1 | ...
 *
 * Each row is padded to a 16-bit word boundary.
 * row_bytes = ((w + 15) / 16) * 2
 */

/* Row bytes for a given width (word-aligned). */
static int row_bytes(int w)
{
	return ((w + 15) / 16) * 2;
}

/* Read a single pixel's color index from interleaved planar data. */
static VPS_TYPE_8U read_planar_pixel
(
	const VPS_TYPE_8U* src,
	int x, int y, int w, int nPlanes
)
{
	int rb = row_bytes(w);
	int byte_idx = x >> 3;
	int bit_pos = 7 - (x & 7);
	VPS_TYPE_8U color_idx = 0;

	/* Interleaved: plane data for row y is at offset y * (rb * nPlanes) + plane * rb. */
	for (int plane = 0; plane < nPlanes; plane++)
	{
		const VPS_TYPE_8U* plane_row = src + (VPS_TYPE_SIZE)y * rb * nPlanes + (VPS_TYPE_SIZE)plane * rb;
		if (plane_row[byte_idx] & (1 << bit_pos))
			color_idx |= (VPS_TYPE_8U)(1 << plane);
	}

	return color_idx;
}

char ILBM_ConvertPlanarToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h, int nPlanes,
	const VPS_TYPE_8U* cmap,
	int cmap_size
)
{
	if (!dest || !src || !cmap) return 0;
	int max_colors = cmap_size / 3;

	for (int y = 0; y < h; y++)
	{
		for (int x = 0; x < w; x++)
		{
			VPS_TYPE_8U ci = read_planar_pixel(src, x, y, w, nPlanes);
			int o = (y * w + x) * 4;

			if (ci < max_colors)
			{
				dest[o + 0] = cmap[ci * 3 + 0];
				dest[o + 1] = cmap[ci * 3 + 1];
				dest[o + 2] = cmap[ci * 3 + 2];
			}
			else
			{
				dest[o + 0] = dest[o + 1] = dest[o + 2] = 0;
			}
			dest[o + 3] = 255;
		}
	}

	return 1;
}

char ILBM_ConvertEHBToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
)
{
	if (!dest || !src || !cmap || cmap_size < 32 * 3) return 0;

	for (int y = 0; y < h; y++)
	{
		for (int x = 0; x < w; x++)
		{
			VPS_TYPE_8U ci = read_planar_pixel(src, x, y, w, 6);
			VPS_TYPE_8U base = ci & 31;
			VPS_TYPE_8U r = cmap[base * 3 + 0];
			VPS_TYPE_8U g = cmap[base * 3 + 1];
			VPS_TYPE_8U b = cmap[base * 3 + 2];

			if (ci & 32) { r /= 2; g /= 2; b /= 2; }

			int o = (y * w + x) * 4;
			dest[o + 0] = r; dest[o + 1] = g; dest[o + 2] = b; dest[o + 3] = 255;
		}
	}

	return 1;
}

char ILBM_ConvertHAM6ToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
)
{
	if (!dest || !src || !cmap || cmap_size < 16 * 3) return 0;

	for (int y = 0; y < h; y++)
	{
		VPS_TYPE_8U lr = 0, lg = 0, lb = 0;

		for (int x = 0; x < w; x++)
		{
			VPS_TYPE_8U ci = read_planar_pixel(src, x, y, w, 6);
			int ctrl = ci >> 4;
			VPS_TYPE_8U data = ci & 0x0F;

			switch (ctrl)
			{
			case 0:
				lr = cmap[data * 3 + 0];
				lg = cmap[data * 3 + 1];
				lb = cmap[data * 3 + 2];
				break;
			case 1: lb = (VPS_TYPE_8U)(data << 4 | data); break;
			case 2: lr = (VPS_TYPE_8U)(data << 4 | data); break;
			case 3: lg = (VPS_TYPE_8U)(data << 4 | data); break;
			}

			int o = (y * w + x) * 4;
			dest[o + 0] = lr; dest[o + 1] = lg; dest[o + 2] = lb; dest[o + 3] = 255;
		}
	}

	return 1;
}

char ILBM_ConvertHAM8ToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
)
{
	if (!dest || !src || !cmap || cmap_size < 64 * 3) return 0;

	for (int y = 0; y < h; y++)
	{
		VPS_TYPE_8U lr = 0, lg = 0, lb = 0;

		for (int x = 0; x < w; x++)
		{
			VPS_TYPE_8U ci = read_planar_pixel(src, x, y, w, 8);
			int ctrl = (ci >> 6) & 0x03;
			VPS_TYPE_8U data = ci & 0x3F;

			switch (ctrl)
			{
			case 0:
				lr = cmap[data * 3 + 0];
				lg = cmap[data * 3 + 1];
				lb = cmap[data * 3 + 2];
				break;
			case 1: lb = (VPS_TYPE_8U)(data << 2); break;
			case 2: lr = (VPS_TYPE_8U)(data << 2); break;
			case 3: lg = (VPS_TYPE_8U)(data << 2); break;
			}

			int o = (y * w + x) * 4;
			dest[o + 0] = lr; dest[o + 1] = lg; dest[o + 2] = lb; dest[o + 3] = 255;
		}
	}

	return 1;
}
