#pragma once
#include <vulpes/VPS_Types.h>

/**
 * @brief Converts interleaved planar bitmap data to RGBA8888.
 *
 * @param dest Destination RGBA buffer (w * h * 4 bytes).
 * @param src Source interleaved planar data.
 * @param w Width in pixels.
 * @param h Height in pixels.
 * @param nPlanes Number of bitplanes.
 * @param cmap Color palette (RGB triplets).
 * @param cmap_size Size of cmap in bytes.
 * @return 1 on success, 0 on failure.
 */
char ILBM_ConvertPlanarToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h, int nPlanes,
	const VPS_TYPE_8U* cmap,
	int cmap_size
);

/** @brief Extra Half-Brite mode (6 planes, 64 colors with dim halves). */
char ILBM_ConvertEHBToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
);

/** @brief Hold-And-Modify 6-bit mode (6 planes). */
char ILBM_ConvertHAM6ToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
);

/** @brief Hold-And-Modify 8-bit mode (8 planes). */
char ILBM_ConvertHAM8ToRGBA
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	int w, int h,
	const VPS_TYPE_8U* cmap,
	int cmap_size
);
