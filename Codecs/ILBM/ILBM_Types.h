#pragma once
#include <vulpes/VPS_Types.h>

struct VPS_Data;

#define ILBM_MAX_PALETTE 256

/* BMHD chunk: bitmap header. All fields stored big-endian in the IFF file. */
struct ILBM_BitMapHeader
{
	VPS_TYPE_16U w, h;                /* Width, height in pixels. */
	VPS_TYPE_16S x, y;                /* Position on screen. */
	VPS_TYPE_8U  nPlanes;             /* Number of bitplanes (1..24). */
	VPS_TYPE_8U  masking;             /* 0=none, 1=mask, 2=transparent, 3=lasso. */
	VPS_TYPE_8U  compression;         /* 0=none, 1=ByteRun1. */
	VPS_TYPE_8U  pad1;
	VPS_TYPE_16U transparentColor;
	VPS_TYPE_8U  xAspect, yAspect;
	VPS_TYPE_16S pageWidth, pageHeight;
};

/* CMAP chunk: color register (RGB triplet). */
struct ILBM_ColorRegister
{
	VPS_TYPE_8U r, g, b;
};

/* CAMG chunk: Amiga viewmode flags. */
#define ILBM_CAMG_HAM    0x0800
#define ILBM_CAMG_EHB    0x0080
#define ILBM_CAMG_HIRES  0x8000
#define ILBM_CAMG_LACE   0x0004

/* Intermediate state assembled by the ILBM FormDecoder (internal). */
struct ILBM_State
{
	struct ILBM_BitMapHeader bmhd;
	struct ILBM_ColorRegister palette[ILBM_MAX_PALETTE];
	VPS_TYPE_16U palette_size;
	VPS_TYPE_32U camg_mode;
	char has_bmhd;
	char has_body;
	struct VPS_Data* body_data; /* Raw (possibly compressed) BODY bytes. Owned. */
};

/**
 * @brief Result produced by the ILBM FormDecoder.
 *
 * Contains RGBA8888 pixel data and image dimensions.
 * Caller must free `pixels` and the struct itself.
 */
struct ILBM_Result
{
	VPS_TYPE_16U width;
	VPS_TYPE_16U height;
	VPS_TYPE_8U* pixels;       /* RGBA8888, width * height * 4 bytes. Owned. */
	VPS_TYPE_16U baseline;     /* Baseline (for fonts, from BMHD.y). */
};
