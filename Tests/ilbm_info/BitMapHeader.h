#pragma once
#include <vulpes/VPS_Types.h>

// Structure of the ILBM BitMapHeader chunk ("BMHD")
// This must be parsed from Big-Endian data.
struct BitMapHeader {
    VPS_TYPE_16U w, h;                // width, height in pixels
    VPS_TYPE_16S x, y;                // position of the image on screen
    VPS_TYPE_8U nPlanes;              // number of bitplanes
    VPS_TYPE_8U masking;              // masking type
    VPS_TYPE_8U compression;          // compression algorithm
    VPS_TYPE_8U pad1;                 // unused, for alignment
    VPS_TYPE_16U transparentColor;    // transparent color number
    VPS_TYPE_8U xAspect, yAspect;     // aspect ratio
    VPS_TYPE_16S pageWidth, pageHeight; // size of the page in pixels
};
