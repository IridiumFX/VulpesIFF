#pragma once
#include "BitMapHeader.h"

#define MAX_PALETTE_COLORS 256

// A simple structure to hold a single RGB color.
struct ColorRegister {
    VPS_TYPE_8U r, g, b;
};

// The final, assembled information we want to extract from an ILBM file.
struct IlbmInfo {
    struct BitMapHeader bmhd;
    struct ColorRegister palette[MAX_PALETTE_COLORS];
    VPS_TYPE_16U palette_size;
};
