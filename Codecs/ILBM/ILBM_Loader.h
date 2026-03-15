#pragma once
#include "ILBM_Types.h"

/**
 * @brief Loads an IFF ILBM image file and returns decoded RGBA8888 pixel data.
 *
 * Supports standard palette, EHB, HAM6, HAM8 modes.
 * Handles ByteRun1 compression.
 *
 * @param filepath Path to the .iff file.
 * @return An ILBM_Result on success, or NULL on failure.
 *         Caller must free: result->pixels and the result struct itself.
 */
struct ILBM_Result* VPS_ILBM_LoadFromFile(const char* filepath);

/**
 * @brief Loads from a VPS_Data buffer (for embedded data).
 */
struct ILBM_Result* VPS_ILBM_LoadFromData(const struct VPS_Data* data);
