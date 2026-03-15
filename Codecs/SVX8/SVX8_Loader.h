#pragma once
#include "SVX8_Types.h"
#include "SVX8_Codec.h"

struct VPS_Data;

/**
 * @brief Loads an IFF 8SVX sound file.
 *
 * @param filepath Path to the .iff file.
 * @return An SVX8_Result on success, or NULL on failure. Caller owns the result.
 *         Free with: VPS_Data_Release(result->samples); free(result);
 */
struct SVX8_Result* VPS_SVX8_LoadFromFile(const char* filepath);
