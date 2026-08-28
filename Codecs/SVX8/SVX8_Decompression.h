#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

/**
 * @brief Decompresses Fibonacci delta encoded 8SVX audio data.
 *
 * Each compressed byte contains two 4-bit nibbles that index into a
 * Fibonacci-derived delta table. The running sum produces signed 8-bit samples.
 *
 * @param dest Output buffer for signed 8-bit PCM samples (num_samples bytes).
 * @param src Compressed source data.
 * @param src_size Source data size in bytes.
 * @param num_samples Expected number of output samples.
 * @return IFF_OK on success, non-zero on failure.
 */
IFF_TYPE_RESULT SVX8_DecompressFibonacciDelta
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	VPS_TYPE_SIZE src_size,
	VPS_TYPE_SIZE num_samples
);
