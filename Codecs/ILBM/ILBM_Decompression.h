#pragma once

#include <IFF/IFF_Result.h>
#include <vulpes/VPS_Types.h>

/**
 * @brief Decompresses ByteRun1 (packbits) encoded data.
 *
 * @param dest Destination buffer (must be pre-allocated to dest_size bytes).
 * @param src Source compressed data.
 * @param src_size Number of source bytes.
 * @param dest_size Expected decompressed size.
 * @return IFF_OK on success, non-zero on failure (buffer overrun or incomplete data).
 */
IFF_TYPE_RESULT ILBM_DecompressByteRun1
(
	VPS_TYPE_8U* dest,
	const VPS_TYPE_8U* src,
	VPS_TYPE_SIZE src_size,
	VPS_TYPE_SIZE dest_size
);
