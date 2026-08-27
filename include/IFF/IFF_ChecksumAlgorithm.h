#pragma once

#include <IFF/IFF_Result.h>

struct VPS_Data;

/**
 * @brief Defines the interface for a pluggable checksum algorithm.
 * @details This struct follows a C-style virtual table pattern, similar to
 *          VPS_Decoder. It provides a set of function pointers that define
 *          the behavior of a specific checksum algorithm (e.g., CRC-32C).
 *          This allows the IFF_CheckedReader to be generic and extensible.
 */
struct IFF_ChecksumAlgorithm
{
	/** @brief The unique string identifier for this algorithm (e.g., "CRC-32C"). */
	const char* identifier;

	/** @brief The size in bytes of the checksum output (e.g., 4 for CRC-32). */
	VPS_TYPE_8U output_size;

	/**
	 * @brief Creates and initializes the algorithm's state context.
	 * @param[out] context A pointer to receive the allocated context.
	 * @return IFF_OK on success, non-zero on failure.
	 */
	IFF_TYPE_RESULT (*create_context)
	(
		void** context
	);

	/**
	 * @brief Updates the checksum with a new block of raw data.
	 * @param context The algorithm's state context.
	 * @param raw_data The raw bytes to process.
	 */
	void (*update)
	(
		void* context
		, const struct VPS_Data* raw_data
	);

	/**
	 * @brief Finalizes the calculation and writes the checksum to a buffer.
	 * @param context The algorithm's state context.
	 * @param[out] out_checksum A VPS_Data buffer to receive the final checksum.
	 *                         The buffer will be resized to `output_size`.
	 * @return IFF_OK on success, non-zero on failure.
	 */
	IFF_TYPE_RESULT (*finalize)
	(
		void* context
		, struct VPS_Data* out_checksum
	);

	/**
	 * @brief Destroys and releases the algorithm's state context.
	 * @param context The context to release.
	 */
	void (*release_context)
	(
		void* context
	);
};

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Allocate
(
	struct IFF_ChecksumAlgorithm **item
);

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Construct
(
	struct IFF_ChecksumAlgorithm *item
	, IFF_TYPE_RESULT (*create_context)
	(
		void** context
	)
	,void (*update)
	(
		void* context
		, const struct VPS_Data* raw_data
	)
	, IFF_TYPE_RESULT (*finalize)
	(
		void* context
		, struct VPS_Data* out_checksum
	)
	, void (*release_context)
	(
		void* context
	)
);

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Deconstruct
(
	struct IFF_ChecksumAlgorithm *item
);

IFF_TYPE_RESULT IFF_ChecksumAlgorithm_Release
(
	struct IFF_ChecksumAlgorithm *item
);
