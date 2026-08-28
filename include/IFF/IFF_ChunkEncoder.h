#pragma once

#include <IFF/IFF_Result.h>

struct VPS_Data;

/**
 * @brief Defines the interface for a chunk encoder.
 * @details Inverse of IFF_ChunkDecoder. Produces the raw data for a
 *          chunk from a structured source object.
 */

struct IFF_Generator_State;

struct IFF_ChunkEncoder
{
	/**
	 * @brief Produces the raw data for a chunk from a structured object.
	 * @param state The generator state for configuration access.
	 * @param source_object The structured object to encode.
	 * @param out_data Receives the encoded data. Caller takes ownership.
	 * @return IFF_OK on success, non-zero on failure.
	 */
	IFF_TYPE_RESULT (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	);
};

IFF_TYPE_RESULT IFF_ChunkEncoder_Allocate
(
	struct IFF_ChunkEncoder **item
);

IFF_TYPE_RESULT IFF_ChunkEncoder_Construct
(
	struct IFF_ChunkEncoder *item
	, IFF_TYPE_RESULT (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	)
);

IFF_TYPE_RESULT IFF_ChunkEncoder_Deconstruct
(
	struct IFF_ChunkEncoder *item
);

IFF_TYPE_RESULT IFF_ChunkEncoder_Release
(
	struct IFF_ChunkEncoder *item
);

/*
 * --- VulpesCore boundary adapter ---
 *
 * The decoder/encoder registries are VulpesCore dictionaries, which expect
 * the boolean convention (1 = success). Register this shim as the release
 * hook rather than casting the function above.
 */

char IFF_ChunkEncoder_VPS_Release
(
	void *item
);
