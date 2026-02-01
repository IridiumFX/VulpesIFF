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
	 * @return 1 on success, 0 on failure.
	 */
	char (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	);
};

char IFF_ChunkEncoder_Allocate
(
	struct IFF_ChunkEncoder **item
);

char IFF_ChunkEncoder_Construct
(
	struct IFF_ChunkEncoder *item
	, char (*encode)
	(
		struct IFF_Generator_State *state
		, void *source_object
		, struct VPS_Data **out_data
	)
);

char IFF_ChunkEncoder_Deconstruct
(
	struct IFF_ChunkEncoder *item
);

char IFF_ChunkEncoder_Release
(
	struct IFF_ChunkEncoder *item
);
