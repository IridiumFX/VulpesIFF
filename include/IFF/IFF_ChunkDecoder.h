/**
 * @brief Defines the interface for a chunk decoder.
 *
 * A chunk decoder is responsible for parsing the raw data of a single
 * IFF chunk and producing a "meaningful item" (a structured object)
 * that can be used by a higher-level Form Decoder.
 */

struct IFF_ChunkDecoder
{
	// Called for the first part of a chunk. Allows allocation of a custom state object.
	char (*begin_decode)
	(
		struct IFF_Parser_State *state
		, void **custom_state // The decoder's internal state for reassembly.
	);

	// Called for each data slice of a chunk (will be called once for non-sharded chunks).
	char (*process_shard)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, const struct VPS_Data *chunk_data
	);

	// Called after the last shard. Finalizes the object and releases the custom state.
	char (*end_decode)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, struct IFF_ContextualData **out
	);
};

char IFF_ChunkDecoder_Allocate
(
	struct IFF_ChunkDecoder **item
);

char IFF_ChunkDecoder_Construct
(
	struct IFF_ChunkDecoder *item
	, char (*begin_decode)
	(
		struct IFF_Parser_State *state
		, void **custom_state
	)
	, char (*process_shard)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, const struct VPS_Data *chunk_data
	)
	, char (*end_decode)
	(
		struct IFF_Parser_State *state
		, void *custom_state
		, struct IFF_ContextualData **out
	)
);

char IFF_ChunkDecoder_Deconstruct
(
	struct IFF_ChunkDecoder *item
);

char IFF_ChunkDecoder_Release
(
	struct IFF_ChunkDecoder *item
);
