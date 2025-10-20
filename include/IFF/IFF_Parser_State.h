struct IFF_Parser_State
{
	// A back-pointer to the factory that created this state.
	// This provides access to the registered decoders.
	struct IFF_Parser *parser_factory;

	// A scoped dictionary to store the decoded properties (chunks) of containers.
	struct VPS_ScopedDictionary *props;

	// A single stack that manages all scope-related state (flags, boundaries, etc.).
	struct VPS_List *scope_stack;
	union IFF_Header_Flags active_header_flags;

	// --- Active Chunk State for Sharding/Progressive Decode ---
	// These fields track the chunk currently being processed across multiple shards.
	struct IFF_ChunkDecoder *active_chunk_decoder;
	struct IFF_Tag active_chunk_tag;
	void *active_chunk_state;

	// I/O Pipeline
	struct IFF_Reader *reader;

    // --- Final Output ---
    // After a successful scan, this will hold the final, assembled object
    // produced by the root FORM's decoder.
    void *final_entity;
};

char IFF_Parser_State_Allocate
(
	struct IFF_Parser_State **item
);

char IFF_Parser_State_Construct
(
	struct IFF_Parser_State *item,
	struct IFF_Parser *factory,
	int file_handle,
	union IFF_Header_Flags flags
);

char IFF_Parser_State_Deconstruct
(
	struct IFF_Parser_State *item
);

char IFF_Parser_State_Release
(
	struct IFF_Parser_State *item
);

char IFF_Parser_State_EnterScope
(
	struct IFF_Parser_State *state,
	struct IFF_Tag variant,
	struct IFF_Tag type
);

char IFF_Parser_State_LeaveScope
(
	struct IFF_Parser_State *state
);

char IFF_Parser_State_SetFlags
(
	struct IFF_Parser_State *state,
	union IFF_Header_Flags flags
);

/**
 * @brief Safely decodes a contextual data packet using a temporary parsing context.
 * @details This function is the standard way for a decoder to lazily parse
 *          the content of a PROP chunk. It temporarily sets the parser's active
 *          flags to match those stored in the contextual data, calls the user's
 *          decode function, and then safely restores the original flags.
 * @param state The global parser state.
 * @param contextual_data The data packet to decode (typically from a PROP).
 * @param decode_callback A user-provided function to perform the actual decoding.
 * @param custom_state A custom pointer to be passed to the decode_callback.
 * @return 1 on success, 0 on failure.
 */
char IFF_Parser_State_DecodeContextualData(
    struct IFF_Parser_State *state,
    struct IFF_ContextualData *contextual_data,
    char (*decode_callback)(struct VPS_DataReader *reader, void *custom_state),
    void *custom_state
);

/**
 * @brief Performs a hierarchical search for a property in the current scope.
 * @details Implements the IFF-2025 "pull" semantics by searching for a property
 *          in the correct order of precedence:
 *          1. A type-specific property (matching the current FORM's type).
 *          2. A wildcard property ('    ').
 */
char IFF_Parser_State_FindProp(
    struct IFF_Parser_State *state,
    struct IFF_Tag *prop_tag,
    struct IFF_ContextualData **out_prop_data
);
