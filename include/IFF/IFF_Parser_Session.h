struct IFF_Parser_Session
{
	// A single stack that manages all scope-related state (flags, boundaries, etc.).
	struct VPS_List *scope_stack;
	union IFF_Header_Flags active_header_flags;

	// --- Active Chunk State for Sharding/Progressive Decode ---
	// These fields track the chunk currently being processed across multiple shards.
	struct IFF_ChunkDecoder *active_chunk_decoder;
	struct IFF_Tag active_chunk_tag;
	void *active_chunk_state;

	// A scoped dictionary to store the decoded properties (chunks) of containers.
	struct VPS_ScopedDictionary* props;

	void *final_entity;
};

char IFF_Parser_Session_Allocate
(
	struct IFF_Parser_Session **item
);

char IFF_Parser_Session_Construct
(
	struct IFF_Parser_Session *item
	, union IFF_Header_Flags flags
);

char IFF_Parser_Session_Deconstruct
(
	struct IFF_Parser_Session *item
);

char IFF_Parser_Session_Release
(
	struct IFF_Parser_Session *item
);

char IFF_Parser_Session_EnterScope
(
	struct IFF_Parser_Session *state
	, struct IFF_Tag variant
	, struct IFF_Tag type
);

char IFF_Parser_Session_LeaveScope
(
	struct IFF_Parser_Session *state
);

char IFF_Parser_Session_SetFlags
(
	struct IFF_Parser_Session *state
	, union IFF_Header_Flags flags
);

char IFF_Parser_Session_FindProp
(
    struct IFF_Parser_Session *state
    , struct IFF_Tag *prop_tag
    , struct IFF_ContextualData **out_prop_data
);

char IFF_Parser_Session_AddProp
(
	struct IFF_Parser_Session* state
	, struct IFF_Tag* form_type
	, struct IFF_Tag* prop_tag
	, struct IFF_ContextualData* prop_data
);
