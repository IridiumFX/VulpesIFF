struct IFF_Tag;
struct IFF_ContextualData;
union IFF_Header_Flags;

enum IFF_Parser_SessionState
{
	IFF_Parser_SessionState_Idle,
	IFF_Parser_SessionState_Handshake,
	IFF_Parser_SessionState_Segment,
	IFF_Parser_SessionState_Container,
	IFF_Parser_SessionState_Chunk,
	IFF_Parser_SessionState_SegmentSwitch,
	IFF_Parser_SessionState_Failed,
	IFF_Parser_SessionState_Complete
};

struct IFF_Parser_Session
{
	// A single stack that manages all scope-related state (flags, boundaries, etc.).
	struct VPS_List *scope_stack;
	struct IFF_Scope* current_scope; // Always points to the active scope for the current parsing context.

	enum IFF_Parser_SessionState session_state;

	// When 1, the stream was identified as IFF-85 during bootstrap (first tag
	// was a container, not an ' IFF' directive). In this mode all directives
	// are rejected except '    ' which acts as filler.
	char iff85_locked;

	// When 1, Parse_Segment was re-entered after a reader stack pop (inclusion
	// ended). Prevents false IFF-85 bootstrap on resumption.
	char parsing_resumed;

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
	struct IFF_Parser_Session *item,
	struct IFF_Scope* new_scope
);

char IFF_Parser_Session_LeaveScope
(
	struct IFF_Parser_Session *item
);

char IFF_Parser_Session_FindProp
(
    struct IFF_Parser_Session *item
    , struct IFF_Tag *prop_tag
    , struct IFF_ContextualData **out_prop_data
);

char IFF_Parser_Session_AddProp
(
	struct IFF_Parser_Session *item
	, struct IFF_Tag* form_type
	, struct IFF_Tag* prop_tag
	, struct IFF_ContextualData *prop_data
);

char IFF_Parser_Session_IsActive
(
	struct IFF_Parser_Session *item
);

char IFF_Parser_Session_IsBoundaryOpen
(
	struct IFF_Parser_Session *item
);

char IFF_Parser_Session_SetState
(
	struct IFF_Parser_Session *item
	, enum IFF_Parser_SessionState new_state
);
