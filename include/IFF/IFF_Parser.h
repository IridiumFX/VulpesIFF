struct VPS_Data;
struct IFF_Chunk;

typedef char (*IFF_SegmentResolverFn)
(
	void *context,
	const struct VPS_Data *identifier,
	int *out_file_handle
);

struct IFF_Parser
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
	struct VPS_Dictionary *directive_processors;

	struct IFF_Parser_Session *session;
	struct IFF_Reader *reader;

	int file_handle;

	IFF_SegmentResolverFn segment_resolver;
	void *resolver_context;
	struct VPS_List *reader_stack;

	/**
	 * @brief When set, mandatory ' REF' directives fail if no resolver
	 *        is registered. When clear (default), unresolved REFs are
	 *        silently consumed for forward compatibility.
	 */
	char strict_references;
};

char IFF_Parser_Allocate
(
	struct IFF_Parser **item
);

char IFF_Parser_Construct
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, int file_handle
);

char IFF_Parser_ConstructFromData
(
	struct IFF_Parser *item
	, struct VPS_Dictionary *form_decoders
	, struct VPS_Dictionary *chunk_decoders
	, struct VPS_Dictionary *directive_processors
	, const struct VPS_Data *source
);

char IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
);

char IFF_Parser_Release
(
	struct IFF_Parser *item
);

char IFF_Parser_ExecuteDirective
(
	struct IFF_Parser *parser,
	struct IFF_Chunk *directive_chunk
);

char IFF_Parser_Scan
(
	struct IFF_Parser *parser
);

char IFF_Parser_SetSegmentResolver
(
	struct IFF_Parser *parser,
	IFF_SegmentResolverFn resolver,
	void *context
);
