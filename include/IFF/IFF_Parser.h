struct IFF_Parser
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
	struct VPS_Dictionary *directive_processors;

	struct IFF_Parser_Session *session;
	struct IFF_Reader *reader;

	int file_handle;
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
