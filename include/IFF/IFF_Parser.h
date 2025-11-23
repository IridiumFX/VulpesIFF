struct IFF_Parser
{
	// NOTE: decoders belong to the factory, not the parser.
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;

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
	struct IFF_Parser *item,
	struct VPS_Dictionary *form_decoders,
	struct VPS_Dictionary *chunk_decoders,
	int file_handle
);

char IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
);

char IFF_Parser_Release
(
	struct IFF_Parser *item
);

char IFF_Parser_Scan
(
	struct IFF_Parser *parser,
	struct IFF_Parser_Session *session
);
