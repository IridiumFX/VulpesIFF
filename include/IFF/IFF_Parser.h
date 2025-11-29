struct IFF_Parser
{
	// A back-pointer to the factory that created this parser.
	struct IFF_Parser_Factory* factory;

	// NOTE: decoders belong to the factory, not the parser.

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
	struct IFF_Parser_Factory* factory,
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
	struct IFF_Parser *parser
);
