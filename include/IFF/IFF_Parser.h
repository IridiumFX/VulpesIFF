struct IFF_Parser
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
};

char IFF_Parser_Allocate
(
	struct IFF_Parser **item
);

char IFF_Parser_Construct
(
	struct IFF_Parser *item
);

char IFF_Parser_Deconstruct
(
	struct IFF_Parser *item
);

char IFF_Parser_Release
(
	struct IFF_Parser *item
);

char IFF_Parser_RegisterFormDecoder
(
	struct IFF_Parser *item
	, const unsigned char *raw_form_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_FormDecoder *decoder
);

char IFF_Parser_RegisterChunkDecoder
(
	struct IFF_Parser *item
	, const unsigned char *raw_form_tag
	, const unsigned char *raw_chunk_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_ChunkDecoder *decoder
);

char IFF_Parser_Attach
(
	struct IFF_Parser *factory
	, int file_handle
	, struct IFF_Parser_State **state
);

char IFF_Parser_Scan
(
	struct IFF_Parser *parser,
	struct IFF_Parser_State *state
);
