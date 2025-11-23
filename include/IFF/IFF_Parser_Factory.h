struct IFF_Parser_Factory
{
	struct VPS_Dictionary *form_decoders;
	struct VPS_Dictionary *chunk_decoders;
};

char IFF_Parser_Factory_Allocate
(
	struct IFF_Parser_Factory **item
);

char IFF_Parser_Factory_Construct
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_Deconstruct
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_Release
(
	struct IFF_Parser_Factory *item
);

char IFF_Parser_Factory_RegisterFormDecoder
(
	struct IFF_Parser_Factory *item
	, const unsigned char *raw_form_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_FormDecoder *decoder
);

char IFF_Parser_Factory_RegisterChunkDecoder
(
	struct IFF_Parser_Factory *item
	, const unsigned char *raw_form_tag
	, const unsigned char *raw_chunk_tag
	, VPS_TYPE_8U raw_tag_size
	, struct IFF_ChunkDecoder *decoder
);

char IFF_Parser_Factory_CreateSession
(
	struct IFF_Parser_Factory *factory
	, int file_handle
	, struct IFF_Parser_Session **state
);

char IFF_Parser_Factory_Scan
(
	struct IFF_Parser_Factory *parser,
	struct IFF_Parser_Session *state
);

char IFF_Parser_Factory_GetFinalEntity(
	struct IFF_Parser_Session* session,
	void** entity
);